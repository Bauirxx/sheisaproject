"""Motor de triagem determinístico (§12).

A propriedade central não é "a pontuação está certa" — é **a pontuação é
verificável**: a soma dos factores tem de conferir com o número apresentado, e
cada factor tem de remeter para um dado concreto. Um motor que produzisse
números plausíveis sem esta propriedade seria indistinguível de um que os
inventa, que é exactamente o que o §4 proíbe.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from app.core.enums import AlertStatus, AssetCriticality, Severity, SourceKind
from app.intelligence.triage import (
    MIN_HISTORY_FOR_FP,
    score_alert,
    severity_from_score,
)
from app.models.catalog import Asset
from app.models.telemetry import Alert


async def _alerta(sessao, **campos) -> Alert:
    """Alerta directo na base de dados, para isolar o motor da ingestão."""
    from app.core.references import ReferenceKind, next_reference

    agora = datetime.now(UTC)
    alerta = Alert(
        reference=await next_reference(sessao, ReferenceKind.ALERT),
        title=campos.pop("titulo", "Alerta de teste"),
        description="",
        source_kind=SourceKind.WAZUH,
        source_name="wazuh-teste",
        severity=campos.pop("severidade", Severity.MEDIA),
        status=campos.pop("estado", AlertStatus.NOVO),
        dedup_key=campos.pop("dedup", f"chave-{agora.timestamp()}"),
        event_count=campos.pop("eventos", 1),
        first_event_at=agora,
        last_event_at=agora,
        rule_id=campos.pop("rule_id", "5710"),
        rule_name=campos.pop("rule_name", "Falhas de autenticacao"),
        tags=campos.pop("tags", ["sshd", "authentication_failed"]),
        **campos,
    )
    sessao.add(alerta)
    await sessao.flush()
    return alerta


# --------------------------------------------------- propriedade fundamental
async def test_a_soma_dos_factores_confere_com_a_pontuacao(sessao):
    alerta = await _alerta(sessao, severidade=Severity.ALTA, eventos=40)
    resultado = await score_alert(sessao, alerta)

    soma = sum(f.pontos for f in resultado.factors)
    # A pontuação é a soma limitada ao intervalo 0-100.
    assert resultado.score == max(0, min(100, soma))
    assert alerta.triage_factors["total_bruto"] == soma
    assert alerta.triage_factors["total_final"] == resultado.score


async def test_cada_factor_traz_razao_textual(sessao):
    alerta = await _alerta(sessao)
    resultado = await score_alert(sessao, alerta)

    assert resultado.factors, "o motor não produziu factores"
    for factor in resultado.factors:
        assert factor.razao.strip(), f"factor '{factor.nome}' sem razão"
        assert factor.nome


async def test_o_motor_e_reproduzivel(sessao):
    """A mesma entrada dá sempre a mesma saída — é o que permite auditá-lo."""
    alerta = await _alerta(sessao, severidade=Severity.ALTA)
    primeira = await score_alert(sessao, alerta)
    segunda = await score_alert(sessao, alerta)
    assert primeira.score == segunda.score
    assert [f.pontos for f in primeira.factors] == [f.pontos for f in segunda.factors]


async def test_pontuacao_dentro_do_intervalo(sessao):
    for severidade in Severity:
        alerta = await _alerta(sessao, severidade=severidade, eventos=9999)
        resultado = await score_alert(sessao, alerta)
        assert 0 <= resultado.score <= 100


# ------------------------------------------------------------------ factores
async def test_severidade_mais_alta_pontua_mais(sessao):
    baixo = await score_alert(sessao, await _alerta(sessao, severidade=Severity.BAIXA))
    alto = await score_alert(sessao, await _alerta(sessao, severidade=Severity.CRITICA))
    assert alto.score > baixo.score


async def test_activo_critico_aumenta_a_pontuacao(sessao):
    activo = Asset(
        identifier="srv-critico",
        name="Servidor crítico",
        criticality=AssetCriticality.CRITICA,
        hostname="srv-critico",
    )
    sessao.add(activo)
    await sessao.flush()

    sem_activo = await score_alert(sessao, await _alerta(sessao))
    com_activo = await score_alert(
        sessao, await _alerta(sessao, asset_id=activo.id), asset=activo
    )
    assert com_activo.score > sem_activo.score

    factor = next(
        f for f in com_activo.factors if f.nome == "criticidade_do_activo"
    )
    assert "Servidor crítico" in factor.razao


async def test_volume_usa_escala_logaritmica(sessao):
    """A diferença entre 1 e 10 eventos informa; entre 1000 e 1010 não.

    Numa escala linear, um alerta repetitivo dominaria a fila só por ser
    repetitivo.
    """
    def volume(resultado):
        return next(f for f in resultado.factors if f.nome == "volume_de_eventos").pontos

    um = volume(await score_alert(sessao, await _alerta(sessao, eventos=1)))
    dez = volume(await score_alert(sessao, await _alerta(sessao, eventos=10)))
    mil = volume(await score_alert(sessao, await _alerta(sessao, eventos=1000)))
    dez_mil = volume(await score_alert(sessao, await _alerta(sessao, eventos=10000)))

    assert um < dez < mil
    # O contributo está limitado: acima de certo ponto, mais volume não compra
    # mais pontuação.
    assert dez_mil - mil <= dez - um


# ------------------------------------------------- aprendizagem com decisões
async def test_sem_historico_o_factor_vale_zero_e_di_lo(sessao):
    """§4: quando não há dados, o motor diz que não há — não estima."""
    alerta = await _alerta(sessao, rule_id="regra-nunca-vista")
    resultado = await score_alert(sessao, alerta)

    factor = next(
        f for f in resultado.factors if f.nome == "historico_de_falsos_positivos"
    )
    assert factor.pontos == 0
    assert "insuficiente" in factor.razao.lower()
    assert resultado.false_positive_score == 0


async def test_o_historico_real_de_decisoes_penaliza_a_regra(sessao):
    """A taxa de falsos positivos vem de decisões tomadas, não de suposições."""
    for _ in range(MIN_HISTORY_FOR_FP + 3):
        await _alerta(
            sessao, rule_id="regra-ruidosa", estado=AlertStatus.FALSO_POSITIVO
        )

    alerta = await _alerta(sessao, rule_id="regra-ruidosa")
    resultado = await score_alert(sessao, alerta)

    factor = next(
        f for f in resultado.factors if f.nome == "historico_de_falsos_positivos"
    )
    assert factor.pontos < 0
    assert resultado.false_positive_score == 100
    assert "regra-ruidosa" in factor.razao


async def test_uma_amostra_pequena_nao_penaliza(sessao):
    """Abaixo do mínimo, duas decisões ao acaso não suprimem uma regra legítima."""
    for _ in range(MIN_HISTORY_FOR_FP - 1):
        await _alerta(
            sessao, rule_id="regra-pouco-vista", estado=AlertStatus.FALSO_POSITIVO
        )

    resultado = await score_alert(
        sessao, await _alerta(sessao, rule_id="regra-pouco-vista")
    )
    factor = next(
        f for f in resultado.factors if f.nome == "historico_de_falsos_positivos"
    )
    assert factor.pontos == 0


async def test_uma_regra_util_nao_e_penalizada(sessao):
    """Alertas promovidos a incidente contam como verdadeiros positivos."""
    for _ in range(MIN_HISTORY_FOR_FP + 2):
        await _alerta(sessao, rule_id="regra-util", estado=AlertStatus.PROMOVIDO)

    resultado = await score_alert(sessao, await _alerta(sessao, rule_id="regra-util"))
    assert resultado.false_positive_score == 0


# ------------------------------------------------------ severidade sugerida
@pytest.mark.parametrize(
    ("pontuacao", "esperado"),
    [
        (0, Severity.INFO), (19, Severity.INFO),
        (20, Severity.BAIXA), (39, Severity.BAIXA),
        (40, Severity.MEDIA), (64, Severity.MEDIA),
        (65, Severity.ALTA), (84, Severity.ALTA),
        (85, Severity.CRITICA), (100, Severity.CRITICA),
    ],
)
def test_fronteiras_da_severidade_sugerida(pontuacao, esperado):
    assert severity_from_score(pontuacao) is esperado


# ------------------------------------------------------------- pela API
async def test_repontuar_pela_api_devolve_a_decomposicao(
    cliente, chave_ingestao, token_analista, sessao
):
    from tests.conftest import cabecalho
    from tests.test_ingestao import alerta_wazuh

    await cliente.post(
        "/api/ingest/wazuh", json=alerta_wazuh(), headers={"X-API-Key": chave_ingestao}
    )
    alerta = (await sessao.execute(select(Alert))).scalar_one()

    resposta = await cliente.post(
        f"/api/alerts/{alerta.id}/rescore", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text
    corpo = resposta.json()
    assert corpo["triage_rationale"]
    assert corpo["triage_factors"]["factores"]
    assert corpo["triage_factors"]["total_final"] == corpo["triage_score"]
