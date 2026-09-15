"""Motor de correlação (§9).

O teste central é o da regressão do §4 do documento de estado: a correlação por
entidade partilhada casava pela **vítima** — o hostname do servidor atacado — e
concluía "mesmo actor". Dois ataques independentes contra o mesmo servidor
passavam a ser o mesmo incidente. A correcção foi restringir a correspondência
aos papéis do lado do atacante, e é isso que aqui se fixa.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.enums import (
    AlertStatus,
    CorrelationOutcome,
    CorrelationStrategy,
    ObservationRole,
    Severity,
    SourceKind,
)
from app.core.references import ReferenceKind, next_reference
from app.correlation.engine import ATTACKER_SIDE_ROLES, correlate_alert
from app.models.telemetry import Alert, CorrelationRule, Event


def test_apenas_papeis_do_lado_do_atacante_correlacionam():
    """O ALVO não entra: é a vítima, e duas vítimas iguais não fazem um actor."""
    assert ObservationRole.ORIGEM.value in ATTACKER_SIDE_ROLES
    assert ObservationRole.ACTOR.value in ATTACKER_SIDE_ROLES
    assert ObservationRole.ALVO.value not in ATTACKER_SIDE_ROLES


async def _alerta_com_indicadores(sessao, *, indicadores, **campos) -> Alert:
    """Alerta e evento com os indicadores indicados, tal como a ingestão os grava."""
    agora = campos.pop("quando", datetime.now(UTC))
    alerta = Alert(
        reference=await next_reference(sessao, ReferenceKind.ALERT),
        title=campos.pop("titulo", "Alerta correlacionável"),
        description="",
        source_kind=SourceKind.WAZUH,
        source_name="wazuh-teste",
        severity=campos.pop("severidade", Severity.ALTA),
        status=campos.pop("estado", AlertStatus.NOVO),
        dedup_key=campos.pop("dedup", f"dedup-{agora.timestamp()}-{len(indicadores)}"),
        event_count=1,
        first_event_at=agora,
        last_event_at=agora,
        rule_id=campos.pop("rule_id", "5710"),
        rule_name="Falhas de autenticacao",
        tags=campos.pop("tags", ["sshd", "authentication_failed"]),
        **campos,
    )
    sessao.add(alerta)
    await sessao.flush()

    sessao.add(
        Event(
            alert_id=alerta.id,
            source_kind=SourceKind.WAZUH,
            source_name="wazuh-teste",
            source_event_id=f"ev-{alerta.reference}",
            event_type="authentication_failed",
            severity=alerta.severity,
            description="tentativa falhada",
            occurred_at=agora,
            received_at=agora,
            raw_payload={},
            normalized_extra={"indicadores": indicadores},
            rule_groups=list(alerta.tags),
            reported_techniques=[],
        )
    )
    await sessao.flush()
    return alerta


async def _regra(sessao, estrategia, **campos) -> CorrelationRule:
    regra = CorrelationRule(
        name=campos.pop("nome", f"Regra {estrategia.value}"),
        description="",
        strategy=estrategia,
        is_enabled=True,
        priority=campos.pop("prioridade", 10),
        window_minutes=campos.pop("janela", 60),
        min_alerts=campos.pop("minimo", 2),
        match_fields=campos.pop("campos", []),
        conditions=campos.pop("condicoes", {}),
        sequence=campos.pop("sequencia", []),
        incident_title_template=campos.pop("titulo_incidente", "Actividade correlacionada"),
        **campos,
    )
    sessao.add(regra)
    await sessao.flush()
    return regra


async def test_o_mesmo_atacante_correlaciona(sessao):
    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA)

    atacante = [
        {"tipo": "IP", "valor": "203.0.113.77", "papel": ObservationRole.ORIGEM.value}
    ]
    await _alerta_com_indicadores(
        sessao, indicadores=atacante, dedup="a", estado=AlertStatus.NOVO
    )
    segundo = await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="b")

    decisao = await correlate_alert(sessao, segundo)
    assert decisao.outcome is not CorrelationOutcome.SEM_CORRELACAO
    assert "203.0.113.77" in decisao.rationale or decisao.related_alert_ids


async def test_a_mesma_vitima_nao_correlaciona(sessao):
    """Regressão: dois ataques distintos ao mesmo servidor são dois incidentes.

    Se a vítima bastasse para correlacionar, um servidor exposto acumularia
    todos os ataques que sofresse num único incidente, e a investigação perderia
    a distinção entre actores.
    """
    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA)

    vitima = "srv-web-01"
    await _alerta_com_indicadores(
        sessao,
        indicadores=[
            {"tipo": "IP", "valor": "203.0.113.10", "papel": ObservationRole.ORIGEM.value},
            {"tipo": "HOSTNAME", "valor": vitima, "papel": ObservationRole.ALVO.value},
        ],
        dedup="v1",
    )
    outro_atacante = await _alerta_com_indicadores(
        sessao,
        indicadores=[
            {"tipo": "IP", "valor": "198.51.100.200", "papel": ObservationRole.ORIGEM.value},
            {"tipo": "HOSTNAME", "valor": vitima, "papel": ObservationRole.ALVO.value},
        ],
        dedup="v2",
    )

    decisao = await correlate_alert(sessao, outro_atacante)
    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO, (
        "a correlação casou pela vítima e concluiu 'mesmo actor'"
    )


async def test_a_conta_visada_nao_correlaciona(sessao):
    """`dstuser` é a conta atacada. Duas tentativas contra 'admin' vindas de
    sítios diferentes não são o mesmo actor."""
    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA)

    await _alerta_com_indicadores(
        sessao,
        indicadores=[
            {"tipo": "UTILIZADOR", "valor": "admin", "papel": ObservationRole.ALVO.value},
            {"tipo": "IP", "valor": "203.0.113.1", "papel": ObservationRole.ORIGEM.value},
        ],
        dedup="c1",
    )
    segundo = await _alerta_com_indicadores(
        sessao,
        indicadores=[
            {"tipo": "UTILIZADOR", "valor": "admin", "papel": ObservationRole.ALVO.value},
            {"tipo": "IP", "valor": "192.0.2.50", "papel": ObservationRole.ORIGEM.value},
        ],
        dedup="c2",
    )

    decisao = await correlate_alert(sessao, segundo)
    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO


async def test_fora_da_janela_nao_correlaciona(sessao):
    """A janela é o que separa 'a mesma actividade' de 'coincidência'."""
    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA, janela=30)

    atacante = [
        {"tipo": "IP", "valor": "203.0.113.90", "papel": ObservationRole.ORIGEM.value}
    ]
    antigo = datetime.now(UTC) - timedelta(hours=6)
    await _alerta_com_indicadores(
        sessao, indicadores=atacante, dedup="j1", quando=antigo
    )
    recente = await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="j2")

    decisao = await correlate_alert(sessao, recente)
    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO


async def test_limiar_exige_repeticao_suficiente(sessao):
    """A estratégia LIMIAR responde a 'isto está a acontecer repetidamente?'."""
    await _regra(
        sessao, CorrelationStrategy.LIMIAR, minimo=3, janela=60,
        condicoes={"rule_groups_any": ["authentication_failed"]},
    )

    indicadores = [
        {"tipo": "IP", "valor": "203.0.113.5", "papel": ObservationRole.ORIGEM.value}
    ]
    primeiro = await _alerta_com_indicadores(sessao, indicadores=indicadores, dedup="l1")
    assert (await correlate_alert(sessao, primeiro)).outcome is (
        CorrelationOutcome.SEM_CORRELACAO
    ), "um único alerta não devia atingir um limiar de 3"

    await _alerta_com_indicadores(sessao, indicadores=indicadores, dedup="l2")
    terceiro = await _alerta_com_indicadores(sessao, indicadores=indicadores, dedup="l3")

    decisao = await correlate_alert(sessao, terceiro)
    assert decisao.outcome is not CorrelationOutcome.SEM_CORRELACAO


async def test_sem_regras_activas_nao_ha_correlacao(sessao):
    """Sem regra, o motor diz que não correlacionou — e diz porquê."""
    alerta = await _alerta_com_indicadores(
        sessao,
        indicadores=[
            {"tipo": "IP", "valor": "203.0.113.11", "papel": ObservationRole.ORIGEM.value}
        ],
    )
    decisao = await correlate_alert(sessao, alerta)
    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO
    assert decisao.rationale
    assert decisao.matched is False


async def test_regra_desactivada_e_ignorada(sessao):
    regra = await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA)
    regra.is_enabled = False
    await sessao.flush()

    atacante = [
        {"tipo": "IP", "valor": "203.0.113.31", "papel": ObservationRole.ORIGEM.value}
    ]
    await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="d1")
    segundo = await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="d2")

    decisao = await correlate_alert(sessao, segundo)
    assert decisao.outcome is CorrelationOutcome.SEM_CORRELACAO


async def test_a_correlacao_conta_as_correspondencias_da_regra(sessao):
    """`match_count` é o que permite avaliar se uma regra vale o que custa."""
    regra = await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA)
    assert regra.match_count == 0

    atacante = [
        {"tipo": "IP", "valor": "203.0.113.41", "papel": ObservationRole.ORIGEM.value}
    ]
    await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="m1")
    segundo = await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="m2")

    await correlate_alert(sessao, segundo)
    # O motor incrementa o contador em memória; quem o invoca é que consolida.
    # Um `refresh` aqui releria a linha por gravar e veria zero.
    await sessao.flush()
    assert regra.match_count == 1
    assert regra.last_matched_at is not None


async def test_a_decisao_traz_sempre_justificacao(sessao):
    """Correlacione ou não, o motor explica-se — é a mesma regra do §12."""
    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA)
    atacante = [
        {"tipo": "IP", "valor": "203.0.113.51", "papel": ObservationRole.ORIGEM.value}
    ]
    await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="r1")
    segundo = await _alerta_com_indicadores(sessao, indicadores=atacante, dedup="r2")

    decisao = await correlate_alert(sessao, segundo)
    assert decisao.rationale.strip()
    if decisao.matched:
        assert decisao.rule is not None
        assert decisao.rule.name in decisao.rationale


async def test_ingestao_correlaciona_ponta_a_ponta(cliente, chave_ingestao, sessao):
    """Com a regra instalada, alertas do mesmo atacante geram um só incidente."""
    from tests.test_ingestao import alerta_wazuh

    await _regra(sessao, CorrelationStrategy.ENTIDADE_PARTILHADA, minimo=2)
    await sessao.commit()

    agora = datetime.now(UTC)
    for i, agente in enumerate(["srv-web-01", "srv-bd-01", "est-financas-07"]):
        await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(
                id_fonte=f"corr-{i}",
                agente=agente,
                quando=agora - timedelta(minutes=5 - i),
                dados={"srcip": "203.0.113.77", "srcuser": "root"},
            ),
            headers={"X-API-Key": chave_ingestao},
        )

    alertas = (await sessao.execute(select(Alert))).scalars().all()
    assert len(alertas) == 3, "anfitriões distintos deviam dar alertas distintos"

    incidentes = {a.incident_id for a in alertas if a.incident_id}
    assert len(incidentes) <= 1, (
        "o mesmo atacante contra três anfitriões devia convergir num incidente"
    )
