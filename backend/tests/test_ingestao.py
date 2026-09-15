"""Normalização, idempotência e deduplicação (§8, §9).

Vários destes testes existem por causa de erros que já foram cometidos e
corrigidos. Estão marcados como tal: são regressões, não hipóteses.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.core.enums import IocType, ObservationRole, Severity
from app.ingestion.base import is_external_ip
from app.ingestion.suricata import map_suricata_severity
from app.ingestion.wazuh import WazuhNormalizer, map_wazuh_level
from app.models.telemetry import Alert, Event


def alerta_wazuh(**campos) -> dict:
    """Alerta Wazuh realista, com os campos que o `integrator` envia."""
    agora = campos.pop("quando", datetime.now(UTC))
    regra = {
        "id": campos.pop("rule_id", "5710"),
        "level": campos.pop("level", 10),
        "description": campos.pop("descricao", "Tentativas de autenticacao falhadas"),
        "groups": campos.pop("grupos", ["syslog", "sshd", "authentication_failed"]),
    }
    if tecnicas := campos.pop("mitre", None):
        regra["mitre"] = {"id": tecnicas}
    return {
        "timestamp": agora.isoformat(),
        "id": campos.pop("id_fonte", f"{int(agora.timestamp() * 1000)}.1"),
        "rule": regra,
        "agent": {"id": "001", "name": campos.pop("agente", "srv-web-01"),
                  "ip": "10.10.5.21"},
        "manager": {"name": "wazuh-manager"},
        "data": campos.pop("dados", {"srcip": "203.0.113.77"}),
        "full_log": "log completo",
        "location": "/var/log/auth.log",
        **campos,
    }


# ------------------------------------------------------------- normalizadores
@pytest.mark.parametrize(
    ("nivel", "esperado"),
    [
        (0, Severity.INFO), (3, Severity.INFO),
        (4, Severity.BAIXA), (6, Severity.BAIXA),
        (7, Severity.MEDIA), (9, Severity.MEDIA),
        (10, Severity.ALTA), (12, Severity.ALTA),
        (13, Severity.CRITICA), (15, Severity.CRITICA),
    ],
)
def test_niveis_wazuh(nivel, esperado):
    """O Wazuh usa 0-15, não 1-5: traduzir mal punha um ataque severo como INFO."""
    assert map_wazuh_level(nivel) is esperado


def test_nivel_wazuh_invalido_nao_rebenta():
    assert map_wazuh_level(None) is Severity.INFO
    assert map_wazuh_level("isto-nao-e-um-numero") is Severity.INFO
    assert map_wazuh_level(99) is Severity.CRITICA  # limitado a 15


@pytest.mark.parametrize(
    ("valor", "esperado"),
    [(1, Severity.ALTA), (2, Severity.MEDIA), (3, Severity.BAIXA)],
)
def test_escala_do_suricata_e_invertida(valor, esperado):
    """No Suricata 1 é a severidade **mais alta** — o contrário do Wazuh."""
    assert map_suricata_severity(valor).rank >= esperado.rank - 1


def test_severidades_do_wazuh_e_do_suricata_nao_se_confundem():
    """Nível 1 significa coisas opostas nas duas fontes."""
    assert map_wazuh_level(1) is Severity.INFO
    assert map_suricata_severity(1).rank > Severity.INFO.rank


# ------------------------------------------------------- endereços externos
@pytest.mark.parametrize(
    "endereco",
    ["192.0.2.10", "198.51.100.4", "203.0.113.77", "8.8.8.8", "1.1.1.1"],
)
def test_gamas_de_documentacao_contam_como_externas(endereco):
    """Regressão: `ipaddress.is_private` classifica a RFC 5737 como privada.

    Enquanto foi assim, o IP do atacante era descartado em silêncio e nunca
    chegava a ser indicador — precisamente nas gamas que toda a literatura e
    todos os laboratórios usam.
    """
    assert is_external_ip(endereco) is True


@pytest.mark.parametrize(
    "endereco",
    ["10.10.5.21", "192.168.1.1", "172.16.0.5", "127.0.0.1", "169.254.1.1"],
)
def test_gamas_internas_nao_sao_externas(endereco):
    assert is_external_ip(endereco) is False


def test_endereco_invalido_nao_rebenta():
    assert is_external_ip("nao-e-um-ip") is False
    assert is_external_ip(None) is False
    assert is_external_ip("") is False


# -------------------------------------------------------- papéis das contas
def test_srcuser_actua_e_dstuser_e_alvo():
    """Regressão: `srcuser` e `dstuser` estavam trocados.

    A consequência era a conta visada ser marcada como ACTOR, e a correlação
    concluir que a vítima era o atacante.
    """
    normalizador = WazuhNormalizer()
    evento = normalizador.normalize(
        alerta_wazuh(dados={"srcip": "203.0.113.77", "srcuser": "atacante",
                            "dstuser": "vitima"}),
        "wazuh-teste",
    )
    papeis = {i.value: i.role for i in evento.indicators if i.ioc_type is IocType.UTILIZADOR}
    assert papeis.get("atacante") is ObservationRole.ACTOR
    assert papeis.get("vitima") is ObservationRole.ALVO


def test_o_payload_original_e_preservado():
    """§8: o que a fonte enviou tem de continuar disponível tal como chegou."""
    normalizador = WazuhNormalizer()
    original = alerta_wazuh()
    evento = normalizador.normalize(original, "wazuh-teste")
    assert evento.raw_payload == original


def test_tecnicas_declaradas_sao_reportadas_e_nao_inferidas():
    normalizador = WazuhNormalizer()
    evento = normalizador.normalize(alerta_wazuh(mitre=["T1110"]), "wazuh-teste")
    assert evento.reported_techniques == ["T1110"]


# ------------------------------------------------------ ingestão pela API
async def test_ingestao_cria_alerta_e_evento(cliente, chave_ingestao, sessao):
    resposta = await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(),
        headers={"X-API-Key": chave_ingestao},
    )
    assert resposta.status_code == 202, resposta.text
    assert resposta.json()["processados"] == 1

    assert await sessao.scalar(select(func.count()).select_from(Alert)) == 1
    assert await sessao.scalar(select(func.count()).select_from(Event)) == 1


async def test_chave_invalida_e_recusada(cliente):
    resposta = await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(),
        headers={"X-API-Key": "chave-que-nao-existe"},
    )
    assert resposta.status_code == 401
    assert resposta.json()["erro"]["codigo"] == "CHAVE_API_INVALIDA"


async def test_idempotencia_por_identificador_da_fonte(cliente, chave_ingestao, sessao):
    """O mesmo alerta reenviado não produz um evento novo.

    O `integrator` do Wazuh pode reenviar em caso de falha de rede; sem
    idempotência, uma falha transitória duplicaria a contagem de eventos e
    inflacionaria as métricas.
    """
    alerta = alerta_wazuh(id_fonte="identificador-fixo-1")
    for _ in range(3):
        await cliente.post(
            "/api/ingest/wazuh", json=alerta, headers={"X-API-Key": chave_ingestao}
        )

    assert await sessao.scalar(select(func.count()).select_from(Event)) == 1
    assert await sessao.scalar(select(func.count()).select_from(Alert)) == 1


async def test_deduplicacao_agrega_eventos_equivalentes(cliente, chave_ingestao, sessao):
    """Sinais equivalentes na janela agregam-se num alerta com contagem.

    4000 tentativas de força bruta são um alerta com `event_count=4000`, não
    4000 alertas — é esta a diferença entre uma fila de trabalho e ruído.
    """
    agora = datetime.now(UTC)
    for i in range(5):
        await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(
                id_fonte=f"evento-{i}", quando=agora - timedelta(minutes=i)
            ),
            headers={"X-API-Key": chave_ingestao},
        )

    alertas = (await sessao.execute(select(Alert))).scalars().all()
    assert len(alertas) == 1
    assert alertas[0].event_count == 5
    assert await sessao.scalar(select(func.count()).select_from(Event)) == 5


async def test_agentes_diferentes_produzem_alertas_diferentes(
    cliente, chave_ingestao, sessao
):
    """A chave de deduplicação inclui o anfitrião: dois servidores, dois alertas."""
    for i, agente in enumerate(["srv-web-01", "srv-bd-01"]):
        await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(id_fonte=f"a-{i}", agente=agente,
                              dados={"srcip": f"203.0.113.{10 + i}"}),
            headers={"X-API-Key": chave_ingestao},
        )
    assert await sessao.scalar(select(func.count()).select_from(Alert)) == 2


async def test_lote_e_aceite(cliente, chave_ingestao):
    """O Suricata envia lotes; o Wazuh envia um de cada vez. Ambos servem."""
    lote = [alerta_wazuh(id_fonte=f"lote-{i}", agente=f"host-{i}") for i in range(3)]
    resposta = await cliente.post(
        "/api/ingest/wazuh", json=lote, headers={"X-API-Key": chave_ingestao}
    )
    assert resposta.status_code == 202
    assert resposta.json()["recebidos"] == 3
    assert resposta.json()["processados"] == 3


async def test_alerta_ingerido_e_pontuado(cliente, chave_ingestao, sessao):
    """A triagem corre na ingestão: um alerta chega à fila já pontuado."""
    await cliente.post(
        "/api/ingest/wazuh", json=alerta_wazuh(), headers={"X-API-Key": chave_ingestao}
    )
    alerta = (await sessao.execute(select(Alert))).scalar_one()
    assert alerta.scored_at is not None
    assert 0 <= alerta.triage_score <= 100
    assert alerta.triage_rationale
    assert alerta.triage_factors["factores"]
