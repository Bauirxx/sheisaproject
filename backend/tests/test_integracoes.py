"""Integrações com sistemas externos (§24, §26).

A regra que aqui se fixa é a do §4 aplicada às integrações: **nada aparece como
ligado sem ter falado com o serviço**, e quando falha diz porquê.

Nenhum teste vai à rede. O duplo HTTP devolve os formatos que o gestor Wazuh
4.12.0 do laboratório devolveu de facto em 2026-09-17 — capturados com a API a
correr, não escritos de memória. O próprio conector foi confrontado com esse
gestor antes de se escreverem estes testes: com a verificação de certificado
ligada falha (`CERTIFICATE_VERIFY_FAILED`, o certificado é auto-assinado); com
`permitir_certificado_auto_assinado` responde "Ligação estabelecida com o gestor
Wazuh v4.12.0; 2 agente(s) registado(s)."

**O que fica deliberadamente de fora:** `fetch_offenses`, `fetch_alerts` e
`fetch_agents`. Nada na aplicação os chama — nem rota, nem linha de comandos,
nem tarefa — e testá-los daria cobertura a código que nenhum utilizador
consegue exercer. Ver `docs/CONTINUAR.md` §4.3.
"""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app.core.enums import ActionKind, IntegrationStatus, SourceKind
from app.core.errors import IntegrationNotAvailableError
from app.integrations.base import BaseConnector
from app.integrations.siem_connectors import NetScoutConnector, QRadarConnector
from app.integrations.wazuh_connector import WazuhConnector
from app.models.system import AuditLog, Integration
from app.services.integration_service import CONNECTOR_CATALOG, ensure_catalog
from tests.conftest import cabecalho

URL_WAZUH = "https://wazuh.lab.invalid:55000"
VARIAVEIS_WAZUH = {
    "SHEISA_WAZUH_API_URL": URL_WAZUH,
    "SHEISA_WAZUH_API_USER": "wazuh-wui",
    "SHEISA_WAZUH_API_PASSWORD": "segredo-que-nunca-pode-sair",
}

# --- respostas reais do gestor 4.12.0 do laboratório (token substituído) ---
AUTENTICACAO = {"data": {"token": "token-de-teste"}, "error": 0}
INFO_DO_GESTOR = {
    "data": {
        "affected_items": [{
            "path": "/var/ossec", "version": "v4.12.0", "type": "server",
            "max_agents": "unlimited", "openssl_support": "yes",
            "tz_offset": "+0000", "tz_name": "UTC",
        }],
        "total_affected_items": 1, "total_failed_items": 0, "failed_items": [],
    },
    "message": "Basic information was successfully read",
    "error": 0,
}
AGENTES = {
    "data": {"affected_items": [{"id": "000"}], "total_affected_items": 2,
             "total_failed_items": 0, "failed_items": []},
    "message": "All selected agents information was returned",
    "error": 0,
}
#: Resposta a `PUT /active-response` para um agente desligado.
AGENTE_INACTIVO = {
    "data": {
        "affected_items": [], "total_affected_items": 0, "total_failed_items": 1,
        "failed_items": [{
            "error": {"code": 1707, "message": "Cannot send request, agent is not active"},
            "id": ["001"],
        }],
    },
    "message": "AR command was not sent to any agent",
    "error": 1,
}


class ServidorFalso:
    """Substitui o cliente HTTP dos conectores e regista o que lhe pedem."""

    def __init__(self, monkeypatch, rotas: dict[tuple[str, str], tuple[int, dict]]):
        self.rotas = rotas
        self.pedidos: list[httpx.Request] = []
        self.verificacoes: list[bool] = []
        servidor = self

        def cliente(_conector, *, verify: bool = True, **kwargs):
            servidor.verificacoes.append(verify)
            return httpx.AsyncClient(transport=httpx.MockTransport(servidor._responder), **kwargs)

        monkeypatch.setattr(BaseConnector, "_client", cliente)

    def _responder(self, pedido: httpx.Request) -> httpx.Response:
        self.pedidos.append(pedido)
        estado, corpo = self.rotas[(pedido.method, pedido.url.path)]
        return httpx.Response(estado, json=corpo)

    def caminhos(self) -> list[tuple[str, str]]:
        return [(p.method, p.url.path) for p in self.pedidos]


def _gestor_wazuh_saudavel(monkeypatch) -> ServidorFalso:
    return ServidorFalso(monkeypatch, {
        ("POST", "/security/user/authenticate"): (200, AUTENTICACAO),
        ("GET", "/manager/info"): (200, INFO_DO_GESTOR),
        ("GET", "/agents"): (200, AGENTES),
    })


def _com_variaveis(monkeypatch, variaveis: dict[str, str]) -> None:
    for nome in {*VARIAVEIS_WAZUH, "SHEISA_QRADAR_API_URL", "SHEISA_QRADAR_API_TOKEN",
                 "SHEISA_NETSCOUT_API_URL", "SHEISA_NETSCOUT_API_TOKEN"}:
        monkeypatch.delenv(nome, raising=False)
    for nome, valor in variaveis.items():
        monkeypatch.setenv(nome, valor)


async def _integracao(sessao, tipo: SourceKind) -> Integration:
    await ensure_catalog(sessao)
    await sessao.flush()
    return (
        await sessao.execute(select(Integration).where(Integration.kind == tipo))
    ).scalar_one()


async def _testar(cliente, token_admin, integracao) -> dict:
    resposta = await cliente.post(
        f"/api/integrations/{integracao.id}/test", headers=cabecalho(token_admin)
    )
    assert resposta.status_code == 200, resposta.text
    return resposta.json()


# ----------------------------------------------------------------- catálogo
async def test_o_catalogo_regista_cada_conector_uma_so_vez_e_desligado(sessao):
    assert await ensure_catalog(sessao) == len(CONNECTOR_CATALOG)
    assert await ensure_catalog(sessao) == 0

    integracoes = (await sessao.execute(select(Integration))).scalars().all()
    assert {i.kind for i in integracoes} == set(CONNECTOR_CATALOG)
    for integracao in integracoes:
        assert integracao.status is IntegrationStatus.NAO_CONFIGURADA, integracao.kind
        assert integracao.is_enabled is False, integracao.kind

    qradar = next(i for i in integracoes if i.kind is SourceKind.QRADAR)
    assert qradar.config["verificavel_neste_ambiente"] is False


async def test_a_listagem_diz_o_que_falta_sem_nunca_mostrar_segredos(
    cliente, sessao, token_admin, monkeypatch
):
    await _integracao(sessao, SourceKind.WAZUH)
    _com_variaveis(monkeypatch, {
        "SHEISA_WAZUH_API_URL": URL_WAZUH,
        "SHEISA_WAZUH_API_PASSWORD": VARIAVEIS_WAZUH["SHEISA_WAZUH_API_PASSWORD"],
    })

    resposta = await cliente.get("/api/integrations", headers=cabecalho(token_admin))

    assert resposta.status_code == 200, resposta.text
    wazuh = next(i for i in resposta.json() if i["kind"] == "WAZUH")
    assert wazuh["variaveis_em_falta"] == ["SHEISA_WAZUH_API_USER"]
    assert VARIAVEIS_WAZUH["SHEISA_WAZUH_API_PASSWORD"] not in resposta.text


# ------------------------------------------------------ teste de ligação
async def test_sem_credenciais_nao_contacta_e_diz_o_que_falta(
    cliente, sessao, token_admin, monkeypatch
):
    integracao = await _integracao(sessao, SourceKind.WAZUH)
    _com_variaveis(monkeypatch, {})
    servidor = _gestor_wazuh_saudavel(monkeypatch)

    corpo = await _testar(cliente, token_admin, integracao)

    assert corpo["sucesso"] is False
    assert corpo["estado"] == IntegrationStatus.NAO_CONFIGURADA.value
    assert corpo["variaveis_em_falta"] == list(VARIAVEIS_WAZUH)
    assert servidor.pedidos == [], "contactou o serviço sem credenciais"


async def test_ligacao_bem_sucedida_activa_e_regista_o_que_verificou(
    cliente, sessao, token_admin, monkeypatch
):
    integracao = await _integracao(sessao, SourceKind.WAZUH)
    integracao.config = {**integracao.config, "permitir_certificado_auto_assinado": True}
    await sessao.flush()
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = _gestor_wazuh_saudavel(monkeypatch)

    corpo = await _testar(cliente, token_admin, integracao)

    assert corpo == {
        "sucesso": True,
        "estado": IntegrationStatus.ACTIVA.value,
        "detalhe": "Ligação estabelecida com o gestor Wazuh v4.12.0; 2 agente(s) registado(s).",
    }
    assert servidor.caminhos() == [
        ("POST", "/security/user/authenticate"),
        ("GET", "/manager/info"),
        ("GET", "/agents"),
    ]
    autenticacao, *seguintes = servidor.pedidos
    assert autenticacao.headers["Authorization"].startswith("Basic ")
    assert all(p.headers["Authorization"] == "Bearer token-de-teste" for p in seguintes)

    await sessao.refresh(integracao)
    assert (integracao.is_enabled, integracao.last_check_ok) == (True, True)
    auditoria = (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "TESTAR_INTEGRACAO", AuditLog.resource_id == integracao.id
            )
        )
    ).scalar_one()
    assert "bem-sucedido" in auditoria.description


async def test_ligacao_recusada_fica_em_erro_com_o_motivo(
    cliente, sessao, token_admin, monkeypatch
):
    integracao = await _integracao(sessao, SourceKind.WAZUH)
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    ServidorFalso(monkeypatch, {
        ("POST", "/security/user/authenticate"): (401, {"title": "Unauthorized"}),
    })

    corpo = await _testar(cliente, token_admin, integracao)

    assert corpo["sucesso"] is False
    assert corpo["estado"] == IntegrationStatus.ERRO.value
    await sessao.refresh(integracao)
    assert integracao.last_check_ok is False
    assert "401" in (integracao.last_error or "")


async def test_fonte_sem_cliente_de_saida_nao_finge_uma_verificacao(
    cliente, sessao, token_admin
):
    """O Suricata só empurra eventos: não há nada a que ligar, e isso é dito."""
    integracao = await _integracao(sessao, SourceKind.SURICATA)

    corpo = await _testar(cliente, token_admin, integracao)

    assert corpo["sucesso"] is False
    assert corpo["detalhe"] == "Não existe cliente implementado para SURICATA."
    assert corpo["estado"] == IntegrationStatus.NAO_CONFIGURADA.value


async def test_certificado_auto_assinado_so_com_autorizacao_explicita(monkeypatch):
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = _gestor_wazuh_saudavel(monkeypatch)
    conector = WazuhConnector()

    await conector.test_connection(Integration(name="Wazuh", config={}))
    await conector.test_connection(
        Integration(name="Wazuh", config={"permitir_certificado_auto_assinado": True})
    )

    assert servidor.verificacoes == [True, False]


async def test_a_url_configurada_prevalece_sobre_a_variavel_de_ambiente(monkeypatch):
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = _gestor_wazuh_saudavel(monkeypatch)

    await WazuhConnector().test_connection(
        Integration(name="Wazuh", config={"base_url": "https://outro-gestor.invalid:55000/"})
    )

    assert {p.url.host for p in servidor.pedidos} == {"outro-gestor.invalid"}


# ----------------------------------------------------- acções no Wazuh
async def test_accao_que_o_conector_nao_executa_falha_explicitamente(monkeypatch):
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = _gestor_wazuh_saudavel(monkeypatch)

    with pytest.raises(IntegrationNotAvailableError, match="não implementa a acção BLOQUEAR_IP"):
        await WazuhConnector().execute_action(
            Integration(name="Wazuh", config={}), ActionKind.BLOQUEAR_IP, {"ip": "203.0.113.7"}, {}
        )
    assert servidor.pedidos == []


async def test_accao_sem_agente_nao_chega_a_contactar_o_gestor(monkeypatch):
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = _gestor_wazuh_saudavel(monkeypatch)

    with pytest.raises(IntegrationNotAvailableError, match="identificador do agente"):
        await WazuhConnector().execute_action(
            Integration(name="Wazuh", config={}), ActionKind.ISOLAR_ACTIVO, {}, {}
        )
    assert servidor.pedidos == []


async def test_agente_inactivo_e_insucesso_e_guarda_a_resposta_do_gestor(monkeypatch):
    """Resposta real do gestor do laboratório a um agente desligado."""
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = ServidorFalso(monkeypatch, {
        ("POST", "/security/user/authenticate"): (200, AUTENTICACAO),
        ("PUT", "/active-response"): (200, AGENTE_INACTIVO),
    })

    resultado = await WazuhConnector().execute_action(
        Integration(name="Wazuh", config={}),
        ActionKind.ISOLAR_ACTIVO, {"agent_id": "001"}, {},
    )

    assert resultado.success is False
    assert resultado.detail == "O Wazuh não aplicou a resposta activa ao agente 001."
    assert resultado.raw_response == AGENTE_INACTIVO
    envio = servidor.pedidos[-1]
    assert envio.url.params["agents_list"] == "001"


# -------------------------------------------------------- QRadar e NetScout
async def test_qradar_testa_a_ligacao_com_token_e_versao_da_api(monkeypatch):
    _com_variaveis(monkeypatch, {
        "SHEISA_QRADAR_API_URL": "https://qradar.invalid",
        "SHEISA_QRADAR_API_TOKEN": "token-qradar",
    })
    servidor = ServidorFalso(monkeypatch, {
        ("GET", "/api/system/about"): (200, {"release_name": "7.5.0", "build_version": "2024.1"}),
    })

    detalhe = await QRadarConnector().test_connection(Integration(name="IBM QRadar", config={}))

    assert detalhe == "Ligação estabelecida com o QRadar 7.5.0 (build 2024.1)."
    cabecalhos = servidor.pedidos[0].headers
    assert (cabecalhos["SEC"], cabecalhos["Version"]) == ("token-qradar", QRadarConnector.API_VERSION)


async def test_qradar_sem_token_falha_antes_de_contactar(monkeypatch):
    _com_variaveis(monkeypatch, {"SHEISA_QRADAR_API_URL": "https://qradar.invalid"})
    servidor = ServidorFalso(monkeypatch, {})

    with pytest.raises(IntegrationNotAvailableError, match="SHEISA_QRADAR_API_TOKEN"):
        await QRadarConnector().test_connection(Integration(name="IBM QRadar", config={}))
    # O cliente é aberto antes de montar os cabeçalhos, mas nenhum pedido sai.
    assert servidor.pedidos == []


async def test_netscout_testa_a_ligacao_com_o_seu_cabecalho(monkeypatch):
    _com_variaveis(monkeypatch, {
        "SHEISA_NETSCOUT_API_URL": "https://sightline.invalid",
        "SHEISA_NETSCOUT_API_TOKEN": "token-netscout",
    })
    servidor = ServidorFalso(monkeypatch, {
        ("GET", "/api/sp/v7/alerts"): (200, {"data": [], "meta": {"available": 12}}),
    })

    detalhe = await NetScoutConnector().test_connection(Integration(name="NetScout", config={}))

    assert detalhe == "Ligação estabelecida com o NetScout; 12 alerta(s) acessível(is)."
    assert servidor.pedidos[0].headers["X-Arbux-APIToken"] == "token-netscout"


async def test_sem_url_nenhum_conector_arranca(monkeypatch):
    _com_variaveis(monkeypatch, {"SHEISA_NETSCOUT_API_TOKEN": "token-netscout"})
    ServidorFalso(monkeypatch, {})

    with pytest.raises(IntegrationNotAvailableError, match="SHEISA_NETSCOUT_API_URL"):
        await NetScoutConnector().test_connection(Integration(name="NetScout", config={}))


# ----------------------------------------------- o motivo de uma falha
async def test_a_accao_falhada_regista_porque_falhou(
    cliente, sessao, token_analista, token_gestor, token_admin, monkeypatch
):
    """Regressão: o registo da acção dizia que falhou, mas não porquê.

    O conector levanta `IntegrationNotAvailableError` com o motivo em `details`, e
    `execute_action` grava `str(exc)` — que era só "A integração 'Wazuh' não está
    disponível.". Um analista a olhar para a acção falhada não tinha forma de
    saber que faltava o agente no alvo.
    """
    integracao = await _integracao(sessao, SourceKind.WAZUH)
    integracao.status = IntegrationStatus.ACTIVA
    integracao.is_enabled = True
    await sessao.flush()
    _com_variaveis(monkeypatch, VARIAVEIS_WAZUH)
    servidor = _gestor_wazuh_saudavel(monkeypatch)

    incidente = await cliente.post(
        "/api/incidents",
        json={"title": "Activo comprometido", "description": "x",
              "category": "CODIGO_MALICIOSO", "severity": "ALTA"},
        headers=cabecalho(token_analista),
    )
    assert incidente.status_code == 201, incidente.text
    accao = await cliente.post(
        "/api/actions",
        json={
            "incident_id": incidente.json()["id"],
            "action_kind": "ISOLAR_ACTIVO",
            "title": "Isolar o servidor",
            "rationale": "Comunicação com infra-estrutura de comando e controlo.",
            "target": {"activo": "srv-web-01"},
        },
        headers=cabecalho(token_analista),
    )
    assert accao.status_code == 201, accao.text
    decisao = await cliente.post(
        f"/api/approvals/{accao.json()['id']}/decide",
        json={"approved": True, "justification": "Contenção necessária."},
        headers=cabecalho(token_gestor),
    )
    assert decisao.status_code == 200, decisao.text

    execucao = await cliente.post(
        f"/api/actions/{accao.json()['id']}/execute", headers=cabecalho(token_admin)
    )

    assert execucao.status_code == 200, execucao.text
    assert execucao.json()["status"] == "FALHADA"
    assert "identificador do agente" in (execucao.json()["error"] or ""), execucao.json()["error"]
    assert servidor.pedidos == []
