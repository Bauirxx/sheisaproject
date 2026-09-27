"""Acções de resposta: reversão, caducidade e execução (`action_service`, rotas).

Dois defeitos, ambos de registo que não corresponde ao que aconteceu:

* **Propor a reversão dava a acção por revertida.** `revert_action` propõe a
  acção inversa — que, sendo de risco moderado, fica à espera de aprovação — e
  marcava logo a original como REVERTIDA. O incidente passava a dizer que o
  endereço tinha sido desbloqueado quando nada fora feito; e, se a inversa fosse
  rejeitada, a original já não podia ser revertida ("já foi revertida"). A
  interface diz ao analista o contrário: "não desfaz nada directamente".
* **Uma aprovação caducada ficava para sempre na fila.** Decidi-la devolvia 409
  sem mudar nada, e a acção continuava AGUARDA_APROVACAO, com botões de decisão
  que falhavam sempre. A base de desenvolvimento tinha um caso real: ACT-000001,
  caducado desde a véspera, ainda na fila.

Nenhum conector real executa `DESBLOQUEAR_IP`, pelo que o caminho de sucesso usa
um conector falso — só aqui, e apenas na fronteira com o sistema externo.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.enums import (
    ActionKind,
    ActionStatus,
    IntegrationStatus,
    NotificationKind,
    SourceKind,
)
from app.integrations.base import ActionResult
from app.models.identity import User
from app.models.response import Action, ActionApproval
from app.models.system import Integration, Notification
from app.services import action_service
from tests.conftest import cabecalho


class ConectorFalso:
    """Executa com sucesso as acções que lhe pedirem. Só para testes."""

    kind = SourceKind.WAZUH
    supported_actions = (ActionKind.DESBLOQUEAR_IP, ActionKind.ISOLAR_ACTIVO)

    def __init__(self) -> None:
        self.executadas: list[tuple[ActionKind, dict]] = []

    async def execute_action(self, integration, action_kind, target, parameters):
        self.executadas.append((action_kind, target))
        return ActionResult(success=True, detail="Executada pelo conector de teste.")


@pytest.fixture
async def conector(sessao, monkeypatch) -> ConectorFalso:
    falso = ConectorFalso()
    monkeypatch.setattr(action_service, "connectors_supporting",
                        lambda kind: [falso] if kind in falso.supported_actions else [])
    monkeypatch.setattr(action_service, "get_connector", lambda kind: falso)
    sessao.add(Integration(name="Wazuh de teste", kind=SourceKind.WAZUH,
                           status=IntegrationStatus.ACTIVA, is_enabled=True))
    await sessao.flush()
    return falso


async def _incidente(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": "Incidente com resposta", "description": "x",
              "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _propor(cliente, token, incidente, tipo="BLOQUEAR_IP", alvo=None) -> dict:
    resposta = await cliente.post(
        "/api/actions",
        json={"incident_id": incidente["id"], "action_kind": tipo,
              "title": f"Acção {tipo}", "rationale": "Justificação da acção.",
              "target": alvo or {"ip": "203.0.113.9"}},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _executada(sessao, accao: dict) -> Action:
    """Uma acção que já foi executada — nenhum conector real bloqueia IPs."""
    registo = await sessao.get(Action, uuid.UUID(accao["id"]))
    registo.status = ActionStatus.EXECUTADA
    registo.executed_at = datetime.now(UTC)
    await sessao.flush()
    return registo


async def _reverter(cliente, token, accao_id):
    return await cliente.post(
        f"/api/actions/{accao_id}/revert",
        json={"rationale": "O endereço pertence a um parceiro."},
        headers=cabecalho(token),
    )


async def _decidir(cliente, token, accao_id, aprovar=True):
    return await cliente.post(
        f"/api/approvals/{accao_id}/decide",
        json={"approved": aprovar, "justification": "Decisão fundamentada."},
        headers=cabecalho(token),
    )


# ----------------------------------------------------------------- reversão
async def test_propor_a_reversao_nao_da_a_accao_por_revertida(
    cliente, sessao, token_analista
):
    """Regressão: a original ficava REVERTIDA com a inversa ainda por aprovar."""
    incidente = await _incidente(cliente, token_analista)
    original = await _executada(sessao, await _propor(cliente, token_analista, incidente))

    resposta = await _reverter(cliente, token_analista, original.id)

    assert resposta.status_code == 200, resposta.text
    inversa = resposta.json()
    assert (inversa["action_kind"], inversa["status"]) == ("DESBLOQUEAR_IP", "AGUARDA_APROVACAO")
    await sessao.refresh(original)
    assert original.status is ActionStatus.EXECUTADA
    assert original.reverted_at is None


async def test_a_accao_so_fica_revertida_quando_a_inversa_e_executada(
    cliente, sessao, conector, token_analista, token_gestor, token_admin
):
    incidente = await _incidente(cliente, token_analista)
    original = await _executada(sessao, await _propor(cliente, token_analista, incidente))
    inversa = (await _reverter(cliente, token_analista, original.id)).json()
    assert (await _decidir(cliente, token_gestor, inversa["id"])).status_code == 200

    execucao = await cliente.post(
        f"/api/actions/{inversa['id']}/execute", headers=cabecalho(token_admin)
    )

    assert execucao.status_code == 200, execucao.text
    assert execucao.json()["status"] == "EXECUTADA"
    assert conector.executadas == [(ActionKind.DESBLOQUEAR_IP, {"ip": "203.0.113.9"})]
    await sessao.refresh(original)
    assert original.status is ActionStatus.REVERTIDA
    assert original.reverted_at is not None
    assert str(original.reverted_by_action_id) == inversa["id"]


async def test_reversao_rejeitada_permite_propor_outra(
    cliente, sessao, token_analista, token_gestor
):
    """Regressão: rejeitada a inversa, a original ficava irreversível."""
    incidente = await _incidente(cliente, token_analista)
    original = await _executada(sessao, await _propor(cliente, token_analista, incidente))
    primeira = (await _reverter(cliente, token_analista, original.id)).json()
    assert (await _decidir(cliente, token_gestor, primeira["id"], aprovar=False)).status_code == 200

    segunda = await _reverter(cliente, token_analista, original.id)

    assert segunda.status_code == 200, segunda.text
    assert segunda.json()["id"] != primeira["id"]


async def test_nao_se_propoem_duas_reversoes_ao_mesmo_tempo(cliente, sessao, token_analista):
    incidente = await _incidente(cliente, token_analista)
    original = await _executada(sessao, await _propor(cliente, token_analista, incidente))
    primeira = (await _reverter(cliente, token_analista, original.id)).json()

    segunda = await _reverter(cliente, token_analista, original.id)

    assert segunda.status_code == 409, segunda.text
    assert primeira["reference"] in segunda.json()["erro"]["mensagem"]


async def test_so_se_reverte_o_que_foi_executado_e_tem_inversa(
    cliente, sessao, token_analista
):
    incidente = await _incidente(cliente, token_analista)
    por_aprovar = await _propor(cliente, token_analista, incidente)
    sem_inversa = await _executada(
        sessao, await _propor(cliente, token_analista, incidente, tipo="RECOLHER_ARTEFACTOS",
                              alvo={"agent_id": "001"})
    )

    assert (await _reverter(cliente, token_analista, por_aprovar["id"])).status_code == 409
    assert (await _reverter(cliente, token_analista, sem_inversa.id)).status_code == 409


# --------------------------------------------------------------- caducidade
async def test_aprovacao_caducada_cancela_a_accao_e_sai_da_fila(
    cliente, sessao, token_analista, token_gestor
):
    """Regressão: ficava AGUARDA_APROVACAO para sempre, com decisões que falhavam."""
    incidente = await _incidente(cliente, token_analista)
    accao = await _propor(cliente, token_analista, incidente)
    pedido = (
        await sessao.execute(
            select(ActionApproval).where(ActionApproval.action_id == uuid.UUID(accao["id"]))
        )
    ).scalar_one()
    pedido.expires_at = datetime.now(UTC) - timedelta(hours=1)
    await sessao.flush()

    decisao = await _decidir(cliente, token_gestor, accao["id"])

    assert decisao.status_code == 409, decisao.text
    assert "caducou" in decisao.json()["erro"]["mensagem"]
    detalhe = (
        await cliente.get(f"/api/actions/{accao['id']}", headers=cabecalho(token_gestor))
    ).json()
    assert detalhe["status"] == "CANCELADA"
    assert [a["decision"] for a in detalhe["approvals"]] == ["CADUCADA"]
    fila = (await cliente.get("/api/approvals", headers=cabecalho(token_gestor))).json()
    assert accao["id"] not in {i["id"] for i in fila["itens"]}


async def test_a_fila_nao_mostra_pedidos_caducados_que_ninguem_tentou_decidir(
    cliente, sessao, token_analista, token_gestor
):
    """O caso de ACT-000001: caducou sem que ninguém tentasse decidi-lo."""
    incidente = await _incidente(cliente, token_analista)
    accao = await _propor(cliente, token_analista, incidente)
    pedido = (
        await sessao.execute(
            select(ActionApproval).where(ActionApproval.action_id == uuid.UUID(accao["id"]))
        )
    ).scalar_one()
    pedido.expires_at = datetime.now(UTC) - timedelta(days=1)
    await sessao.flush()

    fila = (await cliente.get("/api/approvals", headers=cabecalho(token_gestor))).json()

    assert accao["id"] not in {i["id"] for i in fila["itens"]}


# ------------------------------------------------------------------ execução
async def test_executar_accao_de_risco_sem_aprovacao_e_recusado(cliente, token_analista, token_admin):
    incidente = await _incidente(cliente, token_analista)
    accao = await _propor(cliente, token_analista, incidente)

    resposta = await cliente.post(
        f"/api/actions/{accao['id']}/execute", headers=cabecalho(token_admin)
    )

    assert resposta.status_code == 409, resposta.text
    assert resposta.json()["erro"]["codigo"] == "APROVACAO_NECESSARIA"


async def test_falha_do_conector_fica_registada_como_falhada(
    cliente, sessao, conector, token_analista, token_gestor, token_admin, monkeypatch
):
    async def rebentar(*_args, **_kwargs):
        raise RuntimeError("tempo esgotado a contactar o gestor")

    monkeypatch.setattr(conector, "execute_action", rebentar)
    incidente = await _incidente(cliente, token_analista)
    accao = await _propor(cliente, token_analista, incidente, tipo="ISOLAR_ACTIVO",
                          alvo={"agent_id": "001"})
    await _decidir(cliente, token_gestor, accao["id"])

    resposta = await cliente.post(
        f"/api/actions/{accao['id']}/execute", headers=cabecalho(token_admin)
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] == "FALHADA"
    assert "tempo esgotado" in resposta.json()["error"]
    integracao = (
        await sessao.execute(select(Integration).where(Integration.name == "Wazuh de teste"))
    ).scalar_one()
    assert (integracao.actions_executed, integracao.actions_failed) == (1, 1)


async def test_falha_de_accao_notifica_quem_a_propos(
    cliente, sessao, conector, token_analista, token_gestor, token_admin, monkeypatch
):
    """Quem propôs a acção é avisado de que falhou — não quem carregou no
    executar. É o proponente que precisa de saber que o seu pedido não pegou."""
    async def rebentar(*_args, **_kwargs):
        raise RuntimeError("o gestor nao respondeu")

    monkeypatch.setattr(conector, "execute_action", rebentar)
    analista = (
        await sessao.execute(select(User).where(User.email == "analista@teste.local"))
    ).scalar_one()

    incidente = await _incidente(cliente, token_analista)
    accao = await _propor(cliente, token_analista, incidente, tipo="ISOLAR_ACTIVO",
                          alvo={"agent_id": "001"})
    await _decidir(cliente, token_gestor, accao["id"])

    # Executada pelo admin: o proponente (analista) é que deve ser notificado.
    resposta = await cliente.post(
        f"/api/actions/{accao['id']}/execute", headers=cabecalho(token_admin)
    )
    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] == "FALHADA"

    notifs = list(
        (
            await sessao.execute(
                select(Notification).where(
                    Notification.user_id == analista.id,
                    Notification.kind == NotificationKind.ACCAO_FALHADA,
                )
            )
        ).scalars()
    )
    assert len(notifs) == 1
    assert notifs[0].resource_reference == accao["reference"]


async def test_filtros_da_lista_de_accoes(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    critica = await _propor(cliente, token_analista, incidente)
    baixa = await _propor(cliente, token_analista, incidente, tipo="RECOLHER_ARTEFACTOS",
                          alvo={"agent_id": "001"})

    async def ids(consulta):
        resposta = await cliente.get(f"/api/actions?{consulta}", headers=cabecalho(token_analista))
        assert resposta.status_code == 200, resposta.text
        return {a["id"] for a in resposta.json()["itens"]}

    doincidente = await ids(f"incident_id={incidente['id']}")
    assert doincidente == {critica["id"], baixa["id"]}
    assert critica["id"] in await ids(f"incident_id={incidente['id']}&risco=CRITICO")
    assert baixa["id"] not in await ids(f"incident_id={incidente['id']}&risco=CRITICO")
    assert await ids(f"incident_id={incidente['id']}&estado=EXECUTADA") == set()


async def test_o_painel_nao_conta_pedidos_caducados(
    cliente, sessao, token_analista, token_gestor
):
    """Um pedido que ninguém pode decidir não é trabalho pendente."""
    incidente = await _incidente(cliente, token_analista)
    valida = await _propor(cliente, token_analista, incidente)
    caducada = await _propor(cliente, token_analista, incidente)
    pedido = (
        await sessao.execute(
            select(ActionApproval).where(ActionApproval.action_id == uuid.UUID(caducada["id"]))
        )
    ).scalar_one()
    pedido.expires_at = datetime.now(UTC) - timedelta(days=1)
    await sessao.flush()

    painel = (await cliente.get("/api/dashboard", headers=cabecalho(token_gestor))).json()
    centro = (await cliente.get("/api/soc", headers=cabecalho(token_gestor))).json()

    assert painel["resposta"]["aprovacoes_pendentes"] == 1
    assert [a["id"] for a in centro["aprovacoes_pendentes"]] == [valida["id"]]


async def test_playbook_suspenso_numa_aprovacao_caducada_e_terminado(
    cliente, sessao, token_admin, token_analista, token_gestor
):
    """Sem isto ficava AGUARDA_APROVACAO para sempre, como antes da correcção 18."""
    incidente = await _incidente(cliente, token_analista)
    playbook = (
        await cliente.post(
            "/api/playbooks",
            json={"name": "Playbook que espera demasiado", "description": "x",
                  "is_enabled": True,
                  "steps": [{"ordering": 1, "name": "Autorizar", "step_type": "SOLICITAR_APROVACAO",
                             "parameters": {"motivo": "Confirmar."}, "requires_approval": True,
                             "risk_level": "CRITICO"}]},
            headers=cabecalho(token_admin),
        )
    ).json()
    execucao = (
        await cliente.post(
            f"/api/playbooks/{playbook['id']}/run", json={"incident_id": incidente["id"]},
            headers=cabecalho(token_analista),
        )
    ).json()
    for pedido in (await sessao.execute(select(ActionApproval))).scalars():
        pedido.expires_at = datetime.now(UTC) - timedelta(minutes=5)
    await sessao.flush()

    await cliente.get("/api/approvals", headers=cabecalho(token_gestor))

    actual = (
        await cliente.get(
            f"/api/playbooks/executions/{execucao['id']}", headers=cabecalho(token_analista)
        )
    ).json()
    assert actual["status"] == "CANCELADA"
    assert "caducou" in (actual["error"] or ""), actual["error"]
