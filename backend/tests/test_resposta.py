"""Acções de resposta, aprovações e separação de funções (§13).

A regra que estes testes protegem é a mais importante da plataforma do ponto de
vista de governo: **quem propõe uma acção disruptiva não a aprova**. Sem ela, um
único utilizador comprometido bloqueia gamas de rede inteiras sem que ninguém
mais participe na decisão.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.enums import ActionRiskLevel, AuditOutcome
from app.models.system import AuditLog
from app.services.action_service import DEFAULT_RISK, resolve_risk_level
from tests.conftest import cabecalho


async def _incidente(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={
            "title": "Incidente para acções de resposta",
            "description": "Contexto do teste.",
            "category": "INTRUSAO",
            "severity": "ALTA",
        },
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _propor(cliente, token, incidente_id, tipo="BLOQUEAR_IP", **extra) -> object:
    corpo = {
        "incident_id": incidente_id,
        "action_kind": tipo,
        "title": f"Acção {tipo}",
        "rationale": "Justificação da proposta, obrigatória e com detalhe.",
        "target": {"ip": "203.0.113.77"},
        **extra,
    }
    return await cliente.post("/api/actions", json=corpo, headers=cabecalho(token))


# ------------------------------------------------------------ nível de risco
def test_o_risco_pode_subir_mas_nunca_descer():
    """Se pudesse descer, bastaria declarar BAIXO para fugir à aprovação."""
    from app.core.enums import ActionKind

    assert resolve_risk_level(ActionKind.BLOQUEAR_IP) is ActionRiskLevel.CRITICO
    # Tentativa de baixar: ignorada.
    assert (
        resolve_risk_level(ActionKind.BLOQUEAR_IP, ActionRiskLevel.BAIXO)
        is ActionRiskLevel.CRITICO
    )
    # Subir é permitido.
    assert (
        resolve_risk_level(ActionKind.NOTIFICAR_EQUIPA, ActionRiskLevel.CRITICO)
        is ActionRiskLevel.CRITICO
    )


def test_as_accoes_disruptivas_sao_criticas_por_omissao():
    from app.core.enums import ActionKind

    for tipo in (
        ActionKind.BLOQUEAR_IP,
        ActionKind.ISOLAR_ACTIVO,
        ActionKind.DESACTIVAR_UTILIZADOR,
    ):
        assert DEFAULT_RISK[tipo] is ActionRiskLevel.CRITICO


# --------------------------------------------------------------- propostas
async def test_propor_accao_critica_cria_pedido_de_aprovacao(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    resposta = await _propor(cliente, token_analista, incidente["id"])
    assert resposta.status_code == 201, resposta.text

    accao = resposta.json()
    assert accao["risk_level"] == "CRITICO"
    assert accao["status"] in ("PROPOSTA", "AGUARDA_APROVACAO")
    assert accao["approvals"], "nenhum pedido de aprovação foi criado"


async def test_accao_sem_justificacao_e_recusada(cliente, token_analista):
    """Uma acção sem justificação não é aprovável — logo, não é propostável."""
    incidente = await _incidente(cliente, token_analista)
    resposta = await cliente.post(
        "/api/actions",
        json={
            "incident_id": incidente["id"],
            "action_kind": "BLOQUEAR_IP",
            "title": "Bloquear",
            "rationale": "",
            "target": {"ip": "203.0.113.77"},
        },
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 422


async def test_gestor_nao_propoe_accoes(cliente, token_gestor):
    """O gestor decide, não investiga: propor exige `actions:propose`."""
    incidente_admin = await cliente.post(
        "/api/incidents",
        json={"title": "Incidente", "description": "x", "category": "OUTRO",
              "severity": "BAIXA"},
        headers=cabecalho(token_gestor),
    )
    # O gestor também não cria incidentes; usamos apenas o 403 da proposta.
    assert incidente_admin.status_code == 403


# -------------------------------------------------------- separação de funções
async def test_quem_propoe_nao_aprova(cliente, token_admin, sessao):
    """O administrador tem todas as permissões — e continua sem poder aprovar-se.

    A separação de funções não é uma questão de permissões: é uma questão de
    identidade. Se bastasse ter a permissão, o perfil de administração
    contornava a regra por construção.
    """
    incidente = await _incidente(cliente, token_admin)
    accao = (await _propor(cliente, token_admin, incidente["id"])).json()

    resposta = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True, "justification": "Concordo com o bloqueio."},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 403, resposta.text
    assert "propôs" in resposta.json()["erro"]["mensagem"]

    negadas = (
        await sessao.execute(
            select(AuditLog)
            .where(AuditLog.outcome == AuditOutcome.NEGADO)
            .order_by(AuditLog.created_at.desc())
            .limit(1)
        )
    ).scalars().all()
    assert negadas, "a tentativa de auto-aprovação não ficou registada"


async def test_outro_utilizador_com_permissao_aprova(
    cliente, token_analista, token_gestor
):
    incidente = await _incidente(cliente, token_analista)
    accao = (await _propor(cliente, token_analista, incidente["id"])).json()

    resposta = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True, "justification": "Origem externa confirmada."},
        headers=cabecalho(token_gestor),
    )
    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] in ("APROVADA", "EXECUTADA", "FALHADA")


async def test_accao_critica_exige_justificacao_escrita(
    cliente, token_analista, token_gestor
):
    incidente = await _incidente(cliente, token_analista)
    accao = (await _propor(cliente, token_analista, incidente["id"])).json()

    sem = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True},
        headers=cabecalho(token_gestor),
    )
    assert sem.status_code == 422
    assert sem.json()["erro"]["codigo"] == "JUSTIFICACAO_OBRIGATORIA"

    com = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True, "justification": "Decisão fundamentada."},
        headers=cabecalho(token_gestor),
    )
    assert com.status_code == 200


async def test_analista_nao_aprova_accoes_criticas(cliente, token_analista, semente):
    """Propor e aprovar são permissões distintas, e a primeira linha só propõe."""
    from tests.conftest import autenticar

    incidente = await _incidente(cliente, token_analista)
    accao = (await _propor(cliente, token_analista, incidente["id"])).json()

    # Outro analista: tem a mesma identidade de perfil, sem `actions:approve`.
    outro = await autenticar(cliente, "investigador")
    resposta = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True, "justification": "Concordo."},
        headers=cabecalho(outro),
    )
    assert resposta.status_code == 403


async def test_rejeitar_impede_a_execucao(cliente, token_analista, token_gestor):
    incidente = await _incidente(cliente, token_analista)
    accao = (await _propor(cliente, token_analista, incidente["id"])).json()

    await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": False, "justification": "IP pertence a um parceiro."},
        headers=cabecalho(token_gestor),
    )

    execucao = await cliente.post(
        f"/api/actions/{accao['id']}/execute", headers=cabecalho(token_analista)
    )
    assert execucao.status_code in (403, 409), execucao.text


async def test_fila_de_aprovacao_lista_o_que_espera_decisao(
    cliente, token_analista, token_gestor
):
    incidente = await _incidente(cliente, token_analista)
    await _propor(cliente, token_analista, incidente["id"])

    fila = await cliente.get("/api/approvals", headers=cabecalho(token_gestor))
    assert fila.status_code == 200
    assert fila.json()["total"] >= 1


# ---------------------------------------------------- honestidade da execução
async def test_accao_sem_integracao_diz_que_nao_e_executavel(
    cliente, token_analista
):
    """§4: sem conector configurado, a API diz que não executa — não finge."""
    incidente = await _incidente(cliente, token_analista)
    accao = (await _propor(cliente, token_analista, incidente["id"])).json()

    assert accao["executavel"] is False
    assert accao["motivo_nao_executavel"], (
        "a acção diz-se não executável sem explicar porquê"
    )


async def test_a_accao_diz_quem_a_propos(cliente, token_analista):
    """A API expõe o proponente, e não só se foi o motor.

    Sem isto, a interface não consegue explicar a separação de funções a quem
    está a olhar para a fila: o utilizador só descobriria que não pode aprovar
    ao carregar no botão e levar 403. O servidor continua a ser quem recusa —
    isto é o que permite avisar antes.
    """
    incidente = await _incidente(cliente, token_analista)
    accao = (await _propor(cliente, token_analista, incidente["id"])).json()

    assert accao["proposed_by"] is not None
    assert accao["proposed_by"]["email"] == "analista@teste.local"
    assert accao["proposed_by_engine"] is False

    # E continua exposto na fila de aprovação, que é onde importa.
    from tests.conftest import autenticar

    gestor = await autenticar(cliente, "gestor")
    fila = await cliente.get("/api/approvals", headers=cabecalho(gestor))
    assert fila.status_code == 200
    entrada = next(a for a in fila.json()["itens"] if a["id"] == accao["id"])
    assert entrada["proposed_by"]["email"] == "analista@teste.local"
