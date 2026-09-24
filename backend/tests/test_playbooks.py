"""Playbooks: sugestão, execução, suspensão em aprovação e retoma (§14).

A propriedade que aqui importa é que a automação **não contorna** o controlo
humano. Um playbook que chegasse a um passo de aprovação e o executasse à mesma
seria pior do que não ter playbooks: daria a aparência de governo sem o governo.
Por isso a execução suspende, fica à espera de uma decisão de outra pessoa, e só
depois continua de onde ficou.
"""

from __future__ import annotations

from app.core.enums import PlaybookExecutionStatus
from tests.conftest import cabecalho


async def _incidente(cliente, token, **campos) -> dict:
    corpo = {
        "title": "Incidente para playbook",
        "description": "x",
        "category": "INTRUSAO",
        "severity": "ALTA",
        **campos,
    }
    resposta = await cliente.post("/api/incidents", json=corpo, headers=cabecalho(token))
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _playbook(cliente, token, *, passos, **campos) -> dict:
    corpo = {
        "name": campos.pop("nome", "Playbook de teste"),
        "description": "Procedimento de teste.",
        "is_enabled": True,
        "trigger_min_severity": campos.pop("severidade_minima", "BAIXA"),
        "steps": passos,
        **campos,
    }
    resposta = await cliente.post("/api/playbooks", json=corpo, headers=cabecalho(token))
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


PASSO_NOTA = {
    "ordering": 1,
    "name": "Registar nota de abertura",
    "step_type": "REGISTAR_NOTA",
    "parameters": {"texto": "Procedimento iniciado automaticamente."},
    "requires_approval": False,
}


async def test_executar_playbook_simples_corre_ate_ao_fim(cliente, token_admin):
    incidente = await _incidente(cliente, token_admin)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook simples", passos=[PASSO_NOTA]
    )

    execucao = await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_admin),
    )
    assert execucao.status_code == 201, execucao.text
    corpo = execucao.json()
    assert corpo["status"] == PlaybookExecutionStatus.CONCLUIDA.value
    assert corpo["reference"].startswith("EXE-")


async def test_a_versao_do_playbook_e_copiada_para_a_execucao(cliente, token_admin):
    """Alterar o playbook depois não reescreve o que foi de facto executado."""
    incidente = await _incidente(cliente, token_admin)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook versionado", passos=[PASSO_NOTA]
    )

    execucao = (
        await cliente.post(
            f"/api/playbooks/{playbook['id']}/run",
            json={"incident_id": incidente["id"]},
            headers=cabecalho(token_admin),
        )
    ).json()
    assert execucao["playbook_version"] == playbook["version"]


async def test_a_execucao_suspende_num_passo_de_aprovacao(
    cliente, token_admin, token_analista
):
    """O playbook pára e espera — não decide por ninguém."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin,
        nome="Playbook com porta de aprovação",
        passos=[
            PASSO_NOTA,
            {
                "ordering": 2,
                "name": "Autorizar prosseguimento",
                "step_type": "SOLICITAR_APROVACAO",
                "parameters": {"motivo": "Confirmar antes de agir sobre produção."},
                "requires_approval": True,
                "risk_level": "CRITICO",
            },
            {
                "ordering": 3,
                "name": "Registar conclusão",
                "step_type": "REGISTAR_NOTA",
                "parameters": {"texto": "Procedimento concluído."},
            },
        ],
    )

    execucao = (
        await cliente.post(
            f"/api/playbooks/{playbook['id']}/run",
            json={"incident_id": incidente["id"]},
            headers=cabecalho(token_analista),
        )
    ).json()

    assert execucao["status"] == PlaybookExecutionStatus.AGUARDA_APROVACAO.value, (
        "a execução não suspendeu no passo de aprovação"
    )


async def test_o_passo_de_aprovacao_cria_algo_que_se_possa_aprovar(
    cliente, token_admin, token_analista, token_gestor
):
    """Regressão: o passo suspendia sem criar entidade nenhuma.

    A execução ficava em AGUARDA_APROVACAO para sempre, porque não havia nada
    na fila do aprovador. Foi para isto que se criou
    `ActionKind.AUTORIZAR_PROSSEGUIMENTO`.
    """
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin,
        nome="Playbook com aprovação real",
        passos=[
            {
                "ordering": 1,
                "name": "Autorizar prosseguimento",
                "step_type": "SOLICITAR_APROVACAO",
                "parameters": {"motivo": "Confirmar."},
                "requires_approval": True,
                "risk_level": "CRITICO",
            }
        ],
    )
    await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_analista),
    )

    fila = await cliente.get("/api/approvals", headers=cabecalho(token_gestor))
    assert fila.status_code == 200
    assert fila.json()["total"] >= 1, "a suspensão não deixou nada por aprovar"


async def test_a_aprovacao_retoma_a_execucao(
    cliente, token_admin, token_analista, token_gestor
):
    """Depois da decisão, o playbook continua de onde ficou."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin,
        nome="Playbook que retoma",
        passos=[
            {
                "ordering": 1,
                "name": "Autorizar prosseguimento",
                "step_type": "SOLICITAR_APROVACAO",
                "parameters": {"motivo": "Confirmar."},
                "requires_approval": True,
                "risk_level": "CRITICO",
            },
            {
                "ordering": 2,
                "name": "Registar conclusão",
                "step_type": "REGISTAR_NOTA",
                "parameters": {"texto": "Concluído após autorização."},
            },
        ],
    )

    execucao = (
        await cliente.post(
            f"/api/playbooks/{playbook['id']}/run",
            json={"incident_id": incidente["id"]},
            headers=cabecalho(token_analista),
        )
    ).json()
    assert execucao["status"] == PlaybookExecutionStatus.AGUARDA_APROVACAO.value

    fila = (await cliente.get("/api/approvals", headers=cabecalho(token_gestor))).json()
    accao = fila["itens"][0]

    decisao = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True, "justification": "Autorizo o prosseguimento."},
        headers=cabecalho(token_gestor),
    )
    assert decisao.status_code == 200, decisao.text

    listagem = await cliente.get(
        "/api/playbooks/executions/list", headers=cabecalho(token_analista)
    )
    assert listagem.status_code == 200, listagem.text
    itens = listagem.json()
    actual = next(e for e in (itens["itens"] if isinstance(itens, dict) else itens)
                  if e["id"] == execucao["id"])
    assert actual["status"] != PlaybookExecutionStatus.AGUARDA_APROVACAO.value, (
        "a execução ficou suspensa mesmo depois da aprovação"
    )


async def test_playbook_desactivado_nao_corre(cliente, token_admin):
    incidente = await _incidente(cliente, token_admin)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook desligado",
        passos=[PASSO_NOTA], is_enabled=False,
    )

    resposta = await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 409


async def test_sugestoes_trazem_sempre_a_razao(cliente, token_admin):
    """O analista tem de saber porque é que aquele procedimento lhe é proposto."""
    incidente = await _incidente(cliente, token_admin, severity="CRITICA")
    await _playbook(
        cliente, token_admin, nome="Playbook sugerível",
        passos=[PASSO_NOTA], trigger_category="INTRUSAO",
        severidade_minima="MEDIA",
    )

    sugestoes = await cliente.get(
        f"/api/playbooks/suggestions?incident_id={incidente['id']}",
        headers=cabecalho(token_admin),
    )
    assert sugestoes.status_code == 200, sugestoes.text
    itens = sugestoes.json()
    assert itens, "nenhum playbook sugerido para um incidente que satisfaz os gatilhos"
    for item in itens:
        assert item.get("motivo") or item.get("razao"), item


async def test_categoria_diferente_nao_e_sugerida(cliente, token_admin):
    incidente = await _incidente(cliente, token_admin, category="FRAUDE")
    await _playbook(
        cliente, token_admin, nome="Playbook só para intrusão",
        passos=[PASSO_NOTA], trigger_category="INTRUSAO",
    )

    sugestoes = (
        await cliente.get(
            f"/api/playbooks/suggestions?incident_id={incidente['id']}",
            headers=cabecalho(token_admin),
        )
    ).json()
    nomes = {s.get("nome") or s.get("name") for s in sugestoes}
    assert "Playbook só para intrusão" not in nomes


async def test_execucao_automatica_esta_desligada_por_omissao(cliente, token_admin):
    """Automação silenciosa é um risco, não uma comodidade."""
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook sem automatismo", passos=[PASSO_NOTA]
    )
    assert playbook["auto_execute"] is False


async def test_analista_nao_gere_playbooks(cliente, token_analista):
    """Executar e definir procedimentos são responsabilidades distintas."""
    resposta = await cliente.post(
        "/api/playbooks",
        json={
            "name": "Playbook que não devia ser criado",
            "description": "x",
            "steps": [PASSO_NOTA],
        },
        headers=cabecalho(token_analista),
    )
    # O analista tem `playbooks:execute` mas não `playbooks:manage`.
    assert resposta.status_code == 403


# ----------------------------------------------- depois da decisão humana
# Os quatro testes seguintes nasceram ao correr os playbooks semeados de ponta a
# ponta (ver `test_configuracao_inicial.py`). Nenhum dos defeitos dava erro: a
# execução ficava num estado plausível e errado.
def _porta(ordem: int, nome: str) -> dict:
    return {
        "ordering": ordem,
        "name": nome,
        "step_type": "SOLICITAR_APROVACAO",
        "parameters": {"motivo": "Confirmar."},
        "requires_approval": True,
        "risk_level": "CRITICO",
    }


async def _pendente(cliente, token, titulo) -> dict:
    fila = (await cliente.get("/api/approvals", headers=cabecalho(token))).json()
    return next(i for i in fila["itens"] if i["title"] == titulo)


async def _decidir(cliente, token, accao_id, *, aprovar=True):
    return await cliente.post(
        f"/api/approvals/{accao_id}/decide",
        json={"approved": aprovar, "justification": "Decisão fundamentada."},
        headers=cabecalho(token),
    )


async def _execucao(cliente, token, execucao_id) -> dict:
    listagem = (
        await cliente.get("/api/playbooks/executions/list", headers=cabecalho(token))
    ).json()
    itens = listagem["itens"] if isinstance(listagem, dict) else listagem
    return next(e for e in itens if e["id"] == execucao_id)


async def test_rejeitar_termina_a_execucao_em_vez_de_a_deixar_suspensa(
    cliente, token_admin, token_analista, token_gestor
):
    """Regressão: rejeitada a aprovação, a execução ficava AGUARDA_APROVACAO para sempre.

    Sem nada na fila de quem aprova, o painel mostrava um playbook à espera de
    uma decisão que já tinha sido tomada.
    """
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook rejeitável",
        passos=[_porta(1, "Autorizar contenção"), {**PASSO_NOTA, "ordering": 2}],
    )
    execucao = (
        await cliente.post(
            f"/api/playbooks/{playbook['id']}/run",
            json={"incident_id": incidente["id"]},
            headers=cabecalho(token_analista),
        )
    ).json()

    porta = await _pendente(cliente, token_gestor, "Autorizar contenção")
    decisao = await _decidir(cliente, token_gestor, porta["id"], aprovar=False)
    assert decisao.status_code == 200, decisao.text

    actual = await _execucao(cliente, token_analista, execucao["id"])
    assert actual["status"] == PlaybookExecutionStatus.CANCELADA.value
    assert porta["reference"] in (actual["error"] or "")
    assert actual["finished_at"] is not None
    assert [p["step_name"] for p in actual["step_executions"]] == ["Autorizar contenção"], (
        "um passo posterior à rejeição foi executado"
    )


async def test_quem_aprova_um_passo_pode_decidir_o_seguinte(
    cliente, token_admin, token_gestor
):
    """Regressão: a proposta do passo seguinte era atribuída a quem aprovou o anterior.

    A retoma corre no pedido do aprovador, e a proposta ficava em nome dele — que
    passava a não a poder decidir. A proposta é de quem iniciou o playbook, e a
    separação de funções continua a valer para essa pessoa.
    """
    incidente = await _incidente(cliente, token_admin)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook com duas portas",
        passos=[_porta(1, "Primeira autorização"), _porta(2, "Segunda autorização")],
    )
    await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_admin),
    )

    primeira = await _pendente(cliente, token_gestor, "Primeira autorização")
    assert (await _decidir(cliente, token_gestor, primeira["id"])).status_code == 200

    segunda = await _pendente(cliente, token_gestor, "Segunda autorização")
    assert segunda["proposed_by"]["email"] == "admin@teste.local"

    # Quem iniciou continua a não poder aprovar o que o seu playbook propôs...
    assert (await _decidir(cliente, token_admin, segunda["id"])).status_code == 403
    # ...e quem aprovou o passo anterior pode decidir este.
    decisao = await _decidir(cliente, token_gestor, segunda["id"])
    assert decisao.status_code == 200, decisao.text


async def test_a_autorizacao_aprovada_fica_fechada(
    cliente, token_admin, token_analista, token_gestor
):
    """Regressão: a porta aprovada ficava APROVADA para sempre, como se faltasse executá-la."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook com porta que fecha",
        passos=[_porta(1, "Autorizar e fechar"), {**PASSO_NOTA, "ordering": 2}],
    )
    await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_analista),
    )
    porta = await _pendente(cliente, token_gestor, "Autorizar e fechar")
    await _decidir(cliente, token_gestor, porta["id"])

    accao = (
        await cliente.get(f"/api/actions/{porta['id']}", headers=cabecalho(token_analista))
    ).json()
    assert accao["status"] == "EXECUTADA"


async def test_o_resumo_final_inclui_os_passos_anteriores_a_suspensao(
    cliente, token_admin, token_analista, token_gestor
):
    """Regressão: a retoma recomeçava o resumo e apagava o que correra antes da pausa."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook com resumo completo",
        passos=[
            PASSO_NOTA,
            _porta(2, "Autorizar a meio"),
            {**PASSO_NOTA, "ordering": 3, "name": "Registar fecho"},
        ],
    )
    execucao = (
        await cliente.post(
            f"/api/playbooks/{playbook['id']}/run",
            json={"incident_id": incidente["id"]},
            headers=cabecalho(token_analista),
        )
    ).json()
    porta = await _pendente(cliente, token_gestor, "Autorizar a meio")
    await _decidir(cliente, token_gestor, porta["id"])

    actual = await _execucao(cliente, token_analista, execucao["id"])
    assert actual["status"] == PlaybookExecutionStatus.CONCLUIDA.value
    resumo = actual["result_summary"]
    for linha in ("1. Registar nota de abertura", "2. Autorizar a meio", "3. Registar fecho"):
        assert linha in resumo, f"falta '{linha}' no resumo:\n{resumo}"


# ------------------------------------------- estado do incidente num playbook
# Encontrados ao aplicar a armadilha 5.15: o motor mudava `incident.status`
# directamente, verificando só o ciclo de vida. Tudo o resto que uma transição
# garante — marcos temporais das métricas de resposta, resumo obrigatório para
# RESOLVIDO, entrada ALTERAR_ESTADO na auditoria e na linha temporal — ficava
# por fazer.
def _passo_de_estado(ordem: int, estado: str) -> dict:
    return {
        "ordering": ordem,
        "name": f"Passar a {estado}",
        "step_type": "ALTERAR_ESTADO",
        "parameters": {"estado": estado},
        "abort_on_failure": True,
    }


async def _correr(cliente, token, playbook, incidente) -> dict:
    resposta = await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _mudancas_de_estado(sessao, incidente) -> list:
    import uuid

    from sqlalchemy import select

    from app.models.system import AuditLog

    return (
        await sessao.execute(
            select(AuditLog)
            .where(
                AuditLog.action == "ALTERAR_ESTADO",
                AuditLog.resource_id == uuid.UUID(incidente["id"]),
            )
            .order_by(AuditLog.created_at)
        )
    ).scalars().all()


async def test_o_passo_alterar_estado_regista_marcos_e_auditoria(
    cliente, sessao, token_admin, token_analista
):
    """Regressão: sem `contained_at`, o tempo até à contenção nunca era medido."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook que conduz o incidente",
        passos=[_passo_de_estado(1, "TRIAGEM"), _passo_de_estado(2, "INVESTIGACAO"),
                _passo_de_estado(3, "CONTENCAO")],
    )

    execucao = await _correr(cliente, token_analista, playbook, incidente)

    assert execucao["status"] == PlaybookExecutionStatus.CONCLUIDA.value, execucao
    actual = (
        await cliente.get(f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista))
    ).json()
    assert actual["status"] == "CONTENCAO"
    assert actual["acknowledged_at"] is not None
    assert actual["contained_at"] is not None
    mudancas = await _mudancas_de_estado(sessao, incidente)
    assert [m.new_value["estado"] for m in mudancas] == ["TRIAGEM", "INVESTIGACAO", "CONTENCAO"]


async def test_o_passo_nao_resolve_sem_o_resumo_que_a_transicao_exige(
    cliente, token_admin, token_analista
):
    """Regressão: o playbook resolvia o incidente sem resumo da resolução."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook que tenta resolver",
        passos=[_passo_de_estado(1, "TRIAGEM"), _passo_de_estado(2, "INVESTIGACAO"),
                _passo_de_estado(3, "RESOLVIDO")],
    )

    execucao = await _correr(cliente, token_analista, playbook, incidente)

    assert execucao["status"] == PlaybookExecutionStatus.FALHADA.value, execucao
    assert "resumo da resolução" in (execucao["error"] or "")
    actual = (
        await cliente.get(f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista))
    ).json()
    assert actual["status"] == "INVESTIGACAO"


async def test_o_estado_final_do_playbook_passa_pela_transicao_real(
    cliente, sessao, token_admin, token_analista
):
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook que fecha a triagem",
        passos=[PASSO_NOTA], closing_status="TRIAGEM",
    )

    await _correr(cliente, token_analista, playbook, incidente)

    actual = (
        await cliente.get(f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista))
    ).json()
    assert (actual["status"], actual["acknowledged_at"] is not None) == ("TRIAGEM", True)
    assert len(await _mudancas_de_estado(sessao, incidente)) == 1


async def test_estado_final_impossivel_fica_registado_em_vez_de_ignorado(
    cliente, token_admin, token_analista
):
    """Regressão: um estado final que o ciclo de vida recusa era saltado em silêncio."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook com estado final impossível",
        passos=[PASSO_NOTA], closing_status="ENCERRADO",
    )

    execucao = await _correr(cliente, token_admin, playbook, incidente)

    assert execucao["status"] == PlaybookExecutionStatus.CONCLUIDA.value
    # Quem corre (admin) tem incidents:close, logo o refuso é do ciclo de vida,
    # não da permissão — NOVO não transita directamente para ENCERRADO.
    assert "ENCERRADO não aplicado" in execucao["result_summary"], execucao["result_summary"]
    assert "permissão para encerrar" not in execucao["result_summary"]


async def test_playbook_nao_encerra_sem_a_permissao_de_encerrar(
    cliente, token_admin, token_analista
):
    """O motor chama o serviço directamente, pelo que a verificação de
    `incidents:close` da rota de transição não o alcança. Quem corre o playbook
    tem de a deter para que o estado final ENCERRADO se aplique — senão o
    incidente fica por encerrar e o resumo di-lo."""
    incidente = await _incidente(cliente, token_analista)
    playbook = await _playbook(
        cliente, token_admin, nome="Playbook que tenta encerrar",
        passos=[PASSO_NOTA], closing_status="ENCERRADO",
    )

    # O analista tem playbooks:execute mas não incidents:close.
    execucao = await _correr(cliente, token_analista, playbook, incidente)

    assert execucao["status"] == PlaybookExecutionStatus.CONCLUIDA.value
    assert "não tem a permissão para encerrar" in execucao["result_summary"]
    actual = (
        await cliente.get(
            f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista)
        )
    ).json()
    assert actual["status"] == "NOVO"  # não foi encerrado
    assert actual["closed_at"] is None
