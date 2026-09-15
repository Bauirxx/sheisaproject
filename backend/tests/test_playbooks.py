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
