"""Tarefas de investigação (§19).

A tarefa é a unidade que transforma a investigação numa sequência operacional.
Estes testes cobrem o que tem consequência no relatório final — o resultado
registado — e a regra de dependências, que é o que distingue uma lista de
afazeres de uma ordem de trabalho.

O primeiro teste existe por causa de um defeito real: concluir uma tarefa
devolvia 500. A rota obtinha a tarefa com `session.get()`, que não carrega a
relação `depends_on`, e a verificação de dependências disparava IO fora do
contexto assíncrono (`MissingGreenlet`). A suite não cobria este caminho.
"""

from __future__ import annotations

from tests.conftest import cabecalho


async def _criar_incidente(cliente, token) -> str:
    resposta = await cliente.post(
        "/api/incidents",
        json={
            "title": "Incidente para tarefas",
            "description": "Suporte aos testes de tarefas.",
            "category": "TENTATIVA_INTRUSAO",
            "severity": "ALTA",
        },
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()["id"]


async def _criar_tarefa(cliente, token, incidente_id, **campos) -> dict:
    resposta = await cliente.post(
        f"/api/tasks?incident_id={incidente_id}",
        json={"title": "Verificar acessos da origem", **campos},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def test_concluir_tarefa_regista_resultado_e_instante(cliente, token_analista):
    """Concluir uma tarefa tem de funcionar e guardar o resultado.

    Regressão: a rota devolvia 500 por carregamento tardio de `depends_on`.
    """
    incidente = await _criar_incidente(cliente, token_analista)
    tarefa = await _criar_tarefa(cliente, token_analista, incidente)

    resposta = await cliente.patch(
        f"/api/tasks/{tarefa['id']}",
        json={"status": "CONCLUIDA", "outcome": "Nenhum acesso bem sucedido."},
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 200, resposta.text
    corpo = resposta.json()
    assert corpo["status"] == "CONCLUIDA"
    assert corpo["outcome"] == "Nenhum acesso bem sucedido."
    # O instante é preenchido pelo servidor: é dele que o relatório se alimenta.
    assert corpo["completed_at"] is not None


async def test_iniciar_tarefa_marca_o_inicio(cliente, token_analista):
    incidente = await _criar_incidente(cliente, token_analista)
    tarefa = await _criar_tarefa(cliente, token_analista, incidente)

    resposta = await cliente.patch(
        f"/api/tasks/{tarefa['id']}",
        json={"status": "EM_CURSO"},
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["started_at"] is not None


async def test_dependencia_por_concluir_bloqueia_a_conclusao(cliente, token_analista):
    """A ordem operacional do §19 é imposta, não decorativa."""
    incidente = await _criar_incidente(cliente, token_analista)
    primeira = await _criar_tarefa(cliente, token_analista, incidente)
    segunda = await _criar_tarefa(
        cliente,
        token_analista,
        incidente,
        title="Depende da primeira",
        depends_on_ids=[primeira["id"]],
    )

    resposta = await cliente.patch(
        f"/api/tasks/{segunda['id']}",
        json={"status": "CONCLUIDA", "outcome": "Tentativa prematura."},
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 409, resposta.text
    erro = resposta.json()["erro"]
    assert erro["codigo"] == "DEPENDENCIAS_PENDENTES"
    # A resposta diz *quais* — sem isso o analista não sabe o que desbloquear.
    assert primeira["title"] in erro["detalhes"]["tarefas_pendentes"]


async def test_dependencia_concluida_liberta_a_tarefa(cliente, token_analista):
    incidente = await _criar_incidente(cliente, token_analista)
    primeira = await _criar_tarefa(cliente, token_analista, incidente)
    segunda = await _criar_tarefa(
        cliente,
        token_analista,
        incidente,
        title="Depende da primeira",
        depends_on_ids=[primeira["id"]],
    )

    concluir_primeira = await cliente.patch(
        f"/api/tasks/{primeira['id']}",
        json={"status": "CONCLUIDA", "outcome": "Feito."},
        headers=cabecalho(token_analista),
    )
    assert concluir_primeira.status_code == 200, concluir_primeira.text

    resposta = await cliente.patch(
        f"/api/tasks/{segunda['id']}",
        json={"status": "CONCLUIDA", "outcome": "Agora pode."},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 200, resposta.text


async def test_tarefa_sem_alteracoes_e_recusada(cliente, token_analista):
    """Um PATCH vazio não deve gerar um registo de auditoria sem conteúdo."""
    incidente = await _criar_incidente(cliente, token_analista)
    tarefa = await _criar_tarefa(cliente, token_analista, incidente)

    resposta = await cliente.patch(
        f"/api/tasks/{tarefa['id']}", json={}, headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 422, resposta.text
    assert resposta.json()["erro"]["codigo"] == "SEM_ALTERACOES"


async def test_listagem_filtra_por_incidente(cliente, token_analista):
    primeiro = await _criar_incidente(cliente, token_analista)
    segundo = await _criar_incidente(cliente, token_analista)
    await _criar_tarefa(cliente, token_analista, primeiro, title="Do primeiro")
    await _criar_tarefa(cliente, token_analista, segundo, title="Do segundo")

    resposta = await cliente.get(
        f"/api/tasks?incident_id={primeiro}", headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 200, resposta.text
    titulos = [t["title"] for t in resposta.json()["itens"]]
    assert titulos == ["Do primeiro"]
