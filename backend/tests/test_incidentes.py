"""Ciclo de vida do incidente (§7).

O ciclo de vida é um grafo configurável em `INCIDENT_TRANSITIONS`. Estes testes
verificam que o grafo é de facto respeitado — que nenhuma transição fora dele
passa — e que os marcos temporais que alimentam o MTTA e o MTTR são preenchidos
onde têm de ser, porque é deles que os relatórios dependem.
"""

from __future__ import annotations

import pytest

from app.core.enums import INCIDENT_TRANSITIONS, IncidentStatus
from tests.conftest import cabecalho


async def _criar(cliente, token, **campos) -> dict:
    corpo = {
        "title": "Incidente criado no teste",
        "description": "Descrição.",
        "category": "TENTATIVA_INTRUSAO",
        "severity": "ALTA",
        **campos,
    }
    resposta = await cliente.post(
        "/api/incidents", json=corpo, headers=cabecalho(token)
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _transitar(cliente, token, incidente_id, estado, **extra) -> object:
    return await cliente.post(
        f"/api/incidents/{incidente_id}/transition",
        json={"status": estado, **extra},
        headers=cabecalho(token),
    )


async def test_criar_incidente_gera_referencia_legivel(cliente, token_analista):
    incidente = await _criar(cliente, token_analista)
    assert incidente["reference"].startswith("INC-")
    assert incidente["status"] == "NOVO"


async def test_transicao_valida_e_aceite(cliente, token_analista):
    incidente = await _criar(cliente, token_analista)
    resposta = await _transitar(
        cliente, token_analista, incidente["id"], "TRIAGEM", note="A triar."
    )
    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] == "TRIAGEM"


async def test_transicao_invalida_e_recusada_com_as_alternativas(
    cliente, token_analista
):
    """Um erro de transição tem de dizer o que *seria* possível.

    Recusar sem indicar as alternativas obrigaria o utilizador a adivinhar o
    grafo — e obrigaria o frontend a duplicá-lo.
    """
    incidente = await _criar(cliente, token_analista)
    resposta = await _transitar(
        cliente, token_analista, incidente["id"], "ERRADICACAO"
    )
    assert resposta.status_code == 409
    detalhes = resposta.json()["erro"]["detalhes"]
    assert detalhes["estado_actual"] == "NOVO"
    assert detalhes["estado_pedido"] == "ERRADICACAO"
    assert "TRIAGEM" in detalhes["transicoes_permitidas"]


async def test_o_incidente_anuncia_as_transicoes_permitidas(cliente, token_analista):
    """A API expõe o grafo para que o frontend não o reimplemente."""
    incidente = await _criar(cliente, token_analista)
    detalhe = await cliente.get(
        f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista)
    )
    permitidas = set(detalhe.json()["transicoes_permitidas"])
    assert permitidas == {
        e.value for e in INCIDENT_TRANSITIONS[IncidentStatus.NOVO]
    }


async def test_resolver_exige_resumo(cliente, token_analista):
    """Um incidente resolvido sem resumo não é auditável nem reutilizável."""
    incidente = await _criar(cliente, token_analista)
    await _transitar(cliente, token_analista, incidente["id"], "TRIAGEM")
    await _transitar(cliente, token_analista, incidente["id"], "INVESTIGACAO")

    sem_resumo = await _transitar(
        cliente, token_analista, incidente["id"], "RESOLVIDO"
    )
    assert sem_resumo.status_code == 422
    assert sem_resumo.json()["erro"]["codigo"] == "RESUMO_OBRIGATORIO"

    com_resumo = await _transitar(
        cliente, token_analista, incidente["id"], "RESOLVIDO",
        resolution_summary="Acesso bloqueado e credenciais rodadas.",
    )
    assert com_resumo.status_code == 200


async def test_falso_positivo_exige_motivo(cliente, token_analista):
    """Sem o motivo, o detector de falsos positivos não aprende nada (§36)."""
    incidente = await _criar(cliente, token_analista)

    sem_motivo = await _transitar(
        cliente, token_analista, incidente["id"], "FALSO_POSITIVO"
    )
    assert sem_motivo.status_code == 422
    assert sem_motivo.json()["erro"]["codigo"] == "MOTIVO_OBRIGATORIO"

    com_motivo = await _transitar(
        cliente, token_analista, incidente["id"], "FALSO_POSITIVO",
        false_positive_reason="Varrimento autorizado da equipa de infra-estrutura.",
    )
    assert com_motivo.status_code == 200


async def test_transicao_para_o_mesmo_estado_e_recusada(cliente, token_analista):
    incidente = await _criar(cliente, token_analista)
    resposta = await _transitar(cliente, token_analista, incidente["id"], "NOVO")
    assert resposta.status_code == 409


async def test_marcos_temporais_alimentam_as_metricas(cliente, token_analista):
    """MTTA e MTTR não são estimados: derivam de instantes efectivamente marcados."""
    incidente = await _criar(cliente, token_analista)
    assert incidente["acknowledged_at"] is None

    triado = (
        await _transitar(cliente, token_analista, incidente["id"], "TRIAGEM")
    ).json()
    assert triado["acknowledged_at"] is not None

    await _transitar(cliente, token_analista, incidente["id"], "INVESTIGACAO")
    contido = (
        await _transitar(cliente, token_analista, incidente["id"], "CONTENCAO")
    ).json()
    assert contido["contained_at"] is not None

    await _transitar(cliente, token_analista, incidente["id"], "ERRADICACAO")
    erradicado = await cliente.get(
        f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista)
    )
    assert erradicado.json()["eradicated_at"] is not None


async def test_o_marco_de_reconhecimento_nao_e_reescrito(cliente, token_analista):
    """Uma segunda passagem não apaga o primeiro reconhecimento."""
    incidente = await _criar(cliente, token_analista)
    primeiro = (
        await _transitar(cliente, token_analista, incidente["id"], "TRIAGEM")
    ).json()["acknowledged_at"]

    await _transitar(cliente, token_analista, incidente["id"], "ABERTO")
    segundo = (
        await _transitar(cliente, token_analista, incidente["id"], "TRIAGEM")
    ).json()["acknowledged_at"]

    assert primeiro == segundo


@pytest.mark.parametrize("estado", [e.value for e in IncidentStatus])
async def test_todo_o_estado_tem_entrada_no_grafo(estado):
    """Um estado sem entrada seria um beco sem saída silencioso."""
    assert IncidentStatus(estado) in INCIDENT_TRANSITIONS


async def test_analista_nao_encerra_incidentes(cliente, token_analista):
    """Encerrar é do investigador e do gestor — não da primeira linha."""
    incidente = await _criar(cliente, token_analista)
    await _transitar(cliente, token_analista, incidente["id"], "TRIAGEM")
    await _transitar(cliente, token_analista, incidente["id"], "INVESTIGACAO")
    await _transitar(
        cliente, token_analista, incidente["id"], "RESOLVIDO",
        resolution_summary="Resolvido.",
    )
    resposta = await _transitar(cliente, token_analista, incidente["id"], "ENCERRADO")
    assert resposta.status_code == 403


async def test_incidente_encerrado_fica_trancado(cliente, token_analista, token_admin):
    """ENCERRADO preserva o registo histórico: o conteúdo deixa de poder mudar.

    Campos, tarefas e evidências ficam trancados (incluindo eliminá-las). Só os
    comentários continuam — são notas de auditoria posteriores, não alteram o que
    aconteceu. ENCERRADO é terminal: não se reabre.
    """
    incidente = await _criar(cliente, token_analista)
    iid = incidente["id"]

    # Conteúdo criado ANTES de encerrar, para depois tentar alterá-lo e eliminá-lo.
    ev = await cliente.post(
        "/api/evidence",
        data={"incident_id": iid, "tipo": "LOG", "descricao": "Antes de encerrar"},
        files={"ficheiro": ("a.log", b"linha de log\n" * 5, "application/octet-stream")},
        headers=cabecalho(token_analista),
    )
    assert ev.status_code == 201, ev.text
    ev_id = ev.json()["id"]

    tarefa = await cliente.post(
        f"/api/tasks?incident_id={iid}",
        json={"title": "Tarefa antes de encerrar"},
        headers=cabecalho(token_analista),
    )
    assert tarefa.status_code == 201, tarefa.text
    tarefa_id = tarefa.json()["id"]

    # Encerrar (só admin/investigador têm incidents:close).
    await _transitar(cliente, token_analista, iid, "TRIAGEM")
    await _transitar(cliente, token_analista, iid, "INVESTIGACAO")
    await _transitar(
        cliente, token_analista, iid, "RESOLVIDO", resolution_summary="Feito."
    )
    fechar = await _transitar(cliente, token_admin, iid, "ENCERRADO")
    assert fechar.status_code == 200, fechar.text
    assert fechar.json()["status"] == "ENCERRADO"

    def _trancado(resp) -> None:
        assert resp.status_code == 409, resp.text
        assert resp.json()["erro"]["codigo"] == "INCIDENTE_ENCERRADO", resp.text

    # Editar campos.
    _trancado(await cliente.patch(
        f"/api/incidents/{iid}", json={"title": "Novo título"},
        headers=cabecalho(token_admin),
    ))
    # Criar tarefa.
    _trancado(await cliente.post(
        f"/api/tasks?incident_id={iid}",
        json={"title": "Tarefa nova"}, headers=cabecalho(token_admin),
    ))
    # Actualizar a tarefa que já existia.
    _trancado(await cliente.patch(
        f"/api/tasks/{tarefa_id}", json={"title": "Renomeada"},
        headers=cabecalho(token_admin),
    ))
    # Carregar nova evidência.
    _trancado(await cliente.post(
        "/api/evidence",
        data={"incident_id": iid, "tipo": "LOG", "descricao": "Depois"},
        files={"ficheiro": ("b.log", b"x\n", "application/octet-stream")},
        headers=cabecalho(token_admin),
    ))
    # Eliminar a evidência que já existia.
    _trancado(await cliente.delete(
        f"/api/evidence/{ev_id}", headers=cabecalho(token_admin),
    ))

    # Comentar CONTINUA permitido — nota de auditoria posterior ao encerramento.
    comentario = await cliente.post(
        f"/api/incidents/{iid}/comments",
        json={"body": "Nota registada após o encerramento."},
        headers=cabecalho(token_admin),
    )
    assert comentario.status_code == 201, comentario.text


async def test_atribuir_responsavel(cliente, token_analista, semente):
    incidente = await _criar(cliente, token_analista)
    alvo = str(semente["utilizadores"]["investigador"])

    resposta = await cliente.post(
        f"/api/incidents/{incidente['id']}/assign",
        json={"assignee_id": alvo},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["assignee"]["id"] == alvo
