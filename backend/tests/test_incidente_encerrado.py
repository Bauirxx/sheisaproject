"""Um incidente ENCERRADO está trancado — em **todas** as portas.

`test_incidentes.py` fixa a regra nas portas que a tinham: campos, tarefas,
observações e evidências. Estes testes vão às outras, encontradas ao aplicar a
armadilha 5.15 (uma regra aplicada numa porta e esquecida nas outras) ao código
que entrou depois:

* associar e remover técnicas MITRE;
* propor uma acção de resposta;
* correr um playbook (que cria tarefas, notas e acções);
* aceitar ou ligar uma comunicação externa ao incidente;
* aplicar uma recomendação que altera campos ou associa técnicas.

E dois controlos, para a guarda não ir além do que deve: **comentar** continua
permitido (é nota de auditoria posterior) e **relacionar** também — é o próprio
caminho que a mensagem de erro indica para retomar o trabalho.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.enums import Confidence, RecommendationKind
from app.models.catalog import MitreTechnique
from app.models.incident import Incident, IncidentTechnique
from tests.conftest import cabecalho
from tests.test_comunicacoes import _submeter
from tests.test_recomendacoes_aplicacao import _recomendacao


async def _transitar(cliente, token, incidente_id, estado, **extra):
    return await cliente.post(
        f"/api/incidents/{incidente_id}/transition",
        json={"status": estado, **extra}, headers=cabecalho(token),
    )


async def _incidente(cliente, token, titulo="Incidente a encerrar") -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": titulo, "description": "x", "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _encerrar(cliente, token_analista, token_admin, incidente_id) -> None:
    await _transitar(cliente, token_analista, incidente_id, "TRIAGEM")
    await _transitar(cliente, token_analista, incidente_id, "INVESTIGACAO")
    await _transitar(cliente, token_analista, incidente_id, "RESOLVIDO",
                     resolution_summary="Contido e resolvido.")
    fechar = await _transitar(cliente, token_admin, incidente_id, "ENCERRADO")
    assert fechar.status_code == 200, fechar.text


async def _tecnica(sessao) -> MitreTechnique:
    tecnica = MitreTechnique(technique_id="T1110", name="Brute Force", tactic_shortnames=[])
    sessao.add(tecnica)
    await sessao.flush()
    return tecnica


async def _comunicacao_aceite(cliente, sessao, token_analista, token_admin) -> dict:
    """Uma comunicação já aceite noutro incidente, para depois tentar ligá-la."""
    outro = await _incidente(cliente, token_analista, "Incidente da comunicação")
    relato = await _submeter(cliente)
    lista = await cliente.get("/api/reports-inbox", headers=cabecalho(token_analista))
    interno = next(
        r for r in lista.json()["itens"] if r["reference"] == relato["referencia"]
    )
    aceitar = await cliente.post(
        f"/api/reports-inbox/{interno['id']}/accept",
        json={"incident_id": outro["id"], "nota": "Relevante e confirmada."},
        headers=cabecalho(token_analista),
    )
    assert aceitar.status_code == 200, aceitar.text
    return interno


def _trancado(resposta) -> None:
    assert resposta.status_code == 409, resposta.text
    assert resposta.json()["erro"]["codigo"] == "INCIDENTE_ENCERRADO", resposta.text


# ------------------------------------------------------- portas esquecidas
async def test_tecnicas_nao_se_associam_nem_removem_num_incidente_encerrado(
    cliente, sessao, token_analista, token_admin
):
    tecnica = await _tecnica(sessao)
    incidente = await _incidente(cliente, token_analista)
    sessao.add(IncidentTechnique(
        incident_id=uuid.UUID(incidente["id"]), technique_id=tecnica.id, is_asserted=True,
        confidence=Confidence.ALTA, rationale="Antes de encerrar.", evidence_refs={},
    ))
    await sessao.flush()
    await _encerrar(cliente, token_analista, token_admin, incidente["id"])
    rota = f"/api/incidents/{incidente['id']}/techniques"

    _trancado(await cliente.post(rota, json={"technique_id": "T1110"},
                                 headers=cabecalho(token_admin)))
    _trancado(await cliente.delete(f"{rota}/T1110", headers=cabecalho(token_admin)))


async def test_nao_se_propoe_uma_accao_num_incidente_encerrado(
    cliente, token_analista, token_admin
):
    incidente = await _incidente(cliente, token_analista)
    await _encerrar(cliente, token_analista, token_admin, incidente["id"])

    resposta = await cliente.post(
        "/api/actions",
        json={"incident_id": incidente["id"], "action_kind": "ISOLAR_ACTIVO",
              "title": "Isolar depois de encerrar", "rationale": "Justificação.",
              "target": {"agent_id": "001"}},
        headers=cabecalho(token_analista),
    )

    _trancado(resposta)


async def test_nao_se_corre_um_playbook_num_incidente_encerrado(
    cliente, token_analista, token_admin
):
    """Um playbook cria tarefas, notas e acções: é conteúdo."""
    incidente = await _incidente(cliente, token_analista)
    playbook = (
        await cliente.post(
            "/api/playbooks",
            json={"name": "Playbook depois do fecho", "description": "x", "is_enabled": True,
                  "steps": [{"ordering": 1, "name": "Nota", "step_type": "REGISTAR_NOTA",
                             "parameters": {"texto": "Nota do playbook."}}]},
            headers=cabecalho(token_admin),
        )
    ).json()
    await _encerrar(cliente, token_analista, token_admin, incidente["id"])

    resposta = await cliente.post(
        f"/api/playbooks/{playbook['id']}/run",
        json={"incident_id": incidente["id"]}, headers=cabecalho(token_analista),
    )

    _trancado(resposta)


async def test_uma_comunicacao_nao_se_liga_a_um_incidente_encerrado(
    cliente, sessao, token_analista, token_admin
):
    """A comunicação é matéria nova: ligá-la reescreveria um registo concluído."""
    encerrado = await _incidente(cliente, token_analista, "Encerrado para comunicações")
    await _encerrar(cliente, token_analista, token_admin, encerrado["id"])
    aceite = await _comunicacao_aceite(cliente, sessao, token_analista, token_admin)
    nova = await _submeter(cliente, subject="Outra comunicação para aceitar")
    lista = await cliente.get("/api/reports-inbox", headers=cabecalho(token_analista))
    por_aceitar = next(
        r for r in lista.json()["itens"] if r["reference"] == nova["referencia"]
    )

    _trancado(await cliente.post(
        f"/api/reports-inbox/{aceite['id']}/incidents",
        json={"incident_id": encerrado["id"]}, headers=cabecalho(token_analista),
    ))
    _trancado(await cliente.post(
        f"/api/reports-inbox/{por_aceitar['id']}/accept",
        json={"incident_id": encerrado["id"], "nota": "Tentativa de aceitar."},
        headers=cabecalho(token_analista),
    ))


@pytest.mark.parametrize(
    "alteracao",
    [
        {"operacao": "ALTERAR_CAMPOS",
         "alteracoes": [{"campo": "severity", "de": "ALTA", "para": "CRITICA"}]},
        {"operacao": "ASSOCIAR_TECNICAS", "tecnicas": ["T1110"]},
    ],
    ids=["campos", "tecnicas"],
)
async def test_uma_recomendacao_nao_se_aplica_a_um_incidente_encerrado(
    cliente, sessao, token_analista, token_admin, alteracao
):
    await _tecnica(sessao)
    criado = await _incidente(cliente, token_analista)
    await _encerrar(cliente, token_analista, token_admin, criado["id"])
    incidente = await sessao.get(Incident, uuid.UUID(criado["id"]))
    rec = await _recomendacao(sessao, incidente, alteracao,
                              tipo=RecommendationKind.CLASSIFICACAO)

    resposta = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": True, "note": "Aceite depois do fecho."},
        headers=cabecalho(token_analista),
    )

    _trancado(resposta)


# ------------------------------------------------------------- controlos
async def test_comentar_e_relacionar_continuam_permitidos(
    cliente, token_analista, token_admin
):
    encerrado = await _incidente(cliente, token_analista, "Encerrado mas comentável")
    outro = await _incidente(cliente, token_analista, "Incidente que o sucede")
    await _encerrar(cliente, token_analista, token_admin, encerrado["id"])

    comentario = await cliente.post(
        f"/api/incidents/{encerrado['id']}/comments",
        json={"body": "Nota posterior ao encerramento."}, headers=cabecalho(token_analista),
    )
    relacao = await cliente.post(
        f"/api/incidents/{outro['id']}/relations",
        json={"target_incident_id": encerrado["id"], "relation_type": "CAUSADO_POR",
              "rationale": "Continuação do caso encerrado."},
        headers=cabecalho(token_analista),
    )

    assert comentario.status_code == 201, comentario.text
    assert relacao.status_code == 201, relacao.text


async def test_o_que_ja_existia_continua_consultavel(cliente, sessao, token_analista, token_admin):
    """Trancar é impedir alterações, não esconder o registo."""
    tecnica = await _tecnica(sessao)
    incidente = await _incidente(cliente, token_analista)
    sessao.add(IncidentTechnique(
        incident_id=uuid.UUID(incidente["id"]), technique_id=tecnica.id, is_asserted=True,
        confidence=Confidence.ALTA, rationale="Antes de encerrar.", evidence_refs={},
    ))
    await sessao.flush()
    await _encerrar(cliente, token_analista, token_admin, incidente["id"])

    detalhe = await cliente.get(f"/api/incidents/{incidente['id']}",
                                headers=cabecalho(token_analista))
    linha = await cliente.get(f"/api/incidents/{incidente['id']}/timeline",
                              headers=cabecalho(token_analista))

    assert detalhe.status_code == 200
    assert [t["technique"]["technique_id"] for t in detalhe.json()["techniques"]] == ["T1110"]
    assert linha.status_code == 200
    assert (
        await sessao.execute(
            select(IncidentTechnique).where(
                IncidentTechnique.incident_id == uuid.UUID(incidente["id"])
            )
        )
    ).scalar_one()
