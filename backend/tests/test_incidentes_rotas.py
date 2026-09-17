"""Rotas de incidentes ainda sem teste: edição, comentários, observações,
relações, técnicas e filtros (`api/v1/incidents.py`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.enums import Confidence
from app.models.catalog import MitreTechnique
from app.models.incident import IncidentTechnique
from app.models.system import AuditLog
from tests.conftest import cabecalho


async def _incidente(cliente, token, titulo="Incidente das rotas", **campos) -> dict:
    corpo = {"title": titulo, "description": "x", "category": "INTRUSAO",
             "severity": "ALTA", **campos}
    resposta = await cliente.post("/api/incidents", json=corpo, headers=cabecalho(token))
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _indicador(cliente, token, valor="203.0.113.170") -> dict:
    resposta = await cliente.post(
        "/api/iocs", json={"ioc_type": "IP", "value": valor}, headers=cabecalho(token)
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


# ------------------------------------------------------------------ edição
async def test_editar_regista_o_antes_e_o_depois_e_recusa_edicao_sem_efeito(
    cliente, sessao, token_analista
):
    incidente = await _incidente(cliente, token_analista)
    rota = f"/api/incidents/{incidente['id']}"

    editado = await cliente.patch(rota, json={"severity": "CRITICA"},
                                  headers=cabecalho(token_analista))
    repetido = await cliente.patch(rota, json={"severity": "CRITICA"},
                                   headers=cabecalho(token_analista))

    assert editado.status_code == 200, editado.text
    assert editado.json()["severity"] == "CRITICA"
    assert repetido.status_code == 422
    assert repetido.json()["erro"]["codigo"] == "SEM_ALTERACOES"
    entrada = (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "EDITAR_INCIDENTE",
                AuditLog.resource_id == uuid.UUID(incidente["id"]),
            )
        )
    ).scalar_one()
    assert (entrada.old_value["severity"], entrada.new_value["severity"]) == ("ALTA", "CRITICA")


# ------------------------------------------------------------- comentários
async def test_comentarios_por_ordem_de_escrita(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    for texto in ("Primeira nota.", "Segunda nota."):
        resposta = await cliente.post(
            f"/api/incidents/{incidente['id']}/comments", json={"body": texto},
            headers=cabecalho(token_analista),
        )
        assert resposta.status_code == 201, resposta.text

    lista = await cliente.get(
        f"/api/incidents/{incidente['id']}/comments", headers=cabecalho(token_analista)
    )
    em_falta = await cliente.get(
        f"/api/incidents/{uuid.uuid4()}/comments", headers=cabecalho(token_analista)
    )

    assert [c["body"] for c in lista.json()] == ["Primeira nota.", "Segunda nota."]
    assert em_falta.status_code == 404


# ------------------------------------------------------------ observações
async def test_observacao_com_indicador_ou_activo_inexistente_da_404(
    cliente, token_analista
):
    """Regressão: um activo inexistente chegava à base de dados e dava 500."""
    incidente = await _incidente(cliente, token_analista)
    indicador = await _indicador(cliente, token_analista)
    rota = f"/api/incidents/{incidente['id']}/observations"

    sem_indicador = await cliente.post(
        rota, json={"ioc_id": str(uuid.uuid4())}, headers=cabecalho(token_analista)
    )
    sem_activo = await cliente.post(
        rota, json={"ioc_id": indicador["id"], "asset_id": str(uuid.uuid4())},
        headers=cabecalho(token_analista),
    )

    assert sem_indicador.status_code == 404, sem_indicador.text
    assert sem_activo.status_code == 404, sem_activo.text


async def test_observacao_manual_e_listada_com_o_seu_papel(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    indicador = await _indicador(cliente, token_analista)
    await cliente.post(
        f"/api/incidents/{incidente['id']}/observations",
        json={"ioc_id": indicador["id"], "role": "DESTINO", "context": "Tráfego de saída."},
        headers=cabecalho(token_analista),
    )

    lista = (
        await cliente.get(
            f"/api/incidents/{incidente['id']}/observations", headers=cabecalho(token_analista)
        )
    ).json()

    assert [(o["role"], o["is_automatic"], o["context"]) for o in lista] == [
        ("DESTINO", False, "Tráfego de saída.")
    ]


# --------------------------------------------------------------- relações
async def test_relacoes_vistas_dos_dois_lados(cliente, token_analista):
    origem = await _incidente(cliente, token_analista, "Origem")
    destino = await _incidente(cliente, token_analista, "Destino")
    corpo = {"target_incident_id": destino["id"], "relation_type": "CAUSADO_POR",
             "rationale": "A intrusão levou à exfiltração."}

    criada = await cliente.post(f"/api/incidents/{origem['id']}/relations", json=corpo,
                                headers=cabecalho(token_analista))
    repetida = await cliente.post(f"/api/incidents/{origem['id']}/relations", json=corpo,
                                  headers=cabecalho(token_analista))
    propria = await cliente.post(
        f"/api/incidents/{origem['id']}/relations",
        json={**corpo, "target_incident_id": origem["id"]}, headers=cabecalho(token_analista),
    )
    assert (criada.status_code, repetida.status_code, propria.status_code) == (201, 409, 422)

    async def relacoes(incidente):
        resposta = await cliente.get(
            f"/api/incidents/{incidente['id']}/relations", headers=cabecalho(token_analista)
        )
        return [(r["direction"], r["incident_reference"]) for r in resposta.json()]

    assert await relacoes(origem) == [("saida", destino["reference"])]
    assert await relacoes(destino) == [("entrada", origem["reference"])]


# ---------------------------------------------------------------- técnicas
async def test_confirmar_uma_tecnica_inferida_torna_a_afirmada_e_pode_ser_removida(
    cliente, sessao, token_analista
):
    tecnica = MitreTechnique(technique_id="T1021", name="Remote Services", tactic_shortnames=[])
    sessao.add(tecnica)
    await sessao.flush()
    incidente = await _incidente(cliente, token_analista)
    sessao.add(IncidentTechnique(
        incident_id=uuid.UUID(incidente["id"]), technique_id=tecnica.id, is_asserted=False,
        confidence=Confidence.BAIXA, rationale="Inferida pelo motor.", evidence_refs={},
    ))
    await sessao.flush()
    rota = f"/api/incidents/{incidente['id']}/techniques"

    confirmada = await cliente.post(
        rota, json={"technique_id": "T1021", "confidence": "ALTA", "rationale": "Confirmada."},
        headers=cabecalho(token_analista),
    )
    inexistente = await cliente.post(rota, json={"technique_id": "T9999"},
                                     headers=cabecalho(token_analista))

    assert confirmada.status_code == 201, confirmada.text
    assert (confirmada.json()["is_asserted"], confirmada.json()["confidence"]) == (True, "ALTA")
    assert inexistente.status_code == 404

    removida = await cliente.delete(f"{rota}/T1021", headers=cabecalho(token_analista))
    outra_vez = await cliente.delete(f"{rota}/T1021", headers=cabecalho(token_analista))
    assert (removida.status_code, outra_vez.status_code) == (200, 404)


# ----------------------------------------------------------------- filtros
async def test_filtros_por_prioridade_responsavel_e_intervalo(
    cliente, token_analista, semente
):
    analista = semente["utilizadores"]["analista"]
    critico = await _incidente(cliente, token_analista, "Crítico atribuído", severity="CRITICA")
    await cliente.post(
        f"/api/incidents/{critico['id']}/assign", json={"assignee_id": str(analista)},
        headers=cabecalho(token_analista),
    )
    baixo = await _incidente(cliente, token_analista, "Baixo sem responsável", severity="BAIXA")

    async def referencias(consulta):
        resposta = await cliente.get(f"/api/incidents?{consulta}&size=100",
                                     headers=cabecalho(token_analista))
        assert resposta.status_code == 200, resposta.text
        return {i["reference"] for i in resposta.json()["itens"]}

    assert critico["reference"] in await referencias(f"prioridade={critico['priority']}")
    assert baixo["reference"] not in await referencias(f"prioridade={critico['priority']}")
    assert await referencias(f"responsavel_id={analista}") >= {critico["reference"]}
    assert baixo["reference"] not in await referencias(f"responsavel_id={analista}")
    futuro = (datetime.now(UTC) + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    assert critico["reference"] not in await referencias(f"desde={futuro}")
    assert critico["reference"] in await referencias(f"ate={futuro}&categoria=INTRUSAO")


# ----------------------------------------------- referências inexistentes
# O mesmo defeito da observação com activo inexistente repetia-se noutras portas:
# um identificador de utilizador, equipa ou activo que não existe chegava à base
# de dados e dava 500 — ou, nos activos de um incidente novo, era ignorado em
# silêncio e o incidente nascia sem o activo que o analista indicou.
FANTASMA = "00000000-0000-4000-8000-00000000dead"


async def _pedido_com_referencia_inexistente(cliente, token, caso):
    incidente = await _incidente(cliente, token, f"Base para {caso}")
    tarefa = await cliente.post(
        f"/api/tasks?incident_id={incidente['id']}", json={"title": "Tarefa base"},
        headers=cabecalho(token),
    )
    base = {"title": "Incidente com referência", "description": "x",
            "category": "INTRUSAO", "severity": "ALTA"}
    pedidos = {
        "incidente-responsavel": ("post", "/api/incidents", {**base, "assignee_id": FANTASMA}),
        "incidente-equipa": ("post", "/api/incidents", {**base, "team_id": FANTASMA}),
        "incidente-activos": ("post", "/api/incidents", {**base, "asset_ids": [FANTASMA]}),
        "atribuir-responsavel": ("post", f"/api/incidents/{incidente['id']}/assign",
                                 {"assignee_id": FANTASMA}),
        "atribuir-equipa": ("post", f"/api/incidents/{incidente['id']}/assign",
                            {"team_id": FANTASMA}),
        "tarefa-nova": ("post", f"/api/tasks?incident_id={incidente['id']}",
                        {"title": "Tarefa atribuída", "assignee_id": FANTASMA}),
        "tarefa-editada": ("patch", f"/api/tasks/{tarefa.json()['id']}",
                           {"assignee_id": FANTASMA}),
    }
    metodo, rota, corpo = pedidos[caso]
    return await getattr(cliente, metodo)(rota, json=corpo, headers=cabecalho(token))


@pytest.mark.parametrize(
    "caso",
    ["incidente-responsavel", "incidente-equipa", "incidente-activos",
     "atribuir-responsavel", "atribuir-equipa", "tarefa-nova", "tarefa-editada"],
)
async def test_referencia_inexistente_da_404_em_vez_de_500_ou_silencio(
    cliente, token_admin, caso
):
    resposta = await _pedido_com_referencia_inexistente(cliente, token_admin, caso)

    assert resposta.status_code == 404, resposta.text
    assert FANTASMA in resposta.text
