"""Rotas de recomendações: fila, detalhe e geração (`api/v1/recommendations.py`).

O motor e a decisão já estão cobertos em `test_recomendacoes.py`. Aqui fica o que
o analista usa para chegar às recomendações, e dois defeitos encontrados:

* **O filtro `alvo` aceitava qualquer texto.** Os valores guardados são `alert` e
  `incident`; um cliente que pedisse `alvo=incidente` recebia uma fila vazia e
  concluiria que não havia nada por decidir. É a classe do defeito 14 — um filtro
  que parece filtrar. A interface envia os valores certos; a API é que não
  recusava os errados.
* **Recalcular as recomendações de um alerta ou de um incidente não ficava
  auditado**, ao contrário do recálculo global. Ambos criam e retiram
  recomendações, e uma recomendação retirada desaparece da fila de quem decide.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.core.enums import IncidentStatus
from app.intelligence import recommendations as motor
from app.models.system import AuditLog
from app.services import recommendation_service as servico
from tests.conftest import cabecalho
from tests.test_recomendacoes import _alerta, _incidente


async def _fila(cliente, token, consulta="") -> dict:
    resposta = await cliente.get(f"/api/recommendations?{consulta}", headers=cabecalho(token))
    assert resposta.status_code == 200, resposta.text
    return resposta.json()


async def _preparar(sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    incidente = await _incidente(sessao, estado=IncidentStatus.NOVO)
    await servico.sincronizar_alerta(sessao, alerta)
    await servico.sincronizar_incidente(sessao, incidente)
    await sessao.flush()
    return alerta, incidente


# ------------------------------------------------------------------- fila
async def test_os_filtros_da_fila_restringem_o_que_mostram(cliente, sessao, token_analista):
    alerta, incidente = await _preparar(sessao)

    de_alertas = await _fila(cliente, token_analista, "alvo=alert")
    de_incidentes = await _fila(cliente, token_analista, "alvo=incident")
    assert de_alertas["total"] >= 1 and de_incidentes["total"] >= 1
    assert {i["target_type"] for i in de_alertas["itens"]} == {"alert"}
    assert {i["target_type"] for i in de_incidentes["itens"]} == {"incident"}

    deste = await _fila(cliente, token_analista, f"alvo_id={incidente.id}")
    assert deste["total"] >= 1
    assert {i["target_id"] for i in deste["itens"]} == {str(incidente.id)}

    tipo = de_incidentes["itens"][0]["kind"]
    assert {i["kind"] for i in (await _fila(cliente, token_analista, f"tipo={tipo}"))["itens"]} == {tipo}

    maxima = max(i["confidence"] for i in (await _fila(cliente, token_analista))["itens"])
    acima = await _fila(cliente, token_analista, f"confianca_minima={maxima}")
    assert acima["total"] >= 1
    assert all(i["confidence"] >= maxima for i in acima["itens"])


async def test_alvo_desconhecido_e_recusado_em_vez_de_devolver_vazio(cliente, token_analista):
    """Regressão: `alvo=incidente` devolvia uma fila vazia sem aviso."""
    resposta = await cliente.get(
        "/api/recommendations?alvo=incidente", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 422, resposta.text


async def test_detalhe_de_uma_recomendacao(cliente, sessao, token_analista):
    await _preparar(sessao)
    primeira = (await _fila(cliente, token_analista))["itens"][0]

    detalhe = await cliente.get(
        f"/api/recommendations/{primeira['id']}", headers=cabecalho(token_analista)
    )
    em_falta = await cliente.get(
        f"/api/recommendations/{uuid.uuid4()}", headers=cabecalho(token_analista)
    )

    assert detalhe.status_code == 200
    assert detalhe.json()["explanation"] == primeira["explanation"]
    assert em_falta.status_code == 404


# ---------------------------------------------------------------- geração
async def test_recalcular_tudo_fica_auditado_com_o_resumo(cliente, sessao, token_analista):
    await _preparar(sessao)

    resposta = await cliente.post("/api/recommendations/generate", headers=cabecalho(token_analista))

    assert resposta.status_code == 200, resposta.text
    resumo = resposta.json()
    assert (resumo["motor"], resumo["versao"]) == (motor.ENGINE_NAME, motor.ENGINE_VERSION)
    entrada = (
        await sessao.execute(select(AuditLog).where(AuditLog.action == "GERAR_RECOMENDACOES"))
    ).scalar_one()
    assert entrada.new_value == resumo


async def test_recalcular_um_alvo_fica_auditado(cliente, sessao, token_analista):
    """Regressão: só o recálculo global deixava rasto na auditoria."""
    alerta, incidente = await _preparar(sessao)

    for rota, alvo in (
        (f"/api/recommendations/alerts/{alerta.id}/generate", alerta),
        (f"/api/recommendations/incidents/{incidente.id}/generate", incidente),
    ):
        resposta = await cliente.post(rota, headers=cabecalho(token_analista))
        assert resposta.status_code == 200, resposta.text
        entrada = (
            await sessao.execute(
                select(AuditLog).where(
                    AuditLog.action == "GERAR_RECOMENDACOES", AuditLog.resource_id == alvo.id
                )
            )
        ).scalar_one_or_none()
        assert entrada is not None, f"{rota} não ficou auditada"
        assert alvo.reference in entrada.description


async def test_recalcular_um_alvo_inexistente_da_404(cliente, token_analista):
    for rota in (
        f"/api/recommendations/alerts/{uuid.uuid4()}/generate",
        f"/api/recommendations/incidents/{uuid.uuid4()}/generate",
    ):
        resposta = await cliente.post(rota, headers=cabecalho(token_analista))
        assert resposta.status_code == 404, rota
