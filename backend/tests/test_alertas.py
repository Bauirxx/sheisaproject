"""Decisões sobre um alerta: triar, promover, ligar (`api/v1/alerts.py`).

O ciclo de vida do alerta está declarado num só sítio, `ALERT_TRANSITIONS`, e a
rota de triagem cumpria-o. As outras duas portas de saída de um alerta não:

* **A triagem marcava PROMOVIDO ou CORRELACIONADO sem incidente nenhum.** São
  transições válidas do ciclo de vida, mas só as rotas de promoção e de ligação
  criam o incidente ou a ligação que lhes dá sentido. A interface escondia-as;
  a API aceitava-as, e o alerta ficava "promovido" sem ter originado nada.
* **Promover e ligar ignoravam o ciclo de vida.** Um alerta DESCARTADO era
  promovido directamente — apagando do histórico a decisão de descarte que o
  motor usa para estimar o ruído da regra — e um alerta PROMOVIDO podia ser
  religado a outro incidente, saindo do que ele próprio originou.
* **Ligava-se um alerta a um incidente ENCERRADO.** O motor de correlação recusa-o
  ("reescreveria um registo já concluído"); a ligação manual não.
* **A confiança indicada na promoção era ignorada.** O esquema aceita
  `confidence`, a rota não a passava, e o incidente ficava sempre com MEDIA.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.core.enums import AlertStatus, IncidentStatus, Severity
from app.models.incident import Incident
from app.models.system import AuditLog
from tests.conftest import cabecalho
from tests.test_recomendacoes import _alerta, _incidente


async def _triar(cliente, token, alerta, estado, **extra):
    return await cliente.post(
        f"/api/alerts/{alerta.id}/triage",
        json={"status": estado, **extra}, headers=cabecalho(token),
    )


async def _promover(cliente, token, alerta, **extra):
    return await cliente.post(
        f"/api/alerts/{alerta.id}/promote",
        json={"title": "Promovido para investigar", "rationale": "Teste.", **extra},
        headers=cabecalho(token),
    )


async def _ligar(cliente, token, alerta, incidente):
    return await cliente.post(
        f"/api/alerts/{alerta.id}/link",
        json={"incident_id": str(incidente.id), "rationale": "Mesma actividade."},
        headers=cabecalho(token),
    )


async def _estado(sessao, alerta) -> AlertStatus:
    await sessao.refresh(alerta)
    return alerta.status


# ---------------------------------------------------------------- triagem
async def test_a_triagem_nao_promove_nem_correlaciona_sem_incidente(
    cliente, sessao, token_analista
):
    """Regressão: `/triage` deixava o alerta PROMOVIDO sem ter originado nada."""
    alerta = await _alerta(sessao)

    for estado in ("PROMOVIDO", "CORRELACIONADO"):
        resposta = await _triar(cliente, token_analista, alerta, estado)
        assert resposta.status_code == 422, (estado, resposta.text)
        assert resposta.json()["erro"]["codigo"] == "ESTADO_EXIGE_INCIDENTE"

    assert await _estado(sessao, alerta) is AlertStatus.NOVO


async def test_transicao_fora_do_ciclo_de_vida_e_recusada_com_as_permitidas(
    cliente, sessao, token_analista
):
    alerta = await _alerta(sessao, estado=AlertStatus.DESCARTADO)

    resposta = await _triar(cliente, token_analista, alerta, "FALSO_POSITIVO")

    assert resposta.status_code == 409, resposta.text
    assert "EM_TRIAGEM" in str(resposta.json()["erro"])


async def test_marcar_como_duplicado_exige_um_original_que_nao_seja_ele_proprio(
    cliente, sessao, token_analista
):
    original = await _alerta(sessao, titulo="Original")
    copia = await _alerta(sessao, titulo="Cópia")

    sem_original = await _triar(cliente, token_analista, copia, "DUPLICADO")
    de_si_proprio = await _triar(cliente, token_analista, copia, "DUPLICADO",
                                 duplicate_of_id=str(copia.id))
    certo = await _triar(cliente, token_analista, copia, "DUPLICADO",
                         duplicate_of_id=str(original.id), note="Mesmo evento.")

    assert sem_original.json()["erro"]["codigo"] == "ORIGINAL_OBRIGATORIO"
    assert de_si_proprio.status_code == 422
    assert certo.status_code == 200, certo.text
    await sessao.refresh(copia)
    assert (copia.status, copia.duplicate_of_id, copia.triage_note) == (
        AlertStatus.DUPLICADO, original.id, "Mesmo evento."
    )


# --------------------------------------------------------------- promoção
async def test_a_confianca_indicada_na_promocao_chega_ao_incidente(
    cliente, sessao, token_analista
):
    """Regressão: o incidente ficava sempre com confiança MEDIA."""
    alerta = await _alerta(sessao)

    resposta = await _promover(cliente, token_analista, alerta, confidence="ALTA")

    assert resposta.status_code == 201, resposta.text
    assert resposta.json()["confidence"] == "ALTA"


async def test_alerta_descartado_tem_de_ser_reaberto_antes_de_promover(
    cliente, sessao, token_analista
):
    """Regressão: a promoção directa apagava a decisão de descarte."""
    alerta = await _alerta(sessao, estado=AlertStatus.DESCARTADO)

    directa = await _promover(cliente, token_analista, alerta)
    assert directa.status_code == 409, directa.text
    assert await _estado(sessao, alerta) is AlertStatus.DESCARTADO

    assert (await _triar(cliente, token_analista, alerta, "EM_TRIAGEM")).status_code == 200
    assert (await _promover(cliente, token_analista, alerta)).status_code == 201


async def test_promover_duas_vezes_e_recusado(cliente, sessao, token_analista):
    alerta = await _alerta(sessao)
    assert (await _promover(cliente, token_analista, alerta)).status_code == 201

    segunda = await _promover(cliente, token_analista, alerta)

    assert segunda.status_code == 409


# ---------------------------------------------------------------- ligação
async def test_ligar_eleva_a_severidade_do_incidente_e_fica_auditado(
    cliente, sessao, token_analista
):
    alerta = await _alerta(sessao, severidade=Severity.CRITICA)
    incidente = await _incidente(sessao, severidade=Severity.MEDIA)

    resposta = await _ligar(cliente, token_analista, alerta, incidente)

    assert resposta.status_code == 200, resposta.text
    await sessao.refresh(incidente)
    assert incidente.severity is Severity.CRITICA
    assert await _estado(sessao, alerta) is AlertStatus.CORRELACIONADO
    entrada = (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "LIGAR_ALERTA", AuditLog.resource_id == incidente.id
            )
        )
    ).scalar_one()
    assert alerta.reference in entrada.description


async def test_alerta_promovido_nao_e_religado_a_outro_incidente(
    cliente, sessao, token_analista
):
    """Regressão: o alerta saía do incidente que ele próprio originou."""
    alerta = await _alerta(sessao)
    originado = (await _promover(cliente, token_analista, alerta)).json()
    outro = await _incidente(sessao)

    resposta = await _ligar(cliente, token_analista, alerta, outro)

    assert resposta.status_code == 409, resposta.text
    await sessao.refresh(alerta)
    assert str(alerta.incident_id) == originado["id"]


async def test_nao_se_liga_um_alerta_a_um_incidente_encerrado(
    cliente, sessao, token_analista
):
    """Regressão: o motor recusava-o; a ligação manual reescrevia o registo concluído."""
    alerta = await _alerta(sessao)
    encerrado = await _incidente(sessao, estado=IncidentStatus.ENCERRADO)

    resposta = await _ligar(cliente, token_analista, alerta, encerrado)

    assert resposta.status_code == 409, resposta.text
    assert await _estado(sessao, alerta) is AlertStatus.NOVO
    await sessao.refresh(encerrado)
    assert encerrado.status is IncidentStatus.ENCERRADO


# ---------------------------------------------------------- consulta e pontuação
async def test_eventos_e_detalhe_de_alerta_inexistente_dao_404(cliente, token_analista):
    for rota in (f"/api/alerts/{uuid.uuid4()}", f"/api/alerts/{uuid.uuid4()}/events"):
        assert (await cliente.get(rota, headers=cabecalho(token_analista))).status_code == 404


async def test_filtrar_pelos_alertas_de_um_incidente(cliente, sessao, token_analista):
    alerta = await _alerta(sessao)
    solto = await _alerta(sessao, titulo="Alerta solto")
    incidente = (await _promover(cliente, token_analista, alerta)).json()

    deste = await cliente.get(
        f"/api/alerts?incidente_id={incidente['id']}", headers=cabecalho(token_analista)
    )
    sem = await cliente.get("/api/alerts?sem_incidente=true", headers=cabecalho(token_analista))

    assert [a["id"] for a in deste.json()["itens"]] == [str(alerta.id)]
    ids_sem = {a["id"] for a in sem.json()["itens"]}
    assert str(solto.id) in ids_sem and str(alerta.id) not in ids_sem


async def test_incidente_da_promocao_existe_com_o_alerta_como_origem(
    cliente, sessao, token_analista
):
    alerta = await _alerta(sessao, severidade=Severity.ALTA)

    corpo = (await _promover(cliente, token_analista, alerta)).json()

    incidente = await sessao.get(Incident, uuid.UUID(corpo["id"]))
    assert incidente.severity is Severity.ALTA
    assert incidente.detected_at == alerta.first_event_at
