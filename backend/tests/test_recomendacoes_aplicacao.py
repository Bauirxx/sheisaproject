"""Aplicação das recomendações aceites (`recommendation_service._aplicar`).

Dois defeitos:

* **Uma recomendação vencida podia ser aceite e aplicada.** A validade só era
  imposta pelo recálculo global; a fila e a decisão ignoravam-na. Uma proposta
  cujo fundamento já tinha caducado continuava na fila como PENDENTE e, aceite,
  alterava o alvo. É o defeito 47 das aprovações, noutra porta.
* **A triagem por recomendação não tinha a guarda da triagem à mão.** Uma
  proposta de mudar o alerta para PROMOVIDO ou CORRELACIONADO passaria, deixando
  um alerta "promovido" sem incidente — o defeito 34, noutra porta. O motor não
  gera hoje essa proposta; a regra não pode depender disso.

As recomendações dos casos que o motor não produz sozinho são gravadas aqui
directamente, com a forma exacta que o motor usa.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.enums import (
    AlertStatus,
    IncidentStatus,
    RecommendationKind,
    RecommendationStatus,
)
from app.models.catalog import MitreTechnique
from app.models.incident import Incident, IncidentTechnique
from app.models.intelligence import Recommendation
from app.models.response import PlaybookExecution
from app.models.telemetry import Alert
from tests.conftest import cabecalho
from tests.test_recomendacoes import _alerta, _incidente


async def _recomendacao(sessao, alvo, alteracao, *, tipo=RecommendationKind.TRIAGEM,
                        expira=None, evidencia=None) -> Recommendation:
    rec = Recommendation(
        kind=tipo, status=RecommendationStatus.PENDENTE,
        target_type="alert" if isinstance(alvo, Alert) else "incident", target_id=alvo.id,
        title="Proposta de teste", summary="Resumo.", explanation="Porque sim, com evidência.",
        confidence=70, factors={"teste": 70}, evidence_refs=evidencia or {},
        proposed_change=alteracao, expires_at=expira,
    )
    sessao.add(rec)
    await sessao.flush()
    return rec


async def _decidir(cliente, token, rec, aceitar=True):
    return await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": aceitar, "note": "Decisão de teste."},
        headers=cabecalho(token),
    )


# --------------------------------------------------------------- validade
async def test_recomendacao_vencida_nao_se_aplica(cliente, sessao, token_analista):
    """Regressão: aceite depois de vencida, alterava o alvo."""
    alerta = await _alerta(sessao)
    rec = await _recomendacao(
        sessao, alerta, {"operacao": "ALTERAR_ESTADO_ALERTA", "de": "NOVO", "para": "FALSO_POSITIVO"},
        expira=datetime.now(UTC) - timedelta(hours=1),
    )

    resposta = await _decidir(cliente, token_analista, rec)

    assert resposta.status_code == 409, resposta.text
    assert "expirou" in resposta.json()["erro"]["mensagem"]
    await sessao.refresh(rec)
    await sessao.refresh(alerta)
    assert rec.status is RecommendationStatus.EXPIRADA
    assert alerta.status is AlertStatus.NOVO


async def test_a_fila_nao_mostra_recomendacoes_vencidas(cliente, sessao, token_analista):
    """Regressão: continuavam PENDENTES até alguém recalcular tudo."""
    alerta = await _alerta(sessao)
    vencida = await _recomendacao(
        sessao, alerta, {"operacao": "ALTERAR_ESTADO_ALERTA", "de": "NOVO", "para": "FALSO_POSITIVO"},
        expira=datetime.now(UTC) - timedelta(minutes=5),
    )

    fila = (await cliente.get("/api/recommendations", headers=cabecalho(token_analista))).json()

    assert str(vencida.id) not in {r["id"] for r in fila["itens"]}


async def test_pedir_pendentes_a_mao_da_o_mesmo_que_a_omissao(
    cliente, sessao, token_analista
):
    """A regra não pode depender de o filtro ser omitido.

    A primeira correcção excluía as vencidas só quando `estado` não vinha no
    pedido. Passar `?estado=PENDENTE` à mão — que é o que a interface faz ao
    mostrar o filtro escolhido — voltava a trazê-las, pelo que a regra
    contornava-se sem intenção nenhuma.
    """
    alerta = await _alerta(sessao)
    # Tipos diferentes de propósito: `uq_recommendations_pendente_por_alvo`
    # impede duas propostas PENDENTES do mesmo tipo sobre o mesmo alvo, o que é
    # a regra que evita o motor empilhar duplicados.
    vencida = await _recomendacao(
        sessao, alerta, {"operacao": "ALTERAR_ESTADO_ALERTA", "de": "NOVO", "para": "FALSO_POSITIVO"},
        tipo=RecommendationKind.FALSO_POSITIVO,
        expira=datetime.now(UTC) - timedelta(minutes=5),
    )
    viva = await _recomendacao(
        sessao, alerta, {"operacao": "ALTERAR_ESTADO_ALERTA", "de": "NOVO", "para": "DESCARTADO"},
        tipo=RecommendationKind.TRIAGEM,
        expira=datetime.now(UTC) + timedelta(days=1),
    )

    fila = (
        await cliente.get(
            "/api/recommendations?estado=PENDENTE", headers=cabecalho(token_analista)
        )
    ).json()
    presentes = {r["id"] for r in fila["itens"]}

    assert str(vencida.id) not in presentes, "o filtro explícito trouxe uma vencida"
    assert str(viva.id) in presentes, (
        "excluiu uma proposta dentro da validade — o filtro está a cortar demasiado"
    )


# ------------------------------------------------------------- aplicadores
async def test_triagem_por_recomendacao_aplica_o_falso_positivo(cliente, sessao, token_analista):
    alerta = await _alerta(sessao)
    rec = await _recomendacao(
        sessao, alerta, {"operacao": "ALTERAR_ESTADO_ALERTA", "de": "NOVO", "para": "FALSO_POSITIVO"},
        tipo=RecommendationKind.FALSO_POSITIVO,
    )

    resposta = await _decidir(cliente, token_analista, rec)

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["recomendacao"]["applied"] is True
    await sessao.refresh(alerta)
    assert alerta.status is AlertStatus.FALSO_POSITIVO
    assert "recomendação" in alerta.triage_note


async def test_triagem_por_recomendacao_nao_promove_sem_incidente(
    cliente, sessao, token_analista
):
    """Regressão: a guarda do defeito 34 não existia nesta porta."""
    alerta = await _alerta(sessao)
    rec = await _recomendacao(
        sessao, alerta, {"operacao": "ALTERAR_ESTADO_ALERTA", "de": "NOVO", "para": "PROMOVIDO"},
    )

    resposta = await _decidir(cliente, token_analista, rec)

    assert resposta.status_code == 422, resposta.text
    assert resposta.json()["erro"]["codigo"] == "ESTADO_EXIGE_INCIDENTE"
    await sessao.refresh(alerta)
    assert alerta.status is AlertStatus.NOVO


async def test_alterar_campos_de_um_incidente_e_recusar_campos_fora_da_lista(
    cliente, sessao, token_analista
):
    incidente = await _incidente(sessao)
    rec = await _recomendacao(
        sessao, incidente,
        {"operacao": "ALTERAR_CAMPOS",
         "alteracoes": [{"campo": "category", "de": "OUTRO", "para": "INTRUSAO"}]},
        tipo=RecommendationKind.CLASSIFICACAO,
    )
    fora = await _recomendacao(
        sessao, incidente,
        {"operacao": "ALTERAR_CAMPOS", "alteracoes": [{"campo": "title", "para": "Outro título"}]},
        tipo=RecommendationKind.PRIORIZACAO,
    )

    aplicada = await _decidir(cliente, token_analista, rec)
    recusada = await _decidir(cliente, token_analista, fora)

    assert aplicada.status_code == 200, aplicada.text
    await sessao.refresh(incidente)
    assert incidente.category.value == "INTRUSAO"
    assert recusada.status_code == 422
    assert recusada.json()["erro"]["codigo"] == "CAMPO_NAO_ALTERAVEL"


async def test_associar_tecnicas_inferidas_e_nao_repetir(cliente, sessao, token_analista):
    incidente = await _incidente(sessao)
    tecnica = MitreTechnique(technique_id="T1110", name="Brute Force", tactic_shortnames=[])
    sessao.add(tecnica)
    await sessao.flush()
    alteracao = {"operacao": "ASSOCIAR_TECNICAS", "tecnicas": ["T1110"]}
    evidencia = {"tecnicas_propostas": [
        {"tecnica": "T1110", "grupos_de_regra": ["authentication_failed"], "razao": "Falhas."}
    ]}
    primeira = await _recomendacao(sessao, incidente, alteracao,
                                   tipo=RecommendationKind.TECNICA_MITRE, evidencia=evidencia)

    assert (await _decidir(cliente, token_analista, primeira)).status_code == 200
    ligacao = (
        await sessao.execute(
            select(IncidentTechnique).where(IncidentTechnique.incident_id == incidente.id)
        )
    ).scalar_one()
    assert ligacao.is_asserted is False
    assert "authentication_failed" in ligacao.rationale

    segunda = await _recomendacao(sessao, incidente, alteracao,
                                  tipo=RecommendationKind.TECNICA_MITRE, evidencia=evidencia)
    resposta = await _decidir(cliente, token_analista, segunda)
    assert resposta.json()["recomendacao"]["applied"] is False
    assert "já estavam associadas" in resposta.json()["efeito"]


async def test_tecnica_fora_do_catalogo_nao_e_associada(cliente, sessao, token_analista):
    incidente = await _incidente(sessao)
    rec = await _recomendacao(sessao, incidente,
                              {"operacao": "ASSOCIAR_TECNICAS", "tecnicas": ["T9999"]},
                              tipo=RecommendationKind.TECNICA_MITRE)

    resposta = await _decidir(cliente, token_analista, rec)

    assert resposta.status_code == 409, resposta.text


async def test_aceitar_um_playbook_inicia_a_execucao(
    cliente, sessao, token_admin, token_analista
):
    incidente_api = (
        await cliente.post(
            "/api/incidents",
            json={"title": "Incidente para playbook", "description": "x",
                  "category": "INTRUSAO", "severity": "ALTA"},
            headers=cabecalho(token_analista),
        )
    ).json()
    playbook = (
        await cliente.post(
            "/api/playbooks",
            json={"name": "Playbook recomendado", "description": "x", "is_enabled": True,
                  "steps": [{"ordering": 1, "name": "Nota", "step_type": "REGISTAR_NOTA",
                             "parameters": {"texto": "Iniciado por recomendação."}}]},
            headers=cabecalho(token_admin),
        )
    ).json()
    incidente = await sessao.get(Incident, uuid.UUID(incidente_api["id"]))
    rec = await _recomendacao(
        sessao, incidente, {"operacao": "EXECUTAR_PLAYBOOK", "playbook_id": playbook["id"]},
        tipo=RecommendationKind.PLAYBOOK,
    )

    resposta = await _decidir(cliente, token_analista, rec)

    assert resposta.status_code == 200, resposta.text
    execucao = (
        await sessao.execute(
            select(PlaybookExecution).where(PlaybookExecution.incident_id == incidente.id)
        )
    ).scalar_one()
    assert execucao.status.value == "CONCLUIDA"
    assert execucao.reference in resposta.json()["efeito"]


async def test_operacao_desconhecida_e_recusada(cliente, sessao, token_analista):
    incidente = await _incidente(sessao, estado=IncidentStatus.NOVO)
    rec = await _recomendacao(sessao, incidente, {"operacao": "APAGAR_TUDO"})

    resposta = await _decidir(cliente, token_analista, rec)

    assert resposta.status_code == 422
    assert resposta.json()["erro"]["codigo"] == "OPERACAO_DESCONHECIDA"
