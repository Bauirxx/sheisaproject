"""Motor de recomendações (§12).

Além de verificar que as recomendações certas aparecem, estes testes fixam as
quatro invariantes declaradas no cabeçalho do motor — não inventa, não insiste,
não ultrapassa, não decide sozinha. São elas que distinguem apoio à decisão de
automatismo disfarçado, e nenhuma sobrevive a uma alteração descuidada sem que
um destes testes caia.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.core.enums import (
    AlertStatus,
    IncidentCategory,
    IncidentOrigin,
    IncidentStatus,
    Priority,
    RecommendationKind,
    RecommendationStatus,
    Severity,
    SourceKind,
)
from app.core.references import ReferenceKind, next_reference
from app.intelligence import recommendations as motor
from app.models.catalog import MitreTechnique
from app.models.incident import Incident, IncidentTechnique
from app.models.intelligence import Recommendation
from app.models.telemetry import Alert
from app.services import recommendation_service as servico
from tests.conftest import cabecalho


async def _alerta(sessao, **campos) -> Alert:
    agora = datetime.now(UTC)
    alerta = Alert(
        reference=await next_reference(sessao, ReferenceKind.ALERT),
        title=campos.pop("titulo", "Alerta de teste"),
        description="",
        source_kind=SourceKind.WAZUH,
        source_name="wazuh-teste",
        severity=campos.pop("severidade", Severity.MEDIA),
        status=campos.pop("estado", AlertStatus.NOVO),
        dedup_key=campos.pop("dedup", f"chave-{agora.timestamp()}-{id(campos)}"),
        event_count=1,
        first_event_at=agora,
        last_event_at=agora,
        rule_id=campos.pop("rule_id", "5710"),
        rule_name=campos.pop("rule_name", "Falhas de autenticacao"),
        tags=campos.pop("tags", ["sshd", "authentication_failed"]),
        triage_score=campos.pop("pontuacao", 0),
        false_positive_score=campos.pop("fp", 0),
        scored_at=campos.pop("pontuado_em", agora),
        **campos,
    )
    sessao.add(alerta)
    await sessao.flush()
    return alerta


async def _incidente(sessao, **campos) -> Incident:
    agora = datetime.now(UTC)
    incidente = Incident(
        reference=await next_reference(sessao, ReferenceKind.INCIDENT),
        title=campos.pop("titulo", "Incidente de teste"),
        description="",
        category=campos.pop("categoria", IncidentCategory.OUTRO),
        severity=campos.pop("severidade", Severity.MEDIA),
        priority=campos.pop("prioridade", Priority.P3),
        status=campos.pop("estado", IncidentStatus.NOVO),
        origin=IncidentOrigin.REGISTO_MANUAL,
        source_kind=SourceKind.WAZUH,
        detected_at=campos.pop("detectado_em", agora - timedelta(minutes=30)),
        **campos,
    )
    sessao.add(incidente)
    await sessao.flush()
    return incidente


# ============================================ invariante: a conta tem de bater
async def test_a_soma_dos_factores_confere_com_a_confianca(sessao):
    """Mesma propriedade da triagem: o número mostrado é a soma do que o sustenta."""
    await _alerta(sessao, pontuacao=80, severidade=Severity.MEDIA)
    alerta = await _alerta(sessao, pontuacao=80, severidade=Severity.MEDIA)

    propostas = await motor.gerar_para_alerta(sessao, alerta)
    assert propostas

    # Tectos declarados no motor: 100 em geral, 85 para juízos de grau, e
    # MAX_CONFIDENCE_INFERENCIA para inferências (§11).
    tectos = {100, 85, motor.MAX_CONFIDENCE_INFERENCIA}

    for proposta in propostas:
        soma = sum(f.pontos for f in proposta.factors)
        exacta = proposta.confidence == max(0, min(soma, 100))
        limitada = proposta.confidence in tectos and soma >= proposta.confidence
        assert exacta or limitada, (
            f"{proposta.kind}: confiança {proposta.confidence} não é a soma {soma} "
            f"nem um tecto declarado"
        )
        # A decomposição publicada tem de coincidir com o total apresentado.
        assert proposta.factors_as_dict()["total"] == proposta.confidence


async def test_cada_recomendacao_traz_explicacao_e_evidencia(sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    for proposta in await motor.gerar_para_alerta(sessao, alerta):
        assert proposta.explanation.strip()
        assert proposta.summary.strip()
        assert proposta.title.strip()
        for factor in proposta.factors:
            assert factor.razao.strip()


# ================================================== invariante: não inventa
async def test_sem_catalogo_mitre_nao_ha_inferencia(sessao):
    """§4: se o ATT&CK não estiver carregado, o motor não propõe técnicas.

    A base de dados de teste não tem o catálogo. Um motor que propusesse na
    mesma estaria a produzir identificadores sem os ter verificado.
    """
    incidente = await _incidente(sessao)
    await _alerta(sessao, incident_id=incidente.id, tags=["syscheck", "file_integrity"])

    propostas = await motor.gerar_para_incidente(sessao, incidente)
    assert not [p for p in propostas if p.kind is RecommendationKind.TECNICA_MITRE]


async def test_com_catalogo_a_inferencia_aparece(sessao):
    sessao.add(
        MitreTechnique(
            technique_id="T1565",
            name="Data Manipulation",
            url="https://attack.mitre.org/techniques/T1565",
            tactic_shortnames=["impact"],
        )
    )
    await sessao.flush()

    incidente = await _incidente(sessao)
    await _alerta(sessao, incident_id=incidente.id, tags=["syscheck", "file_integrity"])

    propostas = await motor.gerar_para_incidente(sessao, incidente)
    mitre = next(p for p in propostas if p.kind is RecommendationKind.TECNICA_MITRE)
    assert mitre.proposed_change["tecnicas"] == ["T1565"]
    assert mitre.evidence_refs["tecnicas_propostas"][0]["grupos_de_regra"]


async def test_tecnica_ja_associada_nao_e_reproposta(sessao):
    """A que a fonte já afirmou não volta como hipótese do motor."""
    tecnica = MitreTechnique(
        technique_id="T1110", name="Brute Force", tactic_shortnames=["credential-access"]
    )
    sessao.add(tecnica)
    await sessao.flush()

    incidente = await _incidente(sessao)
    await _alerta(sessao, incident_id=incidente.id, tags=["sshd", "authentication_failed"])
    sessao.add(
        IncidentTechnique(
            incident_id=incidente.id,
            technique_id=tecnica.id,
            is_asserted=True,
            rationale="Declarada pela regra da fonte.",
        )
    )
    await sessao.flush()

    propostas = await motor.gerar_para_incidente(sessao, incidente)
    assert not [p for p in propostas if p.kind is RecommendationKind.TECNICA_MITRE]


# =============================================== invariante: não ultrapassa
async def test_a_confianca_de_uma_inferencia_tem_tecto(sessao):
    sessao.add(
        MitreTechnique(technique_id="T1565", name="Data Manipulation", tactic_shortnames=[])
    )
    await sessao.flush()

    incidente = await _incidente(sessao)
    for _ in range(20):  # muitos alertas a corroborar
        await _alerta(
            sessao, incident_id=incidente.id, tags=["syscheck", "file_integrity"]
        )

    propostas = await motor.gerar_para_incidente(sessao, incidente)
    mitre = next(p for p in propostas if p.kind is RecommendationKind.TECNICA_MITRE)
    assert mitre.confidence <= motor.MAX_CONFIDENCE_INFERENCIA


async def test_a_tecnica_aplicada_fica_marcada_como_inferida(
    cliente, token_admin, sessao
):
    """§11: o motor não produz factos — produz hipóteses justificadas."""
    sessao.add(
        MitreTechnique(technique_id="T1565", name="Data Manipulation", tactic_shortnames=[])
    )
    await sessao.flush()

    incidente = await _incidente(sessao)
    await _alerta(sessao, incident_id=incidente.id, tags=["syscheck", "file_integrity"])
    await servico.sincronizar_incidente(sessao, incidente)
    await sessao.commit()

    rec = (
        await sessao.execute(
            select(Recommendation).where(
                Recommendation.kind == RecommendationKind.TECNICA_MITRE
            )
        )
    ).scalar_one()

    resposta = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": True, "aplicar_alteracao": True},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 200, resposta.text

    associacao = (
        await sessao.execute(
            select(IncidentTechnique).where(IncidentTechnique.incident_id == incidente.id)
        )
    ).scalar_one()
    assert associacao.is_asserted is False
    assert associacao.rationale
    assert associacao.evidence_refs["grupos_de_regra"]


# ================================================= invariante: não insiste
async def test_uma_recomendacao_rejeitada_nao_volta(cliente, token_admin, sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    await servico.sincronizar_alerta(sessao, alerta)
    await sessao.commit()

    rec = (
        await sessao.execute(
            select(Recommendation).where(
                Recommendation.kind == RecommendationKind.TRIAGEM
            )
        )
    ).scalar_one()
    proposta_rejeitada = dict(rec.proposed_change)

    await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": False, "note": "Não concordo."},
        headers=cabecalho(token_admin),
    )

    # A decisão foi tomada noutra sessão (a do pedido HTTP), como em produção.
    # Sem recarregar, a sessão do teste devolveria a sua cópia em memória, ainda
    # PENDENTE, e o motor não veria a recusa — uma avaria que só existiria no
    # teste. Recarrega-se só a recomendação: um `expire_all()` expiraria também
    # o alerta, cujos atributos são depois lidos fora de um `await`.
    await sessao.refresh(rec)

    vigentes, _ = await servico.sincronizar_alerta(sessao, alerta)
    assert not [
        r for r in vigentes if r.proposed_change == proposta_rejeitada
    ], "o motor voltou a insistir numa proposta já recusada"


async def test_sincronizar_duas_vezes_nao_duplica(sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    await servico.sincronizar_alerta(sessao, alerta)
    await servico.sincronizar_alerta(sessao, alerta)
    await servico.sincronizar_alerta(sessao, alerta)

    por_tipo = (
        await sessao.execute(
            select(Recommendation.kind, func.count())
            .where(
                Recommendation.target_id == alerta.id,
                Recommendation.status == RecommendationStatus.PENDENTE,
            )
            .group_by(Recommendation.kind)
        )
    ).all()
    assert all(total == 1 for _, total in por_tipo), por_tipo


async def test_recomendacao_sem_fundamento_e_retirada(sessao):
    """Se a justificação desaparece, a recomendação sai da fila."""
    alerta = await _alerta(sessao, pontuacao=80, severidade=Severity.MEDIA)
    vigentes, _ = await servico.sincronizar_alerta(sessao, alerta)
    assert vigentes

    # O alerta é decidido: deixa de estar em aberto e nada há a recomendar.
    alerta.status = AlertStatus.FALSO_POSITIVO
    await sessao.flush()

    _, retiradas = await servico.sincronizar_alerta(sessao, alerta)
    assert retiradas >= 1

    pendentes = await sessao.scalar(
        select(func.count())
        .select_from(Recommendation)
        .where(
            Recommendation.target_id == alerta.id,
            Recommendation.status == RecommendationStatus.PENDENTE,
        )
    )
    assert pendentes == 0


# ============================================ invariante: não decide sozinha
async def test_aceitar_sem_a_permissao_nao_aplica(cliente, token_analista, sessao):
    """Aceitar uma recomendação não é atalho para o que o perfil não permite."""
    from sqlalchemy.orm import selectinload

    from app.models.identity import Role

    papel = (
        await sessao.execute(
            select(Role)
            .where(Role.name == "ANALISTA_SOC")
            .options(selectinload(Role.permissions))
        )
    ).scalar_one()
    papel.permissions.remove(
        next(p for p in papel.permissions if p.code == "incidents:update")
    )
    await sessao.flush()

    incidente = await _incidente(sessao, severidade=Severity.CRITICA)
    await _alerta(sessao, incident_id=incidente.id, pontuacao=10)
    await servico.sincronizar_incidente(sessao, incidente)
    await sessao.commit()

    rec = (
        await sessao.execute(
            select(Recommendation).where(
                Recommendation.kind == RecommendationKind.PRIORIZACAO,
                Recommendation.target_id == incidente.id,
            )
        )
    ).scalar_one()
    severidade_antes = incidente.severity

    resposta = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": True, "aplicar_alteracao": True},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 200, resposta.text
    corpo = resposta.json()

    assert corpo["recomendacao"]["status"] == "ACEITE"
    assert corpo["recomendacao"]["applied"] is False
    assert "incidents:update" in corpo["efeito"]

    await sessao.refresh(incidente)
    assert incidente.severity is severidade_antes, "o alvo foi alterado sem permissão"


async def test_aceitar_sem_aplicar_regista_a_concordancia(
    cliente, token_admin, sessao
):
    alerta = await _alerta(sessao, pontuacao=80)
    await servico.sincronizar_alerta(sessao, alerta)
    await sessao.commit()
    rec = (
        await sessao.execute(
            select(Recommendation).where(Recommendation.kind == RecommendationKind.TRIAGEM)
        )
    ).scalar_one()

    resposta = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": True, "aplicar_alteracao": False},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 200
    assert resposta.json()["recomendacao"]["status"] == "ACEITE"
    assert resposta.json()["recomendacao"]["applied"] is False


async def test_recomendacao_sem_alteracao_mecanica_diz_o_que_e(sessao):
    """"Atribua um responsável" não é aplicável por máquina — e a resposta di-lo."""
    incidente = await _incidente(sessao, estado=IncidentStatus.TRIAGEM, assignee_id=None)
    await _alerta(sessao, incident_id=incidente.id)

    propostas = await motor.gerar_para_incidente(sessao, incidente)
    passo = next(
        p for p in propostas if p.kind is RecommendationKind.PROXIMO_PASSO
    )
    assert passo.proposed_change == {}
    assert "responsável" in passo.title.lower() or "responsavel" in passo.title.lower()


# ==================================================== geradores específicos
async def test_falso_positivo_exige_historico_suficiente(sessao):
    from app.intelligence.triage import MIN_HISTORY_FOR_FP

    for _ in range(MIN_HISTORY_FOR_FP - 1):
        await _alerta(sessao, rule_id="regra-x", estado=AlertStatus.FALSO_POSITIVO)
    alerta = await _alerta(sessao, rule_id="regra-x")

    propostas = await motor.gerar_para_alerta(sessao, alerta)
    assert not [p for p in propostas if p.kind is RecommendationKind.FALSO_POSITIVO]


async def test_falso_positivo_com_historico_penaliza_pela_amostra(sessao):
    """A taxa é 100% mas a confiança não: seis decisões não são dez."""
    for _ in range(6):
        await _alerta(sessao, rule_id="regra-y", estado=AlertStatus.FALSO_POSITIVO)
    alerta = await _alerta(sessao, rule_id="regra-y")

    proposta = next(
        p
        for p in await motor.gerar_para_alerta(sessao, alerta)
        if p.kind is RecommendationKind.FALSO_POSITIVO
    )
    assert proposta.confidence < 100
    ajuste = next(
        f for f in proposta.factors if f.nome == "ajuste_por_dimensao_da_amostra"
    )
    assert ajuste.pontos < 0
    assert proposta.evidence_refs["alertas_descartados"]


async def test_promocao_nao_e_sugerida_com_risco_alto_de_falso_positivo(sessao):
    alerta = await _alerta(sessao, pontuacao=90, fp=80)
    propostas = await motor.gerar_para_alerta(sessao, alerta)
    assert not [p for p in propostas if p.kind is RecommendationKind.TRIAGEM]


async def test_a_transicao_proposta_e_sempre_permitida(sessao):
    """O motor não sugere caminhos que o ciclo de vida recusa."""
    from app.core.enums import INCIDENT_TRANSITIONS

    for estado in IncidentStatus:
        incidente = await _incidente(sessao, estado=estado)
        await _alerta(sessao, incident_id=incidente.id)
        for proposta in await motor.gerar_para_incidente(sessao, incidente):
            mudanca = proposta.proposed_change
            if mudanca.get("operacao") != "TRANSICAO_ESTADO":
                continue
            destino = IncidentStatus(mudanca["para"])
            assert destino in INCIDENT_TRANSITIONS.get(estado, frozenset()), (
                f"{estado.value} -> {destino.value} não é uma transição permitida"
            )


async def test_proximo_passo_devolve_uma_so_recomendacao(sessao):
    """Um incidente parado tem várias lacunas; a fila mostra a mais urgente."""
    incidente = await _incidente(sessao, estado=IncidentStatus.NOVO, assignee_id=None)
    await _alerta(sessao, incident_id=incidente.id)

    passos = [
        p
        for p in await motor.gerar_para_incidente(sessao, incidente)
        if p.kind is RecommendationKind.PROXIMO_PASSO
    ]
    assert len(passos) == 1


async def test_aplicar_transicao_passa_pelo_servico_real(cliente, token_admin, sessao):
    """A aplicação tem de ter o mesmo efeito que a acção feita à mão.

    Se escrevesse `status` directamente, o marco de reconhecimento não seria
    preenchido e o MTTA dos relatórios ficaria errado sem nada o denunciar.
    """
    incidente = await _incidente(sessao, estado=IncidentStatus.NOVO)
    await _alerta(sessao, incident_id=incidente.id)
    await servico.sincronizar_incidente(sessao, incidente)
    await sessao.commit()

    rec = (
        await sessao.execute(
            select(Recommendation).where(
                Recommendation.kind == RecommendationKind.PROXIMO_PASSO,
                Recommendation.target_id == incidente.id,
            )
        )
    ).scalar_one()
    assert rec.proposed_change["operacao"] == "TRANSICAO_ESTADO"

    resposta = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": True, "aplicar_alteracao": True},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 200, resposta.text

    await sessao.refresh(incidente)
    assert incidente.status is IncidentStatus.TRIAGEM
    assert incidente.acknowledged_at is not None


# ====================================================== validade e API
async def test_recomendacao_vencida_e_expirada(sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    vigentes, _ = await servico.sincronizar_alerta(sessao, alerta)
    for rec in vigentes:
        rec.expires_at = datetime.now(UTC) - timedelta(days=1)
    await sessao.flush()

    expiradas = await servico.expirar_vencidas(sessao)
    assert expiradas == len(vigentes)
    assert all(r.status is RecommendationStatus.EXPIRADA for r in vigentes)


async def test_decidir_duas_vezes_e_recusado(cliente, token_admin, sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    await servico.sincronizar_alerta(sessao, alerta)
    await sessao.commit()
    rec = (
        await sessao.execute(
            select(Recommendation).where(Recommendation.kind == RecommendationKind.TRIAGEM)
        )
    ).scalar_one()

    primeira = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": False},
        headers=cabecalho(token_admin),
    )
    assert primeira.status_code == 200

    segunda = await cliente.post(
        f"/api/recommendations/{rec.id}/decide",
        json={"accept": True},
        headers=cabecalho(token_admin),
    )
    assert segunda.status_code == 409


async def test_listagem_mostra_pendentes_por_omissao(cliente, token_analista, sessao):
    alerta = await _alerta(sessao, pontuacao=80)
    await servico.sincronizar_alerta(sessao, alerta)
    await sessao.commit()

    resposta = await cliente.get(
        "/api/recommendations", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["total"] >= 1
    assert all(i["status"] == "PENDENTE" for i in corpo["itens"])
    # Ordenada por confiança decrescente: a fila serve para trabalhar.
    confiancas = [i["confidence"] for i in corpo["itens"]]
    assert confiancas == sorted(confiancas, reverse=True)


async def test_metadados_do_motor_sao_expostos(cliente, token_analista):
    resposta = await cliente.get(
        "/api/recommendations/meta/tipos", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["motor"] == motor.ENGINE_NAME
    assert set(corpo["tipos"]) == {k.value for k in RecommendationKind}
    assert corpo["limiares"]["confianca_maxima_de_inferencia"] == (
        motor.MAX_CONFIDENCE_INFERENCIA
    )
