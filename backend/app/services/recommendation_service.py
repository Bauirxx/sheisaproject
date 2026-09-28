"""Persistência, decisão e aplicação de recomendações (§12).

O motor (`app.intelligence.recommendations`) calcula; este serviço decide o que
fica registado e o que acontece quando alguém aceita.

Três comportamentos que não são óbvios e por isso vão explicados:

1. **Sincronizar, não acumular.** Gerar recomendações duas vezes para o mesmo
   alvo não produz duplicados. Uma recomendação pendente cujo cálculo mudou é
   *actualizada* — o analista deve ver o estado actual, não um histórico de
   versões de uma sugestão que ainda não decidiu. Uma que deixou de se
   justificar é retirada.

2. **Uma recusa é definitiva enquanto a proposta for a mesma.** Se o analista
   rejeitou "reclassificar como INTRUSAO" e o motor volta a chegar à mesma
   conclusão, nada é levantado. Se chegar a uma conclusão *diferente* —
   entretanto surgiram alertas novos — é uma proposta nova e vale a pena. Sem
   esta regra o motor discutiria com o analista até este desligar a lista.

3. **Aceitar não dá poderes.** Aplicar a alteração exige a permissão que a
   operação exigiria se fosse feita à mão: promover um alerta exige
   `alerts:promote`, executar um playbook exige `playbooks:execute`. Quem tem
   `recommendations:decide` mas não a permissão da operação pode concordar com
   a recomendação — fica registado — mas a alteração não é aplicada, e a
   resposta diz porquê em vez de falhar em silêncio.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import (
    AlertStatus,
    AuditOutcome,
    Confidence,
    IncidentCategory,
    IncidentStatus,
    Priority,
    RecommendationKind,
    RecommendationStatus,
    Severity,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.permissions import Permission
from app.intelligence import recommendations as engine
from app.models.catalog import MitreTechnique
from app.models.identity import User
from app.models.incident import Incident, IncidentTechnique
from app.models.intelligence import Recommendation
from app.models.response import Playbook
from app.models.telemetry import Alert

#: Permissão exigida por cada operação aplicável, para além de
#: `recommendations:decide`. Aceitar uma recomendação nunca pode ser um atalho
#: para fazer o que o perfil não permite fazer directamente.
PERMISSAO_POR_OPERACAO: dict[str, Permission] = {
    "ALTERAR_ESTADO_ALERTA": Permission.ALERTS_TRIAGE,
    "PROMOVER_ALERTA": Permission.ALERTS_PROMOTE,
    "TRANSICAO_ESTADO": Permission.INCIDENTS_TRANSITION,
    "ASSOCIAR_TECNICAS": Permission.MITRE_MAP,
    "EXECUTAR_PLAYBOOK": Permission.PLAYBOOKS_EXECUTE,
}


def _permissao_para(proposed_change: dict) -> Permission | None:
    operacao = proposed_change.get("operacao")
    if operacao == "ALTERAR_CAMPOS":
        # Depende do alvo; resolvido em `_aplicar`, que já sabe qual é.
        return None
    return PERMISSAO_POR_OPERACAO.get(operacao) if operacao else None


def _tem(user: User, permissao: Permission) -> bool:
    return permissao.value in {p.code for p in (user.role.permissions if user.role else [])}


# ============================================================== sincronização
async def sincronizar_alerta(
    session: AsyncSession, alert: Alert
) -> tuple[list[Recommendation], int]:
    """Actualiza as recomendações pendentes de um alerta."""
    propostas = await engine.gerar_para_alerta(session, alert)
    return await _sincronizar(session, engine.TARGET_ALERT, alert.id, propostas)


async def sincronizar_incidente(
    session: AsyncSession, incident: Incident
) -> tuple[list[Recommendation], int]:
    """Actualiza as recomendações pendentes de um incidente."""
    propostas = await engine.gerar_para_incidente(session, incident)
    return await _sincronizar(session, engine.TARGET_INCIDENT, incident.id, propostas)


async def _sincronizar(
    session: AsyncSession,
    target_type: str,
    target_id: uuid.UUID,
    propostas: Sequence[engine.Proposta],
) -> tuple[list[Recommendation], int]:
    """Concilia as propostas do motor com o que já está gravado.

    Devolve as recomendações pendentes em vigor e quantas foram retiradas por
    terem deixado de se justificar.
    """
    existentes = await session.execute(
        select(Recommendation).where(
            Recommendation.target_type == target_type,
            Recommendation.target_id == target_id,
        )
    )
    por_tipo: dict[RecommendationKind, list[Recommendation]] = {}
    for rec in existentes.scalars():
        por_tipo.setdefault(rec.kind, []).append(rec)

    em_vigor: list[Recommendation] = []
    propostas_por_tipo = {p.kind: p for p in propostas}

    for kind, proposta in propostas_por_tipo.items():
        anteriores = por_tipo.get(kind, [])

        # Uma recusa da mesma proposta é definitiva: não se volta a insistir.
        recusada_igual = any(
            r.status is RecommendationStatus.REJEITADA
            and r.proposed_change == proposta.proposed_change
            for r in anteriores
        )
        if recusada_igual:
            continue

        # Uma proposta já aceite e aplicada não se repete.
        aceite_igual = any(
            r.status is RecommendationStatus.ACEITE
            and r.proposed_change == proposta.proposed_change
            for r in anteriores
        )
        if aceite_igual:
            continue

        pendente = next(
            (r for r in anteriores if r.status is RecommendationStatus.PENDENTE), None
        )
        if pendente is None:
            pendente = Recommendation(
                kind=kind,
                status=RecommendationStatus.PENDENTE,
                target_type=target_type,
                target_id=target_id,
            )
            session.add(pendente)

        _preencher(pendente, proposta)
        em_vigor.append(pendente)

    # O que o motor deixou de propor deixa de estar pendente. Manter uma
    # recomendação cuja justificação já não existe é pior do que não a ter:
    # o analista decidiria sobre um estado que já passou.
    retiradas = 0
    for kind, anteriores in por_tipo.items():
        if kind in propostas_por_tipo:
            continue
        for rec in anteriores:
            if rec.status is RecommendationStatus.PENDENTE:
                rec.status = RecommendationStatus.EXPIRADA
                rec.decision_note = "Retirada: o motor deixou de a sustentar."
                retiradas += 1

    await session.flush()
    return em_vigor, retiradas


def _preencher(rec: Recommendation, proposta: engine.Proposta) -> None:
    rec.title = proposta.title[:250]
    rec.summary = proposta.summary
    rec.explanation = proposta.explanation
    rec.confidence = proposta.confidence
    rec.factors = proposta.factors_as_dict()
    rec.evidence_refs = proposta.evidence_refs
    rec.proposed_change = proposta.proposed_change
    rec.engine = engine.ENGINE_NAME
    rec.engine_version = engine.ENGINE_VERSION
    rec.expires_at = proposta.expires_at


async def expirar_vencidas(session: AsyncSession) -> int:
    """Marca como expiradas as recomendações pendentes que passaram a validade."""
    agora = datetime.now(UTC)
    resultado = await session.execute(
        select(Recommendation).where(
            Recommendation.status == RecommendationStatus.PENDENTE,
            Recommendation.expires_at.isnot(None),
            Recommendation.expires_at < agora,
        )
    )
    contador = 0
    for rec in resultado.scalars():
        rec.status = RecommendationStatus.EXPIRADA
        rec.decision_note = "Expirada sem decisão."
        contador += 1
    if contador:
        await session.flush()
    return contador


# =================================================================== consulta
async def get_recommendation(
    session: AsyncSession, recommendation_id: uuid.UUID
) -> Recommendation:
    rec = await session.get(Recommendation, recommendation_id)
    if rec is None:
        raise NotFoundError("Recomendação", recommendation_id)
    return rec


async def descrever_alvo(session: AsyncSession, rec: Recommendation) -> str:
    """Referência legível do alvo, para auditoria e para a listagem."""
    if rec.target_type == engine.TARGET_ALERT:
        alerta = await session.get(Alert, rec.target_id)
        return alerta.reference if alerta else str(rec.target_id)
    incidente = await session.get(Incident, rec.target_id)
    return incidente.reference if incidente else str(rec.target_id)


# =================================================================== decisão
async def decidir(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    rec: Recommendation,
    decisor: User,
    aceitar: bool,
    nota: str | None = None,
    aplicar_alteracao: bool = True,
) -> tuple[Recommendation, str]:
    """Regista a decisão e, se pedido e possível, aplica a alteração.

    Devolve a recomendação e uma frase que descreve o que aconteceu de facto —
    incluindo quando **não** foi aplicada nada e porquê. A interface mostra
    essa frase ao analista: uma recomendação que diz "aceite" sem dizer se
    chegou a mudar alguma coisa é exactamente o tipo de ambiguidade que o §4
    proíbe.
    """
    if rec.status is not RecommendationStatus.PENDENTE:
        raise ConflictError(
            f"A recomendação já foi decidida ({rec.status.value}).",
            details={"estado": rec.status.value},
        )

    # A validade era imposta só pelo recálculo global, o que fazia depender uma
    # regra de um varrimento periódico: entre o vencimento e o recálculo
    # seguinte, a proposta continuava a aplicar-se. Uma recomendação venceu
    # porque o fundamento que a sustentava deixou de ser actual — aplicá-la
    # depois altera o alvo com base em indícios que já não valem.
    #
    # Marca-se aqui, em vez de apenas recusar: quem tentou decidir mostrou que
    # a proposta está a ser vista, e deixá-la PENDENTE faria reaparecer o mesmo
    # erro ao próximo analista.
    if rec.expires_at is not None and rec.expires_at <= datetime.now(UTC):
        rec.status = RecommendationStatus.EXPIRADA
        rec.decision_note = "Expirada sem decisão."
        await audit.record_denied(
            session,
            ctx,
            action="DECIDIR_RECOMENDACAO",
            resource_type="recomendacao",
            resource_id=rec.id,
            reason=(
                f"a validade expirou em {rec.expires_at:%Y-%m-%d %H:%M} UTC; "
                "o alvo não foi alterado"
            ),
        )
        # Consolidamos a expiração e o registo antes de levantar: a excepção faz
        # rollback da transacção do pedido e levaria ambos com ela. É o mesmo
        # procedimento que `require()` usa ao registar um acesso negado.
        await session.commit()
        raise ConflictError(
            f"A validade desta recomendação expirou em {rec.expires_at:%Y-%m-%d %H:%M} "
            "UTC e o fundamento que a sustentava deixou de ser actual. "
            "Recalcule as recomendações do alvo para obter uma proposta nova.",
            details={"expirou_em": rec.expires_at.isoformat()},
        )

    referencia = await descrever_alvo(session, rec)
    rec.status = RecommendationStatus.ACEITE if aceitar else RecommendationStatus.REJEITADA
    rec.decided_at = datetime.now(UTC)
    rec.decided_by_id = decisor.id
    rec.decision_note = nota

    if not aceitar:
        efeito = "Recomendação rejeitada; nada foi alterado."
    elif not rec.proposed_change:
        efeito = (
            "Recomendação aceite. Não tem alteração aplicável mecanicamente — "
            "a acção correspondente é do analista."
        )
    elif not aplicar_alteracao:
        efeito = "Recomendação aceite sem aplicar a alteração, a pedido de quem decidiu."
    else:
        efeito = await _aplicar(session, ctx, rec=rec, decisor=decisor)

    await audit.record(
        session,
        ctx,
        action="DECIDIR_RECOMENDACAO",
        resource_type="recomendacao",
        resource_id=rec.id,
        resource_reference=referencia,
        description=(
            f"{rec.kind.value} sobre {referencia} "
            f"({'aceite' if aceitar else 'rejeitada'}, confiança {rec.confidence}). {efeito}"
            + (f" Nota: {nota}" if nota else "")
        ),
        old_value={"estado": RecommendationStatus.PENDENTE.value},
        new_value={"estado": rec.status.value, "aplicada": rec.applied},
        changed_fields=["status", "applied"],
    )
    return rec, efeito


async def _aplicar(
    session: AsyncSession, ctx: AuditContext, *, rec: Recommendation, decisor: User
) -> str:
    """Executa a alteração proposta pelo caminho real da aplicação.

    Nenhuma operação aqui escreve directamente no modelo quando existe um
    serviço que já sabe fazê-lo: a transição de estado passa por
    `incident_service.transition`, que valida o ciclo de vida; a promoção passa
    por `promote_alert`, que cria observações e importa técnicas. Duplicar
    essas regras aqui daria a uma recomendação aceite um efeito diferente do
    da mesma acção feita à mão.
    """
    operacao = rec.proposed_change.get("operacao")
    if not operacao:
        return "Nada a aplicar."

    exigida = _permissao_para(rec.proposed_change)
    if exigida is not None and not _tem(decisor, exigida):
        await audit.record(
            session,
            ctx,
            action="APLICAR_RECOMENDACAO",
            resource_type="recomendacao",
            resource_id=rec.id,
            outcome=AuditOutcome.NEGADO,
            failure_reason=f"permissão em falta: {exigida.value}",
            description=f"Aplicação de {operacao} recusada por falta de {exigida.value}.",
        )
        return (
            f"Recomendação aceite, mas a alteração não foi aplicada: exige a permissão "
            f"'{exigida.value}', que o perfil não tem."
        )

    # Cada aplicador devolve (aplicou, efeito). O booleano não é redundante
    # com a ausência de excepção: há caminhos que terminam sem erro e sem
    # alterar nada — falta de permissão para o campo concreto, proposta já
    # satisfeita. Marcar `applied` nesses casos poria na base de dados a
    # afirmação de que algo mudou quando nada mudou.
    match operacao:
        case "ALTERAR_ESTADO_ALERTA":
            aplicou, efeito = await _aplicar_estado_alerta(session, ctx, rec)
        case "PROMOVER_ALERTA":
            aplicou, efeito = await _aplicar_promocao(session, ctx, rec)
        case "ALTERAR_CAMPOS":
            aplicou, efeito = await _aplicar_campos(session, ctx, rec, decisor)
        case "TRANSICAO_ESTADO":
            aplicou, efeito = await _aplicar_transicao(session, ctx, rec)
        case "ASSOCIAR_TECNICAS":
            aplicou, efeito = await _aplicar_tecnicas(session, ctx, rec)
        case "EXECUTAR_PLAYBOOK":
            aplicou, efeito = await _aplicar_playbook(session, ctx, rec)
        case _:
            raise ValidationError(
                f"Operação '{operacao}' não é aplicável por este serviço.",
                code="OPERACAO_DESCONHECIDA",
            )

    rec.applied = aplicou
    return efeito


async def _carregar_alerta(session: AsyncSession, rec: Recommendation) -> Alert:
    alerta = await session.get(Alert, rec.target_id)
    if alerta is None:
        raise NotFoundError("Alerta", rec.target_id)
    return alerta


async def _carregar_incidente(session: AsyncSession, rec: Recommendation) -> Incident:
    """Carrega o incidente alvo, recusando-o se estiver encerrado.

    É o funil por onde passam todos os aplicadores com alvo incidente — campos,
    técnicas, transição e playbook. A guarda aqui vale para os quatro; posta em
    cada um, faltaria no quinto que aparecesse.
    """
    from app.services import incident_service

    incidente = await session.get(Incident, rec.target_id)
    if incidente is None:
        raise NotFoundError("Incidente", rec.target_id)
    incident_service.garantir_editavel(incidente)
    return incidente


async def _aplicar_estado_alerta(
    session: AsyncSession, ctx: AuditContext, rec: Recommendation
) -> tuple[bool, str]:
    from app.core.enums import (
        ALERT_STATES_REQUIRING_INCIDENT,
        ALERT_TRANSITIONS,
    )
    from app.core.errors import InvalidTransitionError

    alerta = await _carregar_alerta(session, rec)
    destino = AlertStatus(rec.proposed_change["para"])

    # A mesma guarda da triagem à mão. O motor não gera hoje uma proposta
    # destas, mas a regra não pode depender disso: uma recomendação gravada por
    # outro caminho deixaria aqui um alerta PROMOVIDO sem incidente nenhum.
    if destino in ALERT_STATES_REQUIRING_INCIDENT:
        raise ValidationError(
            f"Um alerta só fica {destino.value} ao ser promovido ou ligado a um "
            "incidente, o que cria as observações e importa as técnicas. "
            "Aplicar só o estado deixaria o alerta fora da fila de triagem e "
            "fora de qualquer incidente.",
            code="ESTADO_EXIGE_INCIDENTE",
        )

    permitidas = ALERT_TRANSITIONS.get(alerta.status, frozenset())
    if destino not in permitidas:
        raise InvalidTransitionError(
            alerta.status.value, destino.value, [s.value for s in permitidas]
        )

    anterior = alerta.status
    alerta.status = destino
    alerta.triaged_by_id = ctx.actor_id
    alerta.triaged_at = datetime.now(UTC)
    alerta.triage_note = (
        f"Triado a partir da recomendação {rec.kind.value} "
        f"(confiança {rec.confidence}/100)."
    )

    await audit.record(
        session,
        ctx,
        action="TRIAR_ALERTA",
        resource_type="alerta",
        resource_id=alerta.id,
        resource_reference=alerta.reference,
        description=(
            f"Alerta {alerta.reference}: {anterior.value} -> {destino.value} "
            f"por aplicação de recomendação."
        ),
        old_value={"estado": anterior.value},
        new_value={"estado": destino.value},
        changed_fields=["status"],
    )
    return True, f"Alerta {alerta.reference} passou de {anterior.value} a {destino.value}."


async def _aplicar_promocao(
    session: AsyncSession, ctx: AuditContext, rec: Recommendation
) -> tuple[bool, str]:
    from app.services import incident_service

    alerta = await _carregar_alerta(session, rec)
    severidade = Severity(rec.proposed_change["severidade"])
    incidente = await incident_service.promote_alert(
        session,
        ctx,
        alert=alerta,
        severity=severidade,
        rationale=(
            f"Promovido por aplicação da recomendação {rec.kind.value} "
            f"(confiança {rec.confidence}/100): {rec.explanation}"
        ),
    )
    return True, f"Criado o incidente {incidente.reference} a partir de {alerta.reference}."


#: Campos que uma recomendação pode alterar, por tipo de alvo, com o conversor
#: do valor e a permissão exigida. Lista branca explícita: sem ela, uma
#: proposta malformada poderia escrever em qualquer coluna do modelo.
_CAMPOS_ALERTA: dict[str, tuple[type, Permission]] = {
    "severity": (Severity, Permission.ALERTS_TRIAGE),
}
_CAMPOS_INCIDENTE: dict[str, tuple[type, Permission]] = {
    "severity": (Severity, Permission.INCIDENTS_UPDATE),
    "priority": (Priority, Permission.INCIDENTS_UPDATE),
    "category": (IncidentCategory, Permission.INCIDENTS_UPDATE),
}


async def _aplicar_campos(
    session: AsyncSession, ctx: AuditContext, rec: Recommendation, decisor: User
) -> tuple[bool, str]:
    """Aplica uma proposta de alteração de campos ao alerta ou ao incidente.

    Valida **tudo** antes de escrever **alguma coisa**. Uma proposta pode
    alterar mais do que um campo (severidade e prioridade movem-se juntas) e
    cada campo tem a sua permissão; escrever à medida que se percorre a lista
    deixaria o alvo meio alterado se o segundo campo fosse recusado — com a
    agravante de a auditoria só registar o que se tivesse conseguido escrever.
    """
    e_alerta = rec.target_type == engine.TARGET_ALERT
    alvo = (
        await _carregar_alerta(session, rec)
        if e_alerta
        else await _carregar_incidente(session, rec)
    )
    permitidos = _CAMPOS_ALERTA if e_alerta else _CAMPOS_INCIDENTE

    alteracoes = rec.proposed_change.get("alteracoes") or []
    if not alteracoes:
        return False, "Nada a aplicar."

    # 1ª passagem: valida campo a campo sem tocar no alvo.
    planeadas: list[tuple[str, object]] = []
    for alteracao in alteracoes:
        campo = alteracao.get("campo")
        if campo not in permitidos:
            raise ValidationError(
                f"O campo '{campo}' não é alterável por recomendação.",
                code="CAMPO_NAO_ALTERAVEL",
                details={"campos_permitidos": sorted(permitidos)},
            )
        conversor, exigida = permitidos[campo]
        if not _tem(decisor, exigida):
            await audit.record(
                session,
                ctx,
                action="APLICAR_RECOMENDACAO",
                resource_type="recomendacao",
                resource_id=rec.id,
                outcome=AuditOutcome.NEGADO,
                failure_reason=f"permissão em falta: {exigida.value}",
                description=(
                    f"Alteração de '{campo}' em {alvo.reference} recusada por falta de "
                    f"{exigida.value}."
                ),
            )
            return False, (
                f"Recomendação aceite, mas nenhuma alteração foi aplicada: alterar "
                f"'{campo}' exige a permissão '{exigida.value}'."
            )
        planeadas.append((campo, conversor(alteracao["para"])))

    # 2ª passagem: escreve, agora que se sabe que todas as alterações passam.
    anterior: dict[str, str] = {}
    novo: dict[str, str] = {}
    for campo, valor in planeadas:
        anterior[campo] = getattr(alvo, campo).value
        setattr(alvo, campo, valor)
        novo[campo] = valor.value

    await audit.record(
        session,
        ctx,
        action="ALTERAR_POR_RECOMENDACAO",
        resource_type="alerta" if e_alerta else "incidente",
        resource_id=alvo.id,
        resource_reference=alvo.reference,
        description=(
            f"{alvo.reference}: "
            + ", ".join(f"{c} {anterior[c]} -> {novo[c]}" for c in novo)
            + f" por aplicação de recomendação (confiança {rec.confidence}/100)."
        ),
        old_value=anterior,
        new_value=novo,
        changed_fields=sorted(novo),
    )
    return True, (
        f"{alvo.reference}: " + ", ".join(f"{c} passou a {novo[c]}" for c in novo) + "."
    )


async def _aplicar_transicao(
    session: AsyncSession, ctx: AuditContext, rec: Recommendation
) -> tuple[bool, str]:
    from app.services import incident_service

    incidente = await _carregar_incidente(session, rec)
    destino = IncidentStatus(rec.proposed_change["para"])
    await incident_service.transition(
        session,
        ctx,
        incident=incidente,
        new_status=destino,
        note=(
            f"Transição por aplicação da recomendação {rec.kind.value} "
            f"(confiança {rec.confidence}/100)."
        ),
    )
    return True, f"Incidente {incidente.reference} passou a {destino.value}."


async def _aplicar_tecnicas(
    session: AsyncSession, ctx: AuditContext, rec: Recommendation
) -> tuple[bool, str]:
    """Associa as técnicas propostas como **inferidas** (§11).

    A justificação de cada uma vem da evidência que a recomendação já carrega,
    e não de texto gerado no momento: é a mesma frase que o analista leu antes
    de aceitar.
    """
    incidente = await _carregar_incidente(session, rec)
    ids = rec.proposed_change.get("tecnicas") or []
    if not ids:
        return False, "Nada a aplicar."

    razoes = {
        d["tecnica"]: d
        for d in (rec.evidence_refs.get("tecnicas_propostas") or [])
        if isinstance(d, dict) and d.get("tecnica")
    }

    resultado = await session.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id.in_(ids))
    )
    tecnicas = list(resultado.scalars())
    if not tecnicas:
        raise ConflictError(
            "Nenhuma das técnicas propostas existe no catálogo ATT&CK carregado.",
            details={"tecnicas": ids},
        )

    criadas: list[str] = []
    for tecnica in tecnicas:
        ja_existe = await session.execute(
            select(IncidentTechnique).where(
                IncidentTechnique.incident_id == incidente.id,
                IncidentTechnique.technique_id == tecnica.id,
            )
        )
        if ja_existe.scalar_one_or_none() is not None:
            continue

        detalhe = razoes.get(tecnica.technique_id, {})
        session.add(
            IncidentTechnique(
                incident_id=incidente.id,
                technique_id=tecnica.id,
                is_asserted=False,
                confidence=Confidence.MEDIA if rec.confidence >= 60 else Confidence.BAIXA,
                rationale=(
                    f"Inferida pelo motor de recomendações a partir dos grupos de regra "
                    f"{', '.join(detalhe.get('grupos_de_regra', []))}. "
                    f"{detalhe.get('razao', '')} "
                    f"Aceite por decisão humana (confiança do motor {rec.confidence}/100)."
                ).strip(),
                evidence_refs={
                    "recomendacao": str(rec.id),
                    "grupos_de_regra": detalhe.get("grupos_de_regra", []),
                    "alertas": rec.evidence_refs.get("alertas", []),
                },
                created_by_id=ctx.actor_id,
            )
        )
        criadas.append(tecnica.technique_id)

    await session.flush()
    if not criadas:
        return False, "As técnicas propostas já estavam associadas ao incidente."

    await audit.record(
        session,
        ctx,
        action="ASSOCIAR_TECNICA_MITRE",
        resource_type="incidente",
        resource_id=incidente.id,
        resource_reference=incidente.reference,
        description=(
            f"Associadas como inferidas a {incidente.reference}: {', '.join(criadas)} "
            f"(recomendação com confiança {rec.confidence}/100)."
        ),
        new_value={"tecnicas": criadas, "afirmada": False},
        changed_fields=["techniques"],
    )
    return True, (
        f"Associada(s) a {incidente.reference} como inferida(s): {', '.join(criadas)}."
    )


async def _aplicar_playbook(
    session: AsyncSession, ctx: AuditContext, rec: Recommendation
) -> tuple[bool, str]:
    from app.playbooks import engine as playbook_engine

    incidente = await _carregar_incidente(session, rec)
    playbook_id = rec.proposed_change.get("playbook_id")
    playbook = await session.get(Playbook, uuid.UUID(str(playbook_id)))
    if playbook is None:
        raise NotFoundError("Playbook", playbook_id)

    execucao = await playbook_engine.start_execution(
        session, ctx, playbook=playbook, incident=incidente, triggered_automatically=False
    )
    return True, (
        f"Execução {execucao.reference} do playbook '{playbook.name}' iniciada "
        f"(estado: {execucao.status.value})."
    )


# ================================================== geração em massa (fila)
async def sincronizar_em_aberto(session: AsyncSession, *, limite: int = 200) -> dict:
    """Recalcula as recomendações do trabalho em aberto.

    Percorre os alertas por triar e os incidentes não encerrados. É o que uma
    tarefa periódica chamaria; por agora é invocado explicitamente pela API,
    para que a geração seja sempre uma acção com dono e registo, e não um
    processo de fundo cujo resultado ninguém sabe explicar.
    """
    from app.core.enums import ALERT_OPEN_STATUSES

    expiradas = await expirar_vencidas(session)

    alertas = await session.execute(
        select(Alert)
        .where(Alert.status.in_(list(ALERT_OPEN_STATUSES)))
        .order_by(Alert.triage_score.desc())
        .limit(limite)
    )
    incidentes = await session.execute(
        select(Incident)
        .where(
            Incident.status.notin_(
                [
                    IncidentStatus.ENCERRADO,
                    IncidentStatus.FALSO_POSITIVO,
                    IncidentStatus.DUPLICADO,
                ]
            )
        )
        .order_by(Incident.detected_at.desc())
        .limit(limite)
    )

    criadas_alertas = 0
    retiradas = expiradas
    for alerta in alertas.scalars():
        vigentes, saiu = await sincronizar_alerta(session, alerta)
        criadas_alertas += len(vigentes)
        retiradas += saiu

    criadas_incidentes = 0
    for incidente in incidentes.scalars():
        vigentes, saiu = await sincronizar_incidente(session, incidente)
        criadas_incidentes += len(vigentes)
        retiradas += saiu

    return {
        "recomendacoes_de_alertas": criadas_alertas,
        "recomendacoes_de_incidentes": criadas_incidentes,
        "retiradas_ou_expiradas": retiradas,
        "motor": engine.ENGINE_NAME,
        "versao": engine.ENGINE_VERSION,
    }


def kinds_disponiveis() -> list[str]:
    return [k.value for k in RecommendationKind]
