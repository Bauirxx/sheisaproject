"""Serviço de incidentes: criação, promoção, transições e relações (§7, §20).

O ciclo de vida é validado contra `INCIDENT_TRANSITIONS`. Qualquer transição
não declarada é recusada — pela interface e por chamada directa à API. Isto
importa porque um incidente que salte de NOVO para ENCERRADO sem passar por
investigação destrói a reconstituição exigida pelo §31.

Os marcos temporais são preenchidos automaticamente na transição correspondente
(`contained_at` ao entrar em CONTENÇÃO, `resolved_at` em RESOLVIDO, ...). Deixar
isso ao utilizador tornaria as métricas de resposta do §17 dependentes de
disciplina humana, ou seja, pouco fiáveis.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import (
    ALERT_TRANSITIONS,
    INCIDENT_TRANSITIONS,
    AlertStatus,
    Confidence,
    CorrelationOutcome,
    IncidentCategory,
    IncidentOrigin,
    IncidentStatus,
    IocType,
    ObservationRole,
    Priority,
    RelationType,
    Severity,
    SourceKind,
)
from app.core.errors import (
    ConflictError,
    InvalidTransitionError,
    NotFoundError,
    ValidationError,
)
from app.core.references import ReferenceKind, next_reference
from app.correlation.engine import LINKABLE_STATUSES, CorrelationDecision
from app.models.catalog import Asset, Ioc
from app.models.incident import Incident, IncidentRelation, IncidentTechnique
from app.models.investigation import Comment, Observation
from app.models.telemetry import Alert, Event

#: "Este campo não veio no pedido" — distinto de vir a `null`, que significa
#: retirar. Sem esta distinção, atribuir só a equipa (`{"team_id": ...}`)
#: apagava o responsável, porque o campo ausente chegava como `None`.
NAO_ALTERAR: object = object()

#: Prazo de resposta por severidade, em horas. Base do campo `due_at` e dos
#: indicadores de cumprimento do painel.
SLA_HOURS: dict[Severity, int] = {
    Severity.CRITICA: 4,
    Severity.ALTA: 8,
    Severity.MEDIA: 24,
    Severity.BAIXA: 72,
    Severity.INFO: 168,
}

#: Prioridade sugerida a partir da severidade. O analista pode alterá-la — a
#: severidade descreve o impacto técnico, a prioridade é uma decisão operacional
#: que também pesa contexto de negócio.
SEVERITY_TO_PRIORITY: dict[Severity, Priority] = {
    Severity.CRITICA: Priority.P1,
    Severity.ALTA: Priority.P2,
    Severity.MEDIA: Priority.P3,
    Severity.BAIXA: Priority.P4,
    Severity.INFO: Priority.P4,
}

#: Grupos de regras que sugerem uma categoria. Usado apenas como valor inicial;
#: a classificação final é sempre do analista.
GROUP_TO_CATEGORY: tuple[tuple[tuple[str, ...], IncidentCategory], ...] = (
    (("authentication_failed", "authentication_failures", "brute", "password"),
     IncidentCategory.TENTATIVA_INTRUSAO),
    (("malware", "virus", "trojan", "rootcheck", "ransomware"),
     IncidentCategory.CODIGO_MALICIOSO),
    (("intrusion", "exploit", "attack", "web_attack", "sql_injection"),
     IncidentCategory.INTRUSAO),
    (("recon", "scan", "portscan", "enumeration"),
     IncidentCategory.RECOLHA_INFORMACAO),
    (("dos", "ddos", "flood", "availability"),
     IncidentCategory.DISPONIBILIDADE),
    (("policy", "compliance", "config", "syscheck", "integrity"),
     IncidentCategory.SEGURANCA_INFORMACAO),
    (("vulnerability", "cve", "vulnerability-detector"),
     IncidentCategory.VULNERABILIDADE),
    (("phishing", "fraud", "spam"), IncidentCategory.FRAUDE),
)


def suggest_category(tags: list[str], rule_name: str | None = None) -> IncidentCategory:
    """Categoria sugerida a partir dos grupos de regra da fonte."""
    haystack = " ".join(tags).lower()
    if rule_name:
        haystack += " " + rule_name.lower()
    for markers, category in GROUP_TO_CATEGORY:
        if any(marker in haystack for marker in markers):
            return category
    return IncidentCategory.OUTRO


async def get_incident(
    session: AsyncSession, incident_id: uuid.UUID, *, with_details: bool = False
) -> Incident:
    stmt = select(Incident).where(Incident.id == incident_id)
    if with_details:
        stmt = stmt.options(
            selectinload(Incident.assets),
            selectinload(Incident.techniques).selectinload(IncidentTechnique.technique),
        )
    result = await session.execute(stmt)
    incident = result.scalar_one_or_none()
    if incident is None:
        raise NotFoundError("Incidente", incident_id)
    return incident


async def get_by_reference(session: AsyncSession, reference: str) -> Incident:
    result = await session.execute(
        select(Incident).where(Incident.reference == reference.upper())
    )
    incident = result.scalar_one_or_none()
    if incident is None:
        raise NotFoundError("Incidente", reference)
    return incident


def garantir_editavel(incident: Incident) -> None:
    """Recusa mutações de conteúdo num incidente encerrado.

    ENCERRADO é terminal — não tem transições de saída em `INCIDENT_TRANSITIONS`
    — e existe para preservar o registo histórico: campos, tarefas, observações
    e evidências deixam de poder mudar. Comentários continuam permitidos, porque
    são notas de auditoria posteriores e não alteram o que aconteceu. Para
    retomar o trabalho não se reabre este incidente (não é possível): cria-se um
    incidente relacionado, como no ciclo de vida.
    """
    if incident.status is IncidentStatus.ENCERRADO:
        raise ConflictError(
            f"O incidente {incident.reference} está encerrado: o seu registo é "
            "definitivo e não pode ser alterado. Para retomar o trabalho, crie "
            "um incidente relacionado.",
            code="INCIDENTE_ENCERRADO",
        )


async def create_incident(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    title: str,
    description: str = "",
    category: IncidentCategory = IncidentCategory.OUTRO,
    subtype: str | None = None,
    severity: Severity = Severity.MEDIA,
    priority: Priority | None = None,
    confidence: Confidence = Confidence.MEDIA,
    origin: IncidentOrigin = IncidentOrigin.REGISTO_MANUAL,
    source_kind: SourceKind = SourceKind.MANUAL,
    source_detail: str | None = None,
    detected_at: datetime | None = None,
    assignee_id: uuid.UUID | None = None,
    team_id: uuid.UUID | None = None,
    reporter_id: uuid.UUID | None = None,
    asset_ids: list[uuid.UUID] | None = None,
    affected_users: list[str] | None = None,
    tags: list[str] | None = None,
    is_demo: bool = False,
) -> Incident:
    """Cria um incidente e regista a criação na auditoria."""
    from app.core.lookups import require_all_existing, require_existing
    from app.models.identity import Team, User

    await require_existing(session, User, assignee_id, "Utilizador")
    await require_existing(session, Team, team_id, "Equipa")
    assets = await require_all_existing(session, Asset, asset_ids or [], "Activo")

    detected = detected_at or datetime.now(UTC)
    reference = await next_reference(session, ReferenceKind.INCIDENT)

    incident = Incident(
        reference=reference,
        title=title.strip()[:300],
        description=description,
        category=category,
        subtype=subtype,
        severity=severity,
        priority=priority or SEVERITY_TO_PRIORITY.get(severity, Priority.P3),
        status=IncidentStatus.NOVO,
        confidence=confidence,
        origin=origin,
        source_kind=source_kind,
        source_detail=source_detail,
        assignee_id=assignee_id,
        team_id=team_id,
        reporter_id=reporter_id or ctx.actor_id,
        detected_at=detected,
        due_at=detected + timedelta(hours=SLA_HOURS.get(severity, 24)),
        affected_users=affected_users or [],
        tags=tags or [],
        is_demo_data=is_demo,
    )

    if assets:
        incident.assets = assets

    session.add(incident)
    await session.flush()

    await audit.record(
        session, ctx,
        action="CRIAR_INCIDENTE", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=f"Incidente {reference} criado: {incident.title}",
        new_value={
            "titulo": incident.title,
            "categoria": incident.category.value,
            "severidade": incident.severity.value,
            "prioridade": incident.priority.value,
            "origem": incident.origin.value,
        },
    )
    return incident


async def materialise_observations(
    session: AsyncSession, incident: Incident, alert: Alert
) -> int:
    """Converte os indicadores guardados nos eventos do alerta em observações.

    É aqui que o avistamento ganha contexto de incidente. Os indicadores já
    existem como IOCs globais desde a ingestão; a observação acrescenta *onde*,
    *quando* e *em que papel* foram vistos nesta investigação (§20, §21).
    """
    result = await session.execute(
        select(Event.normalized_extra, Event.occurred_at, Event.asset_id)
        .where(Event.alert_id == alert.id)
        .limit(200)
    )

    # Deduplicamos por (tipo, valor, papel): o mesmo artefacto repetido em
    # dezenas de eventos é um avistamento, não dezenas.
    seen: dict[tuple[str, str, str], tuple[datetime, uuid.UUID | None, str]] = {}
    for extra, occurred_at, asset_id in result.all():
        for item in (extra or {}).get("indicadores", []):
            tipo, valor, papel = item.get("tipo"), item.get("valor"), item.get("papel")
            if not (tipo and valor and papel):
                continue
            key = (tipo, valor, papel)
            if key not in seen or occurred_at < seen[key][0]:
                seen[key] = (occurred_at, asset_id, item.get("contexto", ""))

    created = 0
    for (tipo, valor, papel), (occurred_at, asset_id, contexto) in seen.items():
        try:
            ioc_type = IocType(tipo)
            role = ObservationRole(papel)
        except ValueError:
            continue

        ioc_result = await session.execute(
            select(Ioc).where(Ioc.ioc_type == ioc_type, Ioc.value == valor)
        )
        ioc = ioc_result.scalar_one_or_none()
        if ioc is None:
            continue

        existing = await session.execute(
            select(Observation).where(
                Observation.incident_id == incident.id,
                Observation.ioc_id == ioc.id,
                Observation.role == role,
                Observation.alert_id == alert.id,
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue

        session.add(
            Observation(
                incident_id=incident.id,
                ioc_id=ioc.id,
                alert_id=alert.id,
                asset_id=asset_id,
                role=role,
                observed_at=occurred_at,
                context=contexto,
                confidence=Confidence.MEDIA,
                is_automatic=True,
            )
        )
        created += 1

    await session.flush()
    return created


def _require_alert_transition(alert: Alert, target: AlertStatus) -> None:
    """Promover e ligar também são transições do ciclo de vida do alerta.

    A triagem cumpria `ALERT_TRANSITIONS`; a promoção e a ligação não o
    consultavam. Um alerta DESCARTADO era promovido directamente, apagando a
    decisão de descarte que o motor usa para estimar o ruído da regra, e um
    alerta PROMOVIDO podia ser religado a outro incidente, saindo do que ele
    próprio originou.
    """
    allowed = ALERT_TRANSITIONS.get(alert.status, frozenset())
    if target not in allowed:
        raise InvalidTransitionError(
            alert.status.value, target.value, [s.value for s in allowed]
        )


async def link_alert(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    alert: Alert,
    incident: Incident,
    rationale: str = "",
) -> int:
    """Liga um alerta a um incidente existente e materializa as observações."""
    if alert.incident_id == incident.id:
        raise ConflictError(
            f"O alerta {alert.reference} já está ligado ao incidente "
            f"{incident.reference}."
        )
    _require_alert_transition(alert, AlertStatus.CORRELACIONADO)
    # O mesmo critério do motor de correlação, que já recusava fazê-lo sozinho.
    if incident.status not in LINKABLE_STATUSES:
        raise ConflictError(
            f"O incidente {incident.reference} está {incident.status.value}: "
            "ligar-lhe um alerta reescreveria um registo já concluído.",
            code="INCIDENTE_FECHADO",
        )

    alert.incident_id = incident.id
    alert.status = AlertStatus.CORRELACIONADO
    alert.correlated_at = datetime.now(UTC)
    if rationale:
        alert.correlation_rationale = rationale

    observations = await materialise_observations(session, incident, alert)

    # O incidente herda a severidade mais alta observada: um alerta crítico
    # ligado a um incidente médio eleva-o, nunca o contrário.
    if alert.severity.rank > incident.severity.rank:
        incident.severity = alert.severity
        incident.priority = SEVERITY_TO_PRIORITY.get(alert.severity, incident.priority)

    if alert.asset_id is not None:
        asset = await session.get(Asset, alert.asset_id)
        if asset is not None and asset not in incident.assets:
            incident.assets.append(asset)

    await audit.record(
        session, ctx,
        action="LIGAR_ALERTA", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=(
            f"Alerta {alert.reference} ligado ao incidente {incident.reference}. "
            f"{observations} observação(ões) registada(s). {rationale}".strip()
        ),
    )
    return observations


async def promote_alert(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    alert: Alert,
    title: str | None = None,
    category: IncidentCategory | None = None,
    severity: Severity | None = None,
    assignee_id: uuid.UUID | None = None,
    rationale: str = "",
    confidence: Confidence = Confidence.MEDIA,
    origin: IncidentOrigin = IncidentOrigin.PROMOCAO_ALERTA,
    is_demo: bool = False,
) -> Incident:
    """Cria um incidente a partir de um alerta (§6).

    A promoção é uma decisão, não um automatismo: um alerta que se torna
    incidente passou por triagem, humana ou por regra de correlação explícita.
    """
    if alert.status == AlertStatus.PROMOVIDO and alert.incident_id:
        raise ConflictError(
            f"O alerta {alert.reference} já originou um incidente.",
            details={"incidente_id": str(alert.incident_id)},
        )
    _require_alert_transition(alert, AlertStatus.PROMOVIDO)

    incident = await create_incident(
        session, ctx,
        title=title or alert.title,
        description=alert.description or alert.title,
        category=category or suggest_category(alert.tags, alert.rule_name),
        severity=severity or alert.severity,
        confidence=confidence,
        origin=origin,
        source_kind=alert.source_kind,
        source_detail=f"{alert.source_name} / regra {alert.rule_id or '-'}",
        detected_at=alert.first_event_at,
        assignee_id=assignee_id,
        asset_ids=[alert.asset_id] if alert.asset_id else None,
        tags=list(alert.tags),
        is_demo=is_demo,
    )

    alert.incident_id = incident.id
    alert.status = AlertStatus.PROMOVIDO
    alert.correlated_at = datetime.now(UTC)
    alert.triaged_by_id = ctx.actor_id
    alert.triaged_at = datetime.now(UTC)
    if rationale:
        alert.triage_note = rationale

    observations = await materialise_observations(session, incident, alert)

    # As técnicas declaradas pela fonte entram como afirmadas, não inferidas:
    # foi a ferramenta de detecção que as reportou (§11).
    techniques = await _import_reported_techniques(session, incident, alert)

    await audit.record(
        session, ctx,
        action="PROMOVER_ALERTA", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=(
            f"Alerta {alert.reference} promovido a incidente {incident.reference}. "
            f"{observations} observação(ões), {techniques} técnica(s) MITRE. {rationale}"
        ).strip(),
    )
    return incident


async def _import_reported_techniques(
    session: AsyncSession, incident: Incident, alert: Alert
) -> int:
    """Importa as técnicas MITRE que a própria fonte declarou."""
    from app.services.mitre_service import find_techniques

    result = await session.execute(
        select(Event.reported_techniques).where(Event.alert_id == alert.id).limit(100)
    )
    ids: set[str] = set()
    for (techniques,) in result.all():
        ids.update(t for t in (techniques or []) if t)

    if not ids:
        return 0

    found = await find_techniques(session, sorted(ids))
    created = 0
    for technique_id, technique in found.items():
        existing = await session.execute(
            select(IncidentTechnique).where(
                IncidentTechnique.incident_id == incident.id,
                IncidentTechnique.technique_id == technique.id,
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue
        session.add(
            IncidentTechnique(
                incident_id=incident.id,
                technique_id=technique.id,
                is_asserted=True,
                confidence=Confidence.ALTA,
                rationale=(
                    f"Técnica declarada pela regra {alert.rule_id or '-'} da fonte "
                    f"{alert.source_kind.value}."
                ),
                evidence_refs={"alerta": alert.reference, "tecnica": technique_id},
            )
        )
        created += 1
    await session.flush()
    return created


async def apply_correlation(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    alert: Alert,
    decision: CorrelationDecision,
    is_demo: bool = False,
) -> Incident | None:
    """Aplica a decisão do motor de correlação a um alerta."""
    alert.correlation_outcome = decision.outcome
    alert.correlation_rationale = decision.rationale
    alert.correlated_at = datetime.now(UTC)
    if decision.rule is not None:
        alert.correlation_rule_id = decision.rule.id

    if decision.outcome == CorrelationOutcome.LIGADO_A_INCIDENTE:
        incident = await get_incident(session, decision.incident_id)
        await link_alert(
            session, ctx, alert=alert, incident=incident, rationale=decision.rationale
        )
        return incident

    if decision.outcome == CorrelationOutcome.NOVO_INCIDENTE:
        rule = decision.rule
        title = (
            rule.incident_title_template if rule else "Actividade correlacionada"
        )
        category = None
        if rule and rule.resulting_category:
            try:
                category = IncidentCategory(rule.resulting_category)
            except ValueError:
                category = None

        incident = await promote_alert(
            session, ctx,
            alert=alert,
            title=f"{title}: {alert.title}"[:300],
            category=category,
            severity=decision.suggested_severity,
            rationale=decision.rationale,
            origin=IncidentOrigin.CORRELACAO,
            is_demo=is_demo,
        )

        # Os alertas correlacionados juntam-se ao mesmo incidente.
        for alert_id in decision.related_alert_ids:
            related = await session.get(Alert, alert_id)
            if related is None or related.incident_id is not None:
                continue
            await link_alert(
                session, ctx,
                alert=related, incident=incident,
                rationale=f"Correlacionado com {alert.reference}.",
            )
        return incident

    return None


#: Início do comentário de sistema que cada mudança de estado deixa no incidente.
#:
#: É uma constante porque a linha temporal o usa para não mostrar a mudança duas
#: vezes (uma como comentário, outra como auditoria). Se o texto fosse repetido
#: nos dois sítios e alguém o alterasse só num, a duplicação voltava em silêncio;
#: `tests/test_linha_temporal.py` apanharia, mas assim nem chega a acontecer.
PREFIXO_COMENTARIO_DE_TRANSICAO = "Estado alterado de "


async def transition(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    incident: Incident,
    new_status: IncidentStatus,
    note: str | None = None,
    resolution_summary: str | None = None,
    false_positive_reason: str | None = None,
    escalar_para_equipa: uuid.UUID | None | object = NAO_ALTERAR,
    escalar_para_responsavel: uuid.UUID | None | object = NAO_ALTERAR,
) -> Incident:
    """Altera o estado do incidente, validando contra o ciclo de vida.

    Ao escalar, pode indicar-se a equipa e/ou a pessoa que passa a responder —
    "escalar para a equipa de N2" numa só acção. Só é aceite com `ESCALADO`:
    noutras transições a atribuição faz-se pela rota própria.
    """
    alvo_indicado = (
        escalar_para_equipa is not NAO_ALTERAR or escalar_para_responsavel is not NAO_ALTERAR
    )
    if alvo_indicado and new_status != IncidentStatus.ESCALADO:
        raise ValidationError(
            "Só se indica equipa ou responsável na transição quando se escala.",
            code="ALVO_SO_AO_ESCALAR",
        )
    current = incident.status
    if new_status == current:
        raise ConflictError(f"O incidente já está em {current.value}.")

    allowed = INCIDENT_TRANSITIONS.get(current, frozenset())
    if new_status not in allowed:
        raise InvalidTransitionError(
            current.value, new_status.value, [s.value for s in allowed]
        )

    if new_status == IncidentStatus.FALSO_POSITIVO and not false_positive_reason:
        # Sem o motivo, o detector de falsos positivos não aprende nada com
        # esta decisão — e é dela que depende o §36.
        raise ValidationError(
            "Marcar como falso positivo exige indicar o motivo.",
            code="MOTIVO_OBRIGATORIO",
        )
    if new_status == IncidentStatus.RESOLVIDO and not (
        resolution_summary or incident.resolution_summary
    ):
        raise ValidationError(
            "Resolver um incidente exige um resumo da resolução.",
            code="RESUMO_OBRIGATORIO",
        )

    now = datetime.now(UTC)
    incident.status = new_status

    # Marcos temporais: preenchidos uma única vez, na primeira passagem.
    if incident.acknowledged_at is None and new_status in (
        IncidentStatus.TRIAGEM, IncidentStatus.INVESTIGACAO, IncidentStatus.ABERTO
    ):
        incident.acknowledged_at = now
    if new_status == IncidentStatus.CONTENCAO and incident.contained_at is None:
        incident.contained_at = now
    if new_status == IncidentStatus.ERRADICACAO and incident.eradicated_at is None:
        incident.eradicated_at = now
    if new_status == IncidentStatus.RESOLVIDO:
        incident.resolved_at = now
        if resolution_summary:
            incident.resolution_summary = resolution_summary
    if new_status == IncidentStatus.ENCERRADO:
        incident.closed_at = now
        if incident.resolved_at is None:
            incident.resolved_at = now
    if new_status == IncidentStatus.FALSO_POSITIVO:
        incident.false_positive_reason = false_positive_reason
        incident.closed_at = now
        await _mark_alerts_false_positive(session, incident)

    session.add(
        Comment(
            incident_id=incident.id,
            author_id=ctx.actor_id,
            body=(
                f"{PREFIXO_COMENTARIO_DE_TRANSICAO}{current.value} para {new_status.value}."
                + (f" {note}" if note else "")
            ),
            is_system=True,
        )
    )

    await audit.record(
        session, ctx,
        action="ALTERAR_ESTADO", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=(
            f"Estado de {incident.reference}: {current.value} -> {new_status.value}."
            + (f" {note}" if note else "")
        ),
        old_value={"estado": current.value},
        new_value={"estado": new_status.value},
        changed_fields=["status"],
    )

    # Escalar avisa quem passa a responder — o responsável e toda a equipa —, na
    # plataforma e por email: é o sinal de que o caso precisa de mais mãos, e
    # não pode depender de alguém estar com a plataforma aberta.
    if new_status == IncidentStatus.ESCALADO:
        from app.core.enums import NotificationKind
        from app.models.identity import Team, User
        from app.services import aviso_service

        if alvo_indicado:
            # Sem aviso próprio: o aviso de escalamento, abaixo, cobre as mesmas
            # pessoas, e duas mensagens pelo mesmo acontecimento seriam ruído.
            await assign(
                session, ctx, incident=incident,
                assignee_id=escalar_para_responsavel, team_id=escalar_para_equipa,
                avisar=False,
            )
        equipa = await session.get(Team, incident.team_id) if incident.team_id else None
        responsavel = (
            await session.get(User, incident.assignee_id) if incident.assignee_id else None
        )
        membros = await aviso_service.membros_activos(session, incident.team_id)
        destino = f" para a equipa {equipa.name}" if equipa else ""
        await aviso_service.avisar(
            session, ctx,
            incidente=incident, destinatarios=[responsavel, *membros],
            kind=NotificationKind.INCIDENTE_ESCALADO,
            titulo=f"Incidente escalado{destino}",
            motivo=f"Foi escalado{destino} o incidente",
            equipa=equipa, responsavel=responsavel,
        )
    return incident


async def _mark_alerts_false_positive(
    session: AsyncSession, incident: Incident
) -> None:
    """Propaga a decisão de falso positivo aos alertas de origem.

    É esta propagação que alimenta o factor histórico do motor de triagem: sem
    ela, a plataforma nunca aprenderia que uma regra é ruidosa.
    """
    result = await session.execute(
        select(Alert).where(Alert.incident_id == incident.id)
    )
    for alert in result.scalars():
        alert.status = AlertStatus.FALSO_POSITIVO
        if alert.correlation_rule_id is not None:
            from app.models.telemetry import CorrelationRule

            rule = await session.get(CorrelationRule, alert.correlation_rule_id)
            if rule is not None:
                rule.false_positive_count += 1


async def assign(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    incident: Incident,
    assignee_id: uuid.UUID | None | object = NAO_ALTERAR,
    team_id: uuid.UUID | None | object = NAO_ALTERAR,
    avisar: bool = True,
) -> Incident:
    """Atribui responsável e/ou equipa, e avisa quem passou a responder.

    Só muda o que vier explicitamente: `NAO_ALTERAR` deixa o campo como está,
    `None` retira-o. Avisa (na plataforma e por email) a pessoa que passou a ser
    responsável e os membros activos da equipa que passou a ter o incidente.
    `avisar=False` é para quem vai avisar a seguir por outro motivo — o
    escalamento — e não quer mandar duas mensagens pelo mesmo acontecimento.
    """
    from app.core.enums import NotificationKind
    from app.core.lookups import require_existing
    from app.models.identity import Team, User
    from app.services import aviso_service

    garantir_editavel(incident)
    muda_responsavel = assignee_id is not NAO_ALTERAR
    muda_equipa = team_id is not NAO_ALTERAR

    if muda_responsavel:
        await require_existing(session, User, assignee_id, "Utilizador")
    if muda_equipa and team_id is not None:
        await require_existing(session, Team, team_id, "Equipa")
        equipa_nova = await session.get(Team, team_id)
        if equipa_nova is not None and not equipa_nova.is_active:
            raise ValidationError(
                f"A equipa '{equipa_nova.name}' está desactivada e não pode receber "
                "incidentes.",
                code="EQUIPA_INACTIVA",
            )

    responsavel_antes = incident.assignee_id
    equipa_antes = incident.team_id
    if muda_responsavel:
        incident.assignee_id = assignee_id
    if muda_equipa:
        incident.team_id = team_id
    if incident.acknowledged_at is None and incident.assignee_id is not None:
        incident.acknowledged_at = datetime.now(UTC)

    alterados = [
        campo for campo, muda in (("assignee_id", muda_responsavel), ("team_id", muda_equipa))
        if muda
    ]
    await audit.record(
        session, ctx,
        action="ATRIBUIR_INCIDENTE", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=f"Atribuição de {incident.reference} alterada.",
        old_value={
            "responsavel": str(responsavel_antes) if responsavel_antes else None,
            "equipa": str(equipa_antes) if equipa_antes else None,
        },
        new_value={
            "responsavel": str(incident.assignee_id) if incident.assignee_id else None,
            "equipa": str(incident.team_id) if incident.team_id else None,
        },
        changed_fields=alterados,
    )

    if avisar:
        novo_responsavel = (
            await session.get(User, incident.assignee_id)
            if muda_responsavel and incident.assignee_id
            and incident.assignee_id != responsavel_antes
            else None
        )
        equipa = await session.get(Team, incident.team_id) if incident.team_id else None
        nova_equipa = (
            equipa if muda_equipa and incident.team_id and incident.team_id != equipa_antes
            else None
        )
        responsavel_actual = (
            await session.get(User, incident.assignee_id) if incident.assignee_id else None
        )
        if novo_responsavel is not None:
            await aviso_service.avisar(
                session, ctx,
                incidente=incident, destinatarios=[novo_responsavel],
                kind=NotificationKind.INCIDENTE_ATRIBUIDO,
                titulo="Incidente atribuído a si",
                motivo="Foi-lhe atribuído o incidente",
                equipa=equipa, responsavel=responsavel_actual,
            )
        if nova_equipa is not None:
            membros = await aviso_service.membros_activos(session, nova_equipa.id)
            # Quem já foi avisado como responsável não recebe segunda mensagem.
            if novo_responsavel is not None:
                membros = [m for m in membros if m.id != novo_responsavel.id]
            await aviso_service.avisar(
                session, ctx,
                incidente=incident, destinatarios=membros,
                kind=NotificationKind.INCIDENTE_ATRIBUIDO,
                titulo=f"Incidente atribuído à equipa {nova_equipa.name}",
                motivo=f"A sua equipa ({nova_equipa.name}) recebeu o incidente",
                equipa=nova_equipa, responsavel=responsavel_actual,
            )

    # `assignee` e `team` são carregados com a consulta (`lazy="selectin"`), pelo
    # que alterar a chave estrangeira não actualiza o objecto já em memória. Sem
    # este refresh, a resposta à atribuição devolvia `assignee: null` logo a
    # seguir a atribuir, e a interface mostraria "sem responsável" ao utilizador
    # que acabara de o escolher.
    #
    # O refresh é total e não limitado a `["assignee", "team"]`: o flush emite o
    # UPDATE, que dispara o `onupdate` de `updated_at` no servidor e deixa essa
    # coluna expirada. Lê-la mais tarde, já durante a serialização da resposta,
    # seria um acesso à base de dados fora do contexto assíncrono — o erro
    # `MissingGreenlet`. Recarregar tudo de uma vez deixa o objecto completo.
    await session.flush()
    await session.refresh(incident)
    return incident


async def relate(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    source: Incident,
    target: Incident,
    relation_type: RelationType,
    rationale: str = "",
    created_by_engine: bool = False,
    confidence: Confidence = Confidence.MEDIA,
) -> IncidentRelation:
    """Cria uma aresta tipada entre dois incidentes (§20).

    Ao contrário do merge do RTIR, nada é destruído: ambos os incidentes
    continuam a existir com o seu histórico. Um duplicado permanece consultável.
    """
    if source.id == target.id:
        raise ValidationError("Um incidente não pode ser relacionado consigo próprio.")

    existing = await session.execute(
        select(IncidentRelation).where(
            IncidentRelation.source_incident_id == source.id,
            IncidentRelation.target_incident_id == target.id,
            IncidentRelation.relation_type == relation_type,
        )
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError("Esta relação já existe.")

    relation = IncidentRelation(
        source_incident_id=source.id,
        target_incident_id=target.id,
        relation_type=relation_type,
        rationale=rationale,
        created_by_engine=created_by_engine,
        confidence=confidence,
        created_by_id=ctx.actor_id,
    )
    session.add(relation)

    if relation_type == RelationType.DUPLICADO_DE:
        # Marcar como duplicado é uma transição de estado real, não uma
        # etiqueta: o incidente sai da fila operacional.
        if IncidentStatus.DUPLICADO in INCIDENT_TRANSITIONS.get(source.status, frozenset()):
            source.status = IncidentStatus.DUPLICADO

    await session.flush()
    await audit.record(
        session, ctx,
        action="RELACIONAR_INCIDENTES", resource_type="incidente",
        resource_id=source.id, resource_reference=source.reference,
        description=(
            f"{source.reference} {relation_type.value} {target.reference}. {rationale}"
        ).strip(),
    )
    return relation


async def add_comment(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    incident: Incident,
    body: str,
    is_internal: bool = False,
) -> Comment:
    comment = Comment(
        incident_id=incident.id,
        author_id=ctx.actor_id,
        body=body.strip(),
        is_internal=is_internal,
        is_system=False,
    )
    session.add(comment)
    await session.flush()

    await audit.record(
        session, ctx,
        action="COMENTAR", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=f"Comentário adicionado a {incident.reference}.",
    )
    return comment
