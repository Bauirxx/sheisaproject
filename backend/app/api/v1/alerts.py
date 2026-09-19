"""Rotas de alertas e eventos — /api/alerts, /api/events."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import (
    ALERT_STATES_REQUIRING_INCIDENT,
    ALERT_TRANSITIONS,
    AlertStatus,
    Severity,
    SourceKind,
)
from app.core.errors import NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.models.telemetry import Alert, Event
from app.schemas.alert import (
    AlertLink,
    AlertListItem,
    AlertPromote,
    AlertRead,
    AlertTriage,
    EventDetail,
    EventRead,
)
from app.schemas.common import MessageResponse
from app.schemas.incident import IncidentRead
from app.services import incident_service

router = APIRouter(prefix="/alerts", tags=["Alertas"])
events_router = APIRouter(prefix="/events", tags=["Eventos"])

#: Estados que só a promoção e a ligação podem dar, porque são elas que criam o
#: incidente ou a ligação que lhes dá sentido. Pela triagem, o alerta ficava
#: "promovido" sem ter originado nada.
#: Alias histórico. A definição vive em `core.enums`, ao lado das transições,
#: para que todas as portas a partilhem em vez de cada uma ter a sua.
STATES_REQUIRING_INCIDENT = ALERT_STATES_REQUIRING_INCIDENT

SORTABLE = {
    "created_at", "last_event_at", "first_event_at", "triage_score",
    "severity", "status", "reference", "event_count", "false_positive_score",
}


async def _load_alert(session: AsyncSession, alert_id: uuid.UUID) -> Alert:
    result = await session.execute(
        select(Alert)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.incident))
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise NotFoundError("Alerta", alert_id)
    return alert


def _to_read(alert: Alert) -> AlertRead:
    payload = AlertRead.model_validate(alert)
    payload.transicoes_permitidas = sorted(
        s.value for s in ALERT_TRANSITIONS.get(alert.status, frozenset())
    )
    payload.incident_reference = alert.incident.reference if alert.incident else None
    return payload


@router.get(
    "",
    response_model=Page[AlertListItem],
    summary="Listar alertas",
    description=(
        "Fila de triagem. Por omissão ordenada por pontuação de triagem "
        "descendente, de modo a que o que exige atenção apareça primeiro."
    ),
)
async def list_alerts(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ALERTS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query(description="Pesquisa por referência, título ou regra.")] = None,
    estado: Annotated[list[AlertStatus] | None, Query()] = None,
    severidade: Annotated[list[Severity] | None, Query()] = None,
    fonte: Annotated[list[SourceKind] | None, Query()] = None,
    por_triar: Annotated[bool, Query(description="Apenas NOVO e EM_TRIAGEM.")] = False,
    sem_incidente: Annotated[bool, Query()] = False,
    incidente_id: Annotated[
        uuid.UUID | None,
        Query(description="Apenas os alertas ligados a este incidente."),
    ] = None,
    pontuacao_minima: Annotated[int | None, Query(ge=0, le=100)] = None,
    desde: Annotated[datetime | None, Query()] = None,
    ate: Annotated[datetime | None, Query()] = None,
) -> Page[AlertListItem]:
    stmt = select(Alert).options(selectinload(Alert.incident))

    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Alert.reference.ilike(pattern),
                Alert.title.ilike(pattern),
                Alert.rule_name.ilike(pattern),
                Alert.rule_id.ilike(pattern),
            )
        )
    if estado:
        stmt = stmt.where(Alert.status.in_(estado))
    if severidade:
        stmt = stmt.where(Alert.severity.in_(severidade))
    if fonte:
        stmt = stmt.where(Alert.source_kind.in_(fonte))
    if por_triar:
        stmt = stmt.where(Alert.status.in_([AlertStatus.NOVO, AlertStatus.EM_TRIAGEM]))
    if sem_incidente:
        stmt = stmt.where(Alert.incident_id.is_(None))
    if incidente_id is not None:
        # Complementa `sem_incidente`: permite reconstituir a composição de um
        # incidente a partir dos alertas que o originaram, que é o que a página
        # de detalhe precisa de mostrar.
        stmt = stmt.where(Alert.incident_id == incidente_id)
    if pontuacao_minima is not None:
        stmt = stmt.where(Alert.triage_score >= pontuacao_minima)
    if desde:
        stmt = stmt.where(Alert.last_event_at >= desde)
    if ate:
        stmt = stmt.where(Alert.last_event_at <= ate)

    stmt = apply_sort(stmt, Alert, params.sort, allowed=SORTABLE, default="-triage_score")
    items, total = await paginate(session, stmt, params)
    return Page.build([AlertListItem.model_validate(a) for a in items], total, params)


@router.get(
    "/{alert_id}",
    response_model=AlertRead,
    summary="Detalhe do alerta",
    description=(
        "Inclui a decomposição completa da pontuação de triagem: cada factor "
        "com os pontos que contribuiu e a razão pela qual contribuiu."
    ),
)
async def get_alert(
    alert_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ALERTS_READ))],
) -> AlertRead:
    return _to_read(await _load_alert(session, alert_id))


@router.get(
    "/{alert_id}/events",
    response_model=list[EventRead],
    summary="Eventos agregados no alerta",
)
async def alert_events(
    alert_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.EVENTS_READ))],
    limite: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[EventRead]:
    await _load_alert(session, alert_id)
    result = await session.execute(
        select(Event)
        .where(Event.alert_id == alert_id)
        .order_by(Event.occurred_at.desc())
        .limit(limite)
    )
    return [EventRead.model_validate(e) for e in result.scalars()]


@router.post(
    "/{alert_id}/triage",
    response_model=AlertRead,
    summary="Triar alerta",
    description=(
        "Regista a decisão de triagem. Marcar como falso positivo alimenta o "
        "histórico que o motor usa para estimar o ruído de cada regra."
    ),
)
async def triage_alert(
    alert_id: uuid.UUID,
    payload: AlertTriage,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ALERTS_TRIAGE))],
) -> AlertRead:
    alert = await _load_alert(session, alert_id)
    current = alert.status

    if payload.status in STATES_REQUIRING_INCIDENT:
        raise ValidationError(
            f"Um alerta só fica {payload.status.value} ao ser promovido ou ligado a um "
            f"incidente: use POST /api/alerts/{alert.id}/promote ou /link.",
            code="ESTADO_EXIGE_INCIDENTE",
        )

    allowed = ALERT_TRANSITIONS.get(current, frozenset())
    if payload.status not in allowed:
        from app.core.errors import InvalidTransitionError

        raise InvalidTransitionError(
            current.value, payload.status.value, [s.value for s in allowed]
        )

    if payload.status == AlertStatus.DUPLICADO:
        if payload.duplicate_of_id is None:
            raise ValidationError(
                "Marcar como duplicado exige indicar o alerta original.",
                code="ORIGINAL_OBRIGATORIO",
            )
        original = await session.get(Alert, payload.duplicate_of_id)
        if original is None:
            raise NotFoundError("Alerta original", payload.duplicate_of_id)
        if original.id == alert.id:
            raise ValidationError("Um alerta não pode ser duplicado de si próprio.")
        alert.duplicate_of_id = original.id

    alert.status = payload.status
    alert.triaged_by_id = ctx.actor_id
    alert.triaged_at = datetime.now(UTC)
    if payload.note:
        alert.triage_note = payload.note

    await audit.record(
        session, ctx,
        action="TRIAR_ALERTA", resource_type="alerta",
        resource_id=alert.id, resource_reference=alert.reference,
        description=(
            f"Alerta {alert.reference}: {current.value} -> {payload.status.value}."
            + (f" {payload.note}" if payload.note else "")
        ),
        old_value={"estado": current.value},
        new_value={"estado": payload.status.value},
        changed_fields=["status"],
    )
    return _to_read(alert)


@router.post(
    "/{alert_id}/promote",
    response_model=IncidentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Promover alerta a incidente",
    description=(
        "Cria um incidente a partir do alerta, materializando as observações e "
        "importando as técnicas MITRE declaradas pela fonte."
    ),
)
async def promote_alert(
    alert_id: uuid.UUID,
    payload: AlertPromote,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ALERTS_PROMOTE))],
) -> IncidentRead:
    from app.api.v1.incidents import _to_read as incident_to_read

    alert = await _load_alert(session, alert_id)
    incident = await incident_service.promote_alert(
        session, ctx,
        alert=alert,
        title=payload.title,
        category=payload.category,
        severity=payload.severity,
        assignee_id=payload.assignee_id,
        rationale=payload.rationale,
        confidence=payload.confidence,
    )
    await session.flush()
    incident = await incident_service.get_incident(session, incident.id, with_details=True)
    return await incident_to_read(session, incident)


@router.post(
    "/{alert_id}/link",
    response_model=MessageResponse,
    summary="Ligar alerta a um incidente existente",
)
async def link_alert(
    alert_id: uuid.UUID,
    payload: AlertLink,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ALERTS_PROMOTE))],
) -> MessageResponse:
    alert = await _load_alert(session, alert_id)
    incident = await incident_service.get_incident(session, payload.incident_id)
    observations = await incident_service.link_alert(
        session, ctx, alert=alert, incident=incident, rationale=payload.rationale
    )
    return MessageResponse(
        mensagem=(
            f"Alerta {alert.reference} ligado a {incident.reference}. "
            f"{observations} observação(ões) registada(s)."
        )
    )


@router.post(
    "/{alert_id}/rescore",
    response_model=AlertRead,
    summary="Recalcular a pontuação de triagem",
    description=(
        "Reexecuta o motor determinístico. Útil depois de classificar um "
        "indicador ou de registar um activo: a pontuação passa a reflectir o "
        "contexto actualizado."
    ),
)
async def rescore_alert(
    alert_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ALERTS_TRIAGE))],
) -> AlertRead:
    from app.intelligence.triage import score_alert

    alert = await _load_alert(session, alert_id)
    previous = alert.triage_score
    outcome = await score_alert(session, alert)

    await audit.record(
        session, ctx,
        action="RECALCULAR_TRIAGEM", resource_type="alerta",
        resource_id=alert.id, resource_reference=alert.reference,
        description=(
            f"Pontuação de {alert.reference} recalculada: {previous} -> {outcome.score}."
        ),
        old_value={"pontuacao": previous},
        new_value={"pontuacao": outcome.score},
        changed_fields=["triage_score"],
    )
    return _to_read(alert)


# --------------------------------------------------------------------- eventos
@events_router.get(
    "",
    response_model=Page[EventRead],
    summary="Listar eventos brutos",
    description="Sinais recebidos das fontes, antes da agregação em alertas.",
)
async def list_events(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.EVENTS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    fonte: Annotated[list[SourceKind] | None, Query()] = None,
    severidade: Annotated[list[Severity] | None, Query()] = None,
    alerta_id: Annotated[uuid.UUID | None, Query()] = None,
    ip: Annotated[str | None, Query(description="IP de origem ou destino.")] = None,
    host: Annotated[str | None, Query()] = None,
    desde: Annotated[datetime | None, Query()] = None,
    ate: Annotated[datetime | None, Query()] = None,
) -> Page[EventRead]:
    stmt = select(Event)
    if fonte:
        stmt = stmt.where(Event.source_kind.in_(fonte))
    if severidade:
        stmt = stmt.where(Event.severity.in_(severidade))
    if alerta_id:
        stmt = stmt.where(Event.alert_id == alerta_id)
    if ip:
        stmt = stmt.where(or_(Event.source_ip == ip, Event.destination_ip == ip))
    if host:
        stmt = stmt.where(Event.host.ilike(f"%{host}%"))
    if desde:
        stmt = stmt.where(Event.occurred_at >= desde)
    if ate:
        stmt = stmt.where(Event.occurred_at <= ate)

    stmt = apply_sort(
        stmt, Event, params.sort,
        allowed={"occurred_at", "received_at", "created_at", "severity"},
        default="-occurred_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([EventRead.model_validate(e) for e in items], total, params)


@events_router.get(
    "/{event_id}",
    response_model=EventDetail,
    summary="Detalhe do evento, com o payload original",
    description=(
        "Inclui o payload tal como a fonte o enviou. Permite confrontar "
        "qualquer valor apresentado com o que foi efectivamente recebido."
    ),
)
async def get_event(
    event_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.EVENTS_READ))],
) -> EventDetail:
    event = await session.get(Event, event_id)
    if event is None:
        raise NotFoundError("Evento", event_id)
    return EventDetail.model_validate(event)
