"""Rotas de incidentes — /api/incidents."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import (
    INCIDENT_TRANSITIONS,
    ActionStatus,
    IncidentCategory,
    IncidentStatus,
    Priority,
    Severity,
    TaskStatus,
)
from app.core.errors import NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.models.incident import Incident, IncidentRelation, IncidentTechnique
from app.models.investigation import Comment, Evidence, Observation, Task
from app.models.response import Action
from app.models.telemetry import Alert
from app.schemas.common import MessageResponse
from app.schemas.incident import (
    CommentCreate,
    CommentRead,
    IncidentAssign,
    IncidentCreate,
    IncidentListItem,
    IncidentMetrics,
    IncidentRead,
    IncidentRelate,
    IncidentRelationRead,
    IncidentTechniqueRead,
    IncidentTimelineEntry,
    IncidentTransition,
    IncidentUpdate,
    ObservationCreate,
    ObservationRead,
    TechniqueAssign,
)
from app.services import incident_service

router = APIRouter(prefix="/incidents", tags=["Incidentes"])

#: Campos por que é permitido ordenar. Lista branca deliberada: aceitar um nome
#: de coluna arbitrário do cliente permitiria inferir conteúdo de colunas
#: sensíveis pela ordem devolvida.
SORTABLE = {
    "created_at", "updated_at", "detected_at", "resolved_at", "due_at",
    "severity", "priority", "status", "risk_score", "reference", "title",
}


async def _build_metrics(session: AsyncSession, incident: Incident) -> IncidentMetrics:
    """Métricas calculadas a partir de contagens reais."""
    counts = await session.execute(
        select(
            select(func.count()).select_from(Alert)
            .where(Alert.incident_id == incident.id).scalar_subquery(),
            select(func.count()).select_from(Observation)
            .where(Observation.incident_id == incident.id).scalar_subquery(),
            select(func.count()).select_from(Evidence)
            .where(Evidence.incident_id == incident.id).scalar_subquery(),
            select(func.count()).select_from(Task)
            .where(Task.incident_id == incident.id).scalar_subquery(),
            select(func.count()).select_from(Task)
            .where(Task.incident_id == incident.id,
                   Task.status == TaskStatus.CONCLUIDA).scalar_subquery(),
            select(func.count()).select_from(Action)
            .where(Action.incident_id == incident.id,
                   Action.status == ActionStatus.EXECUTADA).scalar_subquery(),
        )
    )
    alerts, observations, evidence, tasks, done, actions = counts.one()

    within_sla: bool | None = None
    if incident.due_at is not None:
        reference_moment = incident.resolved_at or datetime.now(incident.due_at.tzinfo)
        within_sla = reference_moment <= incident.due_at

    contained = (
        int((incident.contained_at - incident.detected_at).total_seconds())
        if incident.contained_at
        else None
    )

    return IncidentMetrics(
        tempo_ate_reconhecimento_segundos=incident.time_to_acknowledge_seconds,
        tempo_ate_contencao_segundos=contained,
        tempo_ate_resolucao_segundos=incident.time_to_resolve_seconds,
        dentro_do_prazo=within_sla,
        alertas_associados=alerts,
        observacoes=observations,
        evidencias=evidence,
        tarefas_totais=tasks,
        tarefas_concluidas=done,
        accoes_executadas=actions,
    )


def _allowed_transitions(incident: Incident) -> list[str]:
    return sorted(s.value for s in INCIDENT_TRANSITIONS.get(incident.status, frozenset()))


async def _to_read(session: AsyncSession, incident: Incident) -> IncidentRead:
    payload = IncidentRead.model_validate(incident)
    payload.transicoes_permitidas = _allowed_transitions(incident)
    payload.metricas = await _build_metrics(session, incident)
    return payload


# --------------------------------------------------------------------- listar
@router.get(
    "",
    response_model=Page[IncidentListItem],
    summary="Listar incidentes",
    description=(
        "Listagem paginada com filtros e pesquisa textual. A pesquisa incide "
        "sobre a referência, o título e a descrição."
    ),
)
async def list_incidents(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query(description="Pesquisa textual.")] = None,
    estado: Annotated[list[IncidentStatus] | None, Query()] = None,
    severidade: Annotated[list[Severity] | None, Query()] = None,
    prioridade: Annotated[list[Priority] | None, Query()] = None,
    categoria: Annotated[list[IncidentCategory] | None, Query()] = None,
    responsavel_id: Annotated[uuid.UUID | None, Query()] = None,
    apenas_activos: Annotated[bool, Query(description="Exclui encerrados e falsos positivos.")] = False,
    sem_responsavel: Annotated[bool, Query()] = False,
    desde: Annotated[datetime | None, Query(description="Detectados a partir de.")] = None,
    ate: Annotated[datetime | None, Query(description="Detectados até.")] = None,
) -> Page[IncidentListItem]:
    stmt = select(Incident).options(selectinload(Incident.assignee))

    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Incident.reference.ilike(pattern),
                Incident.title.ilike(pattern),
                Incident.description.ilike(pattern),
            )
        )
    if estado:
        stmt = stmt.where(Incident.status.in_(estado))
    if severidade:
        stmt = stmt.where(Incident.severity.in_(severidade))
    if prioridade:
        stmt = stmt.where(Incident.priority.in_(prioridade))
    if categoria:
        stmt = stmt.where(Incident.category.in_(categoria))
    if responsavel_id:
        stmt = stmt.where(Incident.assignee_id == responsavel_id)
    if sem_responsavel:
        stmt = stmt.where(Incident.assignee_id.is_(None))
    if apenas_activos:
        from app.core.enums import INCIDENT_ACTIVE_STATUSES

        stmt = stmt.where(Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)))
    if desde:
        stmt = stmt.where(Incident.detected_at >= desde)
    if ate:
        stmt = stmt.where(Incident.detected_at <= ate)

    stmt = apply_sort(stmt, Incident, params.sort, allowed=SORTABLE, default="-detected_at")
    items, total = await paginate(session, stmt, params)
    return Page.build([IncidentListItem.model_validate(i) for i in items], total, params)


# --------------------------------------------------------------------- criar
@router.post(
    "",
    response_model=IncidentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Registar incidente",
)
async def create_incident(
    payload: IncidentCreate,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[object, Depends(require(Permission.INCIDENTS_CREATE))],
) -> IncidentRead:
    incident = await incident_service.create_incident(
        session, ctx,
        title=payload.title,
        description=payload.description,
        category=payload.category,
        subtype=payload.subtype,
        severity=payload.severity,
        priority=payload.priority,
        confidence=payload.confidence,
        detected_at=payload.detected_at,
        assignee_id=payload.assignee_id,
        team_id=payload.team_id,
        asset_ids=payload.asset_ids or None,
        affected_users=payload.affected_users,
        tags=payload.tags,
    )
    await session.flush()
    incident = await incident_service.get_incident(session, incident.id, with_details=True)
    return await _to_read(session, incident)


# ---------------------------------------------------------------------- ler
@router.get("/{incident_id}", response_model=IncidentRead, summary="Detalhe do incidente")
async def get_incident(
    incident_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
) -> IncidentRead:
    incident = await incident_service.get_incident(session, incident_id, with_details=True)
    return await _to_read(session, incident)


@router.patch("/{incident_id}", response_model=IncidentRead, summary="Editar incidente")
async def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_UPDATE))],
) -> IncidentRead:
    incident = await incident_service.get_incident(session, incident_id, with_details=True)

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(incident, field, value)

    # O diff é calculado a partir do histórico da sessão, antes do commit,
    # para que a auditoria registe valor anterior e novo (§16).
    entry = await audit.record_change(
        session, ctx, incident,
        action="EDITAR_INCIDENTE", resource_type="incidente",
        description=f"Incidente {incident.reference} editado.",
    )
    if entry is None:
        raise ValidationError("Nenhuma alteração foi submetida.", code="SEM_ALTERACOES")

    return await _to_read(session, incident)


@router.post(
    "/{incident_id}/transition",
    response_model=IncidentRead,
    summary="Alterar o estado do incidente",
    description=(
        "Valida a transição contra o ciclo de vida configurado. Transições não "
        "declaradas são recusadas com 409 e a lista do que é permitido."
    ),
)
async def transition_incident(
    incident_id: uuid.UUID,
    payload: IncidentTransition,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_TRANSITION))],
) -> IncidentRead:
    incident = await incident_service.get_incident(session, incident_id, with_details=True)
    await incident_service.transition(
        session, ctx,
        incident=incident,
        new_status=payload.status,
        note=payload.note,
        resolution_summary=payload.resolution_summary,
        false_positive_reason=payload.false_positive_reason,
    )
    return await _to_read(session, incident)


@router.post(
    "/{incident_id}/assign", response_model=IncidentRead, summary="Atribuir responsável"
)
async def assign_incident(
    incident_id: uuid.UUID,
    payload: IncidentAssign,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_ASSIGN))],
) -> IncidentRead:
    incident = await incident_service.get_incident(session, incident_id, with_details=True)
    await incident_service.assign(
        session, ctx,
        incident=incident,
        assignee_id=payload.assignee_id,
        team_id=payload.team_id,
    )
    return await _to_read(session, incident)


# ---------------------------------------------------------------- comentários
@router.get(
    "/{incident_id}/comments",
    response_model=list[CommentRead],
    summary="Comentários do incidente",
)
async def list_comments(
    incident_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
) -> list[CommentRead]:
    await incident_service.get_incident(session, incident_id)
    result = await session.execute(
        select(Comment)
        .where(Comment.incident_id == incident_id)
        .options(selectinload(Comment.author))
        .order_by(Comment.created_at.asc())
    )
    return [CommentRead.model_validate(c) for c in result.scalars()]


@router.post(
    "/{incident_id}/comments",
    response_model=CommentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Adicionar comentário",
)
async def add_comment(
    incident_id: uuid.UUID,
    payload: CommentCreate,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[object, Depends(require(Permission.COMMENTS_CREATE))],
) -> CommentRead:
    incident = await incident_service.get_incident(session, incident_id)
    comment = await incident_service.add_comment(
        session, ctx, incident=incident, body=payload.body, is_internal=payload.is_internal
    )
    comment.author = user  # type: ignore[assignment]
    return CommentRead.model_validate(comment)


# --------------------------------------------------------------- observações
@router.get(
    "/{incident_id}/observations",
    response_model=list[ObservationRead],
    summary="Observações (avistamentos de artefactos)",
    description=(
        "Cada observação regista que indicador foi visto, em que papel, quando "
        "e a partir de que alerta. É a base do grafo investigativo."
    ),
)
async def list_observations(
    incident_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
) -> list[ObservationRead]:
    await incident_service.get_incident(session, incident_id)
    result = await session.execute(
        select(Observation)
        .where(Observation.incident_id == incident_id)
        .options(selectinload(Observation.ioc), selectinload(Observation.asset))
        .order_by(Observation.observed_at.asc())
    )
    return [ObservationRead.model_validate(o) for o in result.scalars()]


@router.post(
    "/{incident_id}/observations",
    response_model=ObservationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Registar observação",
)
async def add_observation(
    incident_id: uuid.UUID,
    payload: ObservationCreate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.OBSERVATIONS_MANAGE))],
) -> ObservationRead:
    from datetime import UTC

    from app.models.catalog import Ioc

    incident = await incident_service.get_incident(session, incident_id)
    ioc = await session.get(Ioc, payload.ioc_id)
    if ioc is None:
        raise NotFoundError("Indicador", payload.ioc_id)

    observation = Observation(
        incident_id=incident.id,
        ioc_id=ioc.id,
        asset_id=payload.asset_id,
        role=payload.role,
        observed_at=payload.observed_at or datetime.now(UTC),
        context=payload.context,
        confidence=payload.confidence,
        is_automatic=False,
        created_by_id=ctx.actor_id,
    )
    session.add(observation)
    await session.flush()

    await audit.record(
        session, ctx,
        action="REGISTAR_OBSERVACAO", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=(
            f"Observação registada em {incident.reference}: "
            f"{ioc.ioc_type.value} {ioc.value} ({payload.role.value})."
        ),
    )
    await session.refresh(observation, ["ioc", "asset"])
    return ObservationRead.model_validate(observation)


# ------------------------------------------------------------------ relações
@router.get(
    "/{incident_id}/relations",
    response_model=list[IncidentRelationRead],
    summary="Incidentes relacionados",
)
async def list_relations(
    incident_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
) -> list[IncidentRelationRead]:
    await incident_service.get_incident(session, incident_id)
    result = await session.execute(
        select(IncidentRelation)
        .where(
            or_(
                IncidentRelation.source_incident_id == incident_id,
                IncidentRelation.target_incident_id == incident_id,
            )
        )
        .options(
            selectinload(IncidentRelation.source_incident),
            selectinload(IncidentRelation.target_incident),
        )
    )

    entries: list[IncidentRelationRead] = []
    for relation in result.scalars():
        outgoing = relation.source_incident_id == incident_id
        other = relation.target_incident if outgoing else relation.source_incident
        entries.append(
            IncidentRelationRead(
                id=relation.id,
                relation_type=relation.relation_type.value,
                rationale=relation.rationale,
                created_by_engine=relation.created_by_engine,
                confidence=relation.confidence.value,
                created_at=relation.created_at,
                incident_id=other.id,
                incident_reference=other.reference,
                incident_title=other.title,
                incident_status=other.status.value,
                direction="saida" if outgoing else "entrada",
            )
        )
    return entries


@router.post(
    "/{incident_id}/relations",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Relacionar incidentes",
    description=(
        "Cria uma aresta tipada entre dois incidentes. Ao contrário de uma "
        "fusão, nada é destruído: ambos permanecem consultáveis com o seu "
        "histórico intacto."
    ),
)
async def relate_incidents(
    incident_id: uuid.UUID,
    payload: IncidentRelate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_RELATE))],
) -> MessageResponse:
    source = await incident_service.get_incident(session, incident_id)
    target = await incident_service.get_incident(session, payload.target_incident_id)
    await incident_service.relate(
        session, ctx,
        source=source, target=target,
        relation_type=payload.relation_type,
        rationale=payload.rationale,
        confidence=payload.confidence,
    )
    return MessageResponse(
        mensagem=(
            f"{source.reference} relacionado com {target.reference} "
            f"({payload.relation_type.value})."
        )
    )


# ------------------------------------------------------------------- técnicas
@router.post(
    "/{incident_id}/techniques",
    response_model=IncidentTechniqueRead,
    status_code=status.HTTP_201_CREATED,
    summary="Associar técnica MITRE ATT&CK",
    description=(
        "Associação afirmada por um analista. Distingue-se das hipóteses do "
        "motor, que ficam marcadas como não afirmadas."
    ),
)
async def assign_technique(
    incident_id: uuid.UUID,
    payload: TechniqueAssign,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.MITRE_MAP))],
) -> IncidentTechniqueRead:
    from app.services.mitre_service import find_technique

    incident = await incident_service.get_incident(session, incident_id)
    technique = await find_technique(session, payload.technique_id)
    if technique is None:
        raise NotFoundError("Técnica MITRE", payload.technique_id)

    existing = await session.execute(
        select(IncidentTechnique).where(
            IncidentTechnique.incident_id == incident.id,
            IncidentTechnique.technique_id == technique.id,
        )
    )
    link = existing.scalar_one_or_none()
    if link is not None:
        # Uma associação inferida pelo motor passa a afirmada quando o analista
        # a confirma — a confirmação humana sobrepõe-se à hipótese.
        link.is_asserted = True
        link.confidence = payload.confidence
        link.rationale = payload.rationale or link.rationale
    else:
        link = IncidentTechnique(
            incident_id=incident.id,
            technique_id=technique.id,
            is_asserted=True,
            confidence=payload.confidence,
            rationale=payload.rationale,
            created_by_id=ctx.actor_id,
        )
        session.add(link)
    await session.flush()

    await audit.record(
        session, ctx,
        action="ASSOCIAR_TECNICA", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=(
            f"Técnica {technique.technique_id} ({technique.name}) associada a "
            f"{incident.reference}."
        ),
    )
    await session.refresh(link, ["technique"])
    return IncidentTechniqueRead.model_validate(link)


@router.delete(
    "/{incident_id}/techniques/{technique_id}",
    response_model=MessageResponse,
    summary="Remover associação de técnica",
)
async def remove_technique(
    incident_id: uuid.UUID,
    technique_id: str,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.MITRE_MAP))],
) -> MessageResponse:
    from app.services.mitre_service import find_technique

    incident = await incident_service.get_incident(session, incident_id)
    technique = await find_technique(session, technique_id)
    if technique is None:
        raise NotFoundError("Técnica MITRE", technique_id)

    result = await session.execute(
        select(IncidentTechnique).where(
            IncidentTechnique.incident_id == incident.id,
            IncidentTechnique.technique_id == technique.id,
        )
    )
    link = result.scalar_one_or_none()
    if link is None:
        raise NotFoundError("Associação de técnica", technique_id)

    await session.delete(link)
    await audit.record(
        session, ctx,
        action="REMOVER_TECNICA", resource_type="incidente",
        resource_id=incident.id, resource_reference=incident.reference,
        description=f"Técnica {technique.technique_id} removida de {incident.reference}.",
    )
    return MessageResponse(mensagem=f"Técnica {technique.technique_id} removida.")


# ------------------------------------------------------------- linha temporal
@router.get(
    "/{incident_id}/timeline",
    response_model=list[IncidentTimelineEntry],
    summary="Linha temporal do incidente",
    description=(
        "Sequência unificada de tudo o que aconteceu: registo de auditoria, "
        "comentários, alertas associados, evidências, tarefas e acções. É o que "
        "permite reconstruir o incidente do princípio ao fim."
    ),
)
async def incident_timeline(
    incident_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
) -> list[IncidentTimelineEntry]:
    from app.services.timeline_service import build_timeline

    incident = await incident_service.get_incident(session, incident_id)
    return await build_timeline(session, incident)
