"""Acções, aprovações e playbooks — /api/actions, /api/approvals, /api/playbooks."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import (
    ActionRiskLevel,
    ActionStatus,
    ApprovalDecision,
    PlaybookExecutionStatus,
)
from app.core.errors import ConflictError, NotFoundError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.integrations.registry import action_is_executable
from app.models.response import (
    Action,
    ActionApproval,
    Playbook,
    PlaybookExecution,
    PlaybookStep,
)
from app.schemas.response import (
    ActionPropose,
    ActionRead,
    ActionRevert,
    ApprovalDecide,
    PlaybookExecutionRead,
    PlaybookRead,
    PlaybookRun,
    PlaybookSuggestion,
    PlaybookWrite,
)
from app.services import action_service, incident_service

action_router = APIRouter(prefix="/actions", tags=["Acções de resposta"])
approval_router = APIRouter(prefix="/approvals", tags=["Aprovações"])
playbook_router = APIRouter(prefix="/playbooks", tags=["Playbooks"])


async def _to_action_read(session, action: Action) -> ActionRead:
    """Anexa a informação de executabilidade real (§4)."""
    payload = ActionRead.model_validate(action)
    integration = await action_service.find_integration_for(session, action.action_kind)

    if not action_is_executable(action.action_kind):
        payload.executavel = False
        payload.motivo_nao_executavel = (
            f"Não existe conector implementado para {action.action_kind.value}."
        )
    elif integration is None:
        payload.executavel = False
        payload.motivo_nao_executavel = (
            "Nenhuma integração activa suporta esta acção. Configure e verifique "
            "a integração correspondente."
        )
    return payload


# -------------------------------------------------------------------- acções
@action_router.get("", response_model=Page[ActionRead], summary="Listar acções")
async def list_actions(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ACTIONS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    incident_id: Annotated[uuid.UUID | None, Query()] = None,
    estado: Annotated[list[ActionStatus] | None, Query()] = None,
    risco: Annotated[list[ActionRiskLevel] | None, Query()] = None,
) -> Page[ActionRead]:
    stmt = select(Action).options(
        selectinload(Action.approvals).selectinload(ActionApproval.decided_by)
    )
    if incident_id:
        stmt = stmt.where(Action.incident_id == incident_id)
    if estado:
        stmt = stmt.where(Action.status.in_(estado))
    if risco:
        stmt = stmt.where(Action.risk_level.in_(risco))

    stmt = apply_sort(
        stmt, Action, params.sort,
        allowed={"created_at", "executed_at", "status", "risk_level", "reference"},
        default="-created_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build(
        [await _to_action_read(session, a) for a in items], total, params
    )


@action_router.post(
    "", response_model=ActionRead, status_code=status.HTTP_201_CREATED,
    summary="Propor acção de resposta",
    description=(
        "Acções de risco moderado ou crítico entram em AGUARDA_APROVACAO e não "
        "podem ser executadas até haver decisão humana registada."
    ),
)
async def propose_action(
    payload: ActionPropose,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ACTIONS_PROPOSE))],
) -> ActionRead:
    incident = await incident_service.get_incident(session, payload.incident_id)
    action = await action_service.propose_action(
        session, ctx,
        incident=incident,
        action_kind=payload.action_kind,
        title=payload.title,
        rationale=payload.rationale,
        target=payload.target,
        parameters=payload.parameters,
        risk_level=payload.risk_level,
    )
    await session.refresh(action, ["approvals"])
    return await _to_action_read(session, action)


@action_router.get("/{action_id}", response_model=ActionRead, summary="Detalhe da acção")
async def get_action(
    action_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ACTIONS_READ))],
) -> ActionRead:
    action = await action_service.get_action(session, action_id)
    return await _to_action_read(session, action)


@action_router.post(
    "/{action_id}/execute",
    response_model=ActionRead,
    summary="Executar acção aprovada",
    description=(
        "Executa através da integração configurada. Se não existir integração "
        "activa, a chamada devolve 503 e a acção fica registada como falhada — "
        "nunca é reportado um sucesso que não aconteceu."
    ),
)
async def execute_action(
    action_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ACTIONS_EXECUTE))],
) -> ActionRead:
    action = await action_service.get_action(session, action_id)
    await action_service.execute_action(session, ctx, action=action)
    return await _to_action_read(session, action)


@action_router.post(
    "/{action_id}/revert",
    response_model=ActionRead,
    summary="Reverter acção executada",
    description="Cria a acção inversa (ex.: DESBLOQUEAR_IP reverte BLOQUEAR_IP).",
)
async def revert_action(
    action_id: uuid.UUID,
    payload: ActionRevert,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ACTIONS_PROPOSE))],
) -> ActionRead:
    action = await action_service.get_action(session, action_id)
    inverse = await action_service.revert_action(
        session, ctx, action=action, rationale=payload.rationale
    )
    await session.refresh(inverse, ["approvals"])
    return await _to_action_read(session, inverse)


# ----------------------------------------------------------------- aprovações
@approval_router.get(
    "",
    response_model=Page[ActionRead],
    summary="Acções que aguardam decisão",
    description="Fila de aprovação do §13.",
)
async def list_pending(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ACTIONS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    apenas_pendentes: Annotated[bool, Query()] = True,
) -> Page[ActionRead]:
    stmt = (
        select(Action)
        .join(ActionApproval, ActionApproval.action_id == Action.id)
        .options(selectinload(Action.approvals).selectinload(ActionApproval.decided_by))
    )
    if apenas_pendentes:
        stmt = stmt.where(ActionApproval.decision == ApprovalDecision.PENDENTE)

    stmt = apply_sort(
        stmt, Action, params.sort,
        allowed={"created_at", "risk_level", "reference"}, default="created_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build(
        [await _to_action_read(session, a) for a in items], total, params
    )


@approval_router.post(
    "/{action_id}/decide",
    response_model=ActionRead,
    summary="Aprovar ou rejeitar uma acção",
    description=(
        "Exige `actions:approve` (risco moderado) ou `actions:approve_critical` "
        "(risco crítico). Quem propôs a acção não a pode aprovar. Acções "
        "críticas exigem justificação escrita."
    ),
)
async def decide(
    action_id: uuid.UUID,
    payload: ApprovalDecide,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[object, Depends(require(Permission.ACTIONS_APPROVE, Permission.ACTIONS_APPROVE_CRITICAL, require_all=False))],
) -> ActionRead:
    action = await action_service.get_action(session, action_id)
    await action_service.decide_action(
        session, ctx,
        action=action,
        decider=user,
        approved=payload.approved,
        justification=payload.justification,
    )

    # Se a acção pertencia a um playbook suspenso, a aprovação retoma-o.
    if payload.approved and action.playbook_execution_id:
        from app.playbooks import engine as playbook_engine

        execution = await session.get(PlaybookExecution, action.playbook_execution_id)
        if execution is not None and execution.status == PlaybookExecutionStatus.AGUARDA_APROVACAO:
            await session.refresh(execution, ["step_executions"])
            await playbook_engine.resume_execution(session, ctx, execution=execution)

    await session.refresh(action, ["approvals"])
    return await _to_action_read(session, action)


# ------------------------------------------------------------------ playbooks
@playbook_router.get("", response_model=list[PlaybookRead], summary="Listar playbooks")
async def list_playbooks(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_READ))],
    apenas_activos: Annotated[bool, Query()] = False,
) -> list[PlaybookRead]:
    stmt = select(Playbook).options(selectinload(Playbook.steps)).order_by(Playbook.name)
    if apenas_activos:
        stmt = stmt.where(Playbook.is_enabled.is_(True))
    result = await session.execute(stmt)
    return [PlaybookRead.model_validate(p) for p in result.scalars().unique()]


@playbook_router.post(
    "", response_model=PlaybookRead, status_code=status.HTTP_201_CREATED,
    summary="Criar playbook",
)
async def create_playbook(
    payload: PlaybookWrite,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_MANAGE))],
) -> PlaybookRead:
    existing = await session.execute(select(Playbook).where(Playbook.name == payload.name))
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Já existe um playbook chamado '{payload.name}'.")

    data = payload.model_dump(exclude={"steps"})
    playbook = Playbook(**data, created_by_id=ctx.actor_id)
    session.add(playbook)
    await session.flush()

    for step in payload.steps:
        session.add(PlaybookStep(playbook_id=playbook.id, **step.model_dump()))
    await session.flush()

    await audit.record(
        session, ctx,
        action="CRIAR_PLAYBOOK", resource_type="playbook", resource_id=playbook.id,
        description=f"Playbook '{playbook.name}' criado com {len(payload.steps)} passo(s).",
    )
    await session.refresh(playbook, ["steps"])
    return PlaybookRead.model_validate(playbook)


@playbook_router.get(
    "/suggestions",
    response_model=list[PlaybookSuggestion],
    summary="Playbooks sugeridos para um incidente",
    description="Cada sugestão indica porque é aplicável àquele incidente.",
)
async def suggestions(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_READ))],
    incident_id: Annotated[uuid.UUID, Query()],
) -> list[PlaybookSuggestion]:
    from app.playbooks import engine as playbook_engine

    incident = await incident_service.get_incident(session, incident_id)
    return [
        PlaybookSuggestion(playbook=PlaybookRead.model_validate(p), motivo=reason)
        for p, reason in await playbook_engine.suggest_playbooks(session, incident)
    ]


@playbook_router.get(
    "/{playbook_id}", response_model=PlaybookRead, summary="Detalhe do playbook"
)
async def get_playbook(
    playbook_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_READ))],
) -> PlaybookRead:
    result = await session.execute(
        select(Playbook).where(Playbook.id == playbook_id).options(selectinload(Playbook.steps))
    )
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise NotFoundError("Playbook", playbook_id)
    return PlaybookRead.model_validate(playbook)


@playbook_router.post(
    "/{playbook_id}/run",
    response_model=PlaybookExecutionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Executar playbook sobre um incidente",
    description=(
        "Corre os passos por ordem. Ao chegar a um passo que exija aprovação, "
        "a execução é suspensa em AGUARDA_APROVACAO e retomada quando a "
        "decisão for registada."
    ),
)
async def run_playbook(
    playbook_id: uuid.UUID,
    payload: PlaybookRun,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_EXECUTE))],
) -> PlaybookExecutionRead:
    from app.playbooks import engine as playbook_engine

    result = await session.execute(
        select(Playbook).where(Playbook.id == playbook_id).options(selectinload(Playbook.steps))
    )
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise NotFoundError("Playbook", playbook_id)

    incident = await incident_service.get_incident(session, payload.incident_id)
    execution = await playbook_engine.start_execution(
        session, ctx, playbook=playbook, incident=incident
    )
    await session.refresh(execution, ["step_executions"])
    return PlaybookExecutionRead.model_validate(execution)


@playbook_router.get(
    "/executions/list",
    response_model=Page[PlaybookExecutionRead],
    summary="Execuções de playbooks",
)
async def list_executions(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    incident_id: Annotated[uuid.UUID | None, Query()] = None,
    estado: Annotated[list[PlaybookExecutionStatus] | None, Query()] = None,
) -> Page[PlaybookExecutionRead]:
    stmt = select(PlaybookExecution).options(
        selectinload(PlaybookExecution.step_executions)
    )
    if incident_id:
        stmt = stmt.where(PlaybookExecution.incident_id == incident_id)
    if estado:
        stmt = stmt.where(PlaybookExecution.status.in_(estado))

    stmt = apply_sort(
        stmt, PlaybookExecution, params.sort,
        allowed={"created_at", "started_at", "finished_at", "status", "reference"},
        default="-created_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build(
        [PlaybookExecutionRead.model_validate(e) for e in items], total, params
    )


@playbook_router.get(
    "/executions/{execution_id}",
    response_model=PlaybookExecutionRead,
    summary="Detalhe de uma execução",
)
async def get_execution(
    execution_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.PLAYBOOKS_READ))],
) -> PlaybookExecutionRead:
    result = await session.execute(
        select(PlaybookExecution)
        .where(PlaybookExecution.id == execution_id)
        .options(selectinload(PlaybookExecution.step_executions))
    )
    execution = result.scalar_one_or_none()
    if execution is None:
        raise NotFoundError("Execução de playbook", execution_id)
    return PlaybookExecutionRead.model_validate(execution)
