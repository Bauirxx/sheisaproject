"""Rotas de evidências e tarefas — /api/evidence, /api/tasks."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import EvidenceType, TaskStatus
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.lookups import require_existing
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.partial_update import reject_nulls_for_required
from app.core.permissions import Permission
from app.models.identity import User
from app.models.investigation import Task
from app.schemas.common import MessageResponse
from app.schemas.incident import EvidenceRead, TaskCreate, TaskRead, TaskUpdate
from app.services import evidence_service, incident_service

evidence_router = APIRouter(prefix="/evidence", tags=["Evidências"])
task_router = APIRouter(prefix="/tasks", tags=["Tarefas"])


# ---------------------------------------------------------------- evidências
@evidence_router.post(
    "",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Carregar evidência",
    description=(
        "Associa um ficheiro a um incidente e calcula SHA-256 e MD5 sobre os "
        "bytes recebidos. O hash passa a ser o valor de referência para "
        "verificações de integridade posteriores."
    ),
)
async def upload_evidence(
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.EVIDENCE_UPLOAD))],
    incident_id: Annotated[uuid.UUID, Form()],
    ficheiro: Annotated[UploadFile, File(description="Ficheiro a associar.")],
    nome: Annotated[str | None, Form()] = None,
    descricao: Annotated[str, Form()] = "",
    tipo: Annotated[EvidenceType, Form()] = EvidenceType.OUTRO,
    origem: Annotated[str, Form()] = "",
    recolhido_em: Annotated[datetime | None, Form()] = None,
) -> EvidenceRead:
    incident = await incident_service.get_incident(session, incident_id)
    incident_service.garantir_editavel(incident)
    evidence = await evidence_service.store_evidence(
        session, ctx,
        incident=incident,
        upload=ficheiro,
        name=nome,
        description=descricao,
        evidence_type=tipo,
        source=origem,
        collected_at=recolhido_em,
    )
    await session.refresh(evidence, ["uploaded_by"])
    return EvidenceRead.model_validate(evidence)


@evidence_router.get(
    "/limits",
    summary="Limites de carregamento",
    description=(
        "Tamanho máximo e extensões aceites, tal como o servidor os aplica. "
        "A interface lê-os daqui em vez de os repetir: uma lista duplicada no "
        "cliente acabaria por divergir da que é de facto imposta, e o "
        "utilizador veria um ficheiro ser recusado depois de a interface lhe "
        "dizer que era aceite."
    ),
)
async def evidence_limits(
    _: Annotated[object, Depends(require(Permission.EVIDENCE_READ))],
) -> dict:
    from app.core.config import settings

    return {
        "tamanho_maximo_bytes": settings.evidence_max_bytes,
        "tamanho_maximo_legivel": (
            f"{settings.evidence_max_bytes // (1024 * 1024)} MiB"
        ),
        "extensoes_permitidas": sorted(settings.evidence_allowed_suffixes),
        "tipos": [t.value for t in EvidenceType],
    }


@evidence_router.get(
    "",
    response_model=list[EvidenceRead],
    summary="Evidências de um incidente",
)
async def list_evidence(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.EVIDENCE_READ))],
    incident_id: Annotated[uuid.UUID, Query()],
) -> list[EvidenceRead]:
    await incident_service.get_incident(session, incident_id)
    items = await evidence_service.list_for_incident(session, incident_id)
    return [EvidenceRead.model_validate(e) for e in items]


@evidence_router.get(
    "/{evidence_id}", response_model=EvidenceRead, summary="Detalhe da evidência"
)
async def get_evidence(
    evidence_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.EVIDENCE_READ))],
) -> EvidenceRead:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    await session.refresh(evidence, ["uploaded_by"])
    return EvidenceRead.model_validate(evidence)


@evidence_router.get(
    "/{evidence_id}/download",
    summary="Descarregar evidência",
    description=(
        "Devolve sempre `application/octet-stream` como anexo, "
        "independentemente do tipo real do ficheiro, para que nada possa ser "
        "interpretado como conteúdo activo pelo navegador."
    ),
    response_class=FileResponse,
)
async def download_evidence(
    evidence_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.EVIDENCE_READ))],
) -> FileResponse:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    path = evidence_service.absolute_path_for(evidence)
    if not path.exists():
        raise NotFoundError("Ficheiro da evidência", evidence_id)

    # Descarregar uma evidência é um acesso a material probatório e fica
    # registado como tal.
    await audit.record(
        session, ctx,
        action="DESCARREGAR_EVIDENCIA", resource_type="evidencia",
        resource_id=evidence.id,
        description=f"Evidência '{evidence.name}' descarregada.",
    )

    return FileResponse(
        path=path,
        media_type="application/octet-stream",
        filename=evidence.original_filename,
        headers={
            "Content-Disposition": f'attachment; filename="{evidence.id}"',
            "X-Content-Type-Options": "nosniff",
            "X-Evidence-SHA256": evidence.sha256,
        },
    )


@evidence_router.post(
    "/{evidence_id}/verify",
    summary="Verificar integridade",
    description=(
        "Recalcula o hash do ficheiro em disco e compara-o com o registado na "
        "recepção. Um resultado negativo indica que a evidência foi alterada."
    ),
)
async def verify_evidence(
    evidence_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.EVIDENCE_READ))],
) -> dict:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    return await evidence_service.verify_integrity(session, ctx, evidence)


@evidence_router.delete(
    "/{evidence_id}",
    response_model=MessageResponse,
    summary="Eliminar evidência",
    description=(
        "Exige a permissão `evidence:delete`. O nome e o hash do conteúdo "
        "removido ficam preservados no registo de auditoria."
    ),
)
async def delete_evidence(
    evidence_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.EVIDENCE_DELETE))],
) -> MessageResponse:
    evidence = await evidence_service.get_evidence(session, evidence_id)
    name = evidence.name
    await evidence_service.delete_evidence(session, ctx, evidence)
    return MessageResponse(mensagem=f"Evidência '{name}' eliminada.")


# ------------------------------------------------------------------- tarefas
@task_router.get("", response_model=Page[TaskRead], summary="Listar tarefas")
async def list_tasks(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.TASKS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    incident_id: Annotated[uuid.UUID | None, Query()] = None,
    estado: Annotated[list[TaskStatus] | None, Query()] = None,
    responsavel_id: Annotated[uuid.UUID | None, Query()] = None,
    pendentes: Annotated[bool, Query(description="Apenas por concluir.")] = False,
) -> Page[TaskRead]:
    stmt = select(Task).options(selectinload(Task.assignee))
    if incident_id:
        stmt = stmt.where(Task.incident_id == incident_id)
    if estado:
        stmt = stmt.where(Task.status.in_(estado))
    if responsavel_id:
        stmt = stmt.where(Task.assignee_id == responsavel_id)
    if pendentes:
        stmt = stmt.where(
            Task.status.in_([TaskStatus.PENDENTE, TaskStatus.EM_CURSO, TaskStatus.BLOQUEADA])
        )

    stmt = apply_sort(
        stmt, Task, params.sort,
        allowed={"created_at", "due_at", "priority", "status", "ordering", "title"},
        default="-created_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([TaskRead.model_validate(t) for t in items], total, params)


@task_router.post(
    "",
    response_model=TaskRead,
    status_code=status.HTTP_201_CREATED,
    summary="Criar tarefa",
)
async def create_task(
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.TASKS_MANAGE))],
    incident_id: Annotated[uuid.UUID, Query(description="Incidente a que pertence.")],
    payload: TaskCreate = ...,
) -> TaskRead:
    incident = await incident_service.get_incident(session, incident_id)
    incident_service.garantir_editavel(incident)
    await require_existing(session, User, payload.assignee_id, "Utilizador")

    highest = await session.execute(
        select(Task.ordering).where(Task.incident_id == incident.id)
        .order_by(Task.ordering.desc()).limit(1)
    )
    next_order = (highest.scalar_one_or_none() or 0) + 1

    task = Task(
        incident_id=incident.id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        assignee_id=payload.assignee_id,
        due_at=payload.due_at,
        ordering=next_order,
        created_by_id=ctx.actor_id,
    )

    if payload.depends_on_ids:
        result = await session.execute(
            select(Task).where(
                Task.id.in_(payload.depends_on_ids), Task.incident_id == incident.id
            )
        )
        dependencies = list(result.scalars())
        if len(dependencies) != len(set(payload.depends_on_ids)):
            raise ValidationError(
                "Algumas dependências não existem ou pertencem a outro incidente.",
                code="DEPENDENCIA_INVALIDA",
            )
        task.depends_on = dependencies

    session.add(task)
    await session.flush()

    await audit.record(
        session, ctx,
        action="CRIAR_TAREFA", resource_type="tarefa",
        resource_id=task.id, resource_reference=incident.reference,
        description=f"Tarefa '{task.title}' criada em {incident.reference}.",
    )

    # Se a tarefa já nasce com responsável, avisa-o (excepto se for ele a criá-la).
    if task.assignee_id is not None:
        from app.core.enums import NotificationKind
        from app.services import notification_service

        notification_service.notificar(
            session,
            user_id=task.assignee_id,
            kind=NotificationKind.TAREFA_ATRIBUIDA,
            title=f"Tarefa atribuída: {task.title}",
            body=f"Foi-lhe atribuída a tarefa '{task.title}' em {incident.reference}.",
            resource_type="tarefa",
            resource_id=task.id,
            resource_reference=incident.reference,
            excepto=ctx.actor_id,
        )

    # `assignee` não foi carregado ao construir a tarefa; sem este refresh, serializar
    # `TaskRead` de uma tarefa com responsável acede a uma relação por carregar e
    # rebenta com `MissingGreenlet` (IO fora do contexto assíncrono).
    await session.refresh(task, ["assignee"])
    return TaskRead.model_validate(task)


@task_router.patch("/{task_id}", response_model=TaskRead, summary="Actualizar tarefa")
async def update_task(
    task_id: uuid.UUID,
    payload: TaskUpdate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.TASKS_MANAGE))],
) -> TaskRead:
    from datetime import UTC

    # `depends_on` e `assignee` são carregados explicitamente com a tarefa.
    #
    # `session.get()` não aplica o carregamento antecipado destas relações, e
    # aceder a `task.depends_on` mais abaixo dispararia IO fora do contexto
    # assíncrono — que o SQLAlchemy recusa com `MissingGreenlet` e a API
    # devolve como 500. A verificação de dependências precisa mesmo da lista,
    # pelo que a alternativa não é não a carregar: é carregá-la aqui.
    result = await session.execute(
        select(Task)
        .where(Task.id == task_id)
        .options(selectinload(Task.depends_on), selectinload(Task.assignee))
    )
    task = result.scalar_one_or_none()
    if task is None:
        raise NotFoundError("Tarefa", task_id)
    incidente = await incident_service.get_incident(session, task.incident_id)
    incident_service.garantir_editavel(incidente)
    responsavel_anterior = task.assignee_id

    changes = payload.model_dump(exclude_unset=True)
    reject_nulls_for_required(task, changes)
    await require_existing(session, User, changes.get("assignee_id"), "Utilizador")

    if (new_status := changes.get("status")) is not None:
        if new_status == TaskStatus.CONCLUIDA:
            # Uma dependência por cumprir bloqueia a conclusão: sem isto, a
            # ordem operacional do §19 seria decorativa.
            pending = [
                d.title for d in task.depends_on
                if d.status not in (TaskStatus.CONCLUIDA, TaskStatus.CANCELADA)
            ]
            if pending:
                raise ConflictError(
                    "A tarefa depende de outras ainda por concluir.",
                    code="DEPENDENCIAS_PENDENTES",
                    details={"tarefas_pendentes": pending},
                )
            task.completed_at = datetime.now(UTC)
        elif new_status == TaskStatus.EM_CURSO and task.started_at is None:
            task.started_at = datetime.now(UTC)

    for field, value in changes.items():
        setattr(task, field, value)

    entry = await audit.record_change(
        session, ctx, task,
        action="ACTUALIZAR_TAREFA", resource_type="tarefa",
        description=f"Tarefa '{task.title}' actualizada.",
    )
    if entry is None:
        raise ValidationError("Nenhuma alteração foi submetida.", code="SEM_ALTERACOES")

    # Avisa quem passou a ser responsável pela tarefa — não quem a reatribuiu.
    if task.assignee_id is not None and task.assignee_id != responsavel_anterior:
        from app.core.enums import NotificationKind
        from app.services import notification_service

        notification_service.notificar(
            session,
            user_id=task.assignee_id,
            kind=NotificationKind.TAREFA_ATRIBUIDA,
            title=f"Tarefa atribuída: {task.title}",
            body=f"Foi-lhe atribuída a tarefa '{task.title}' em {incidente.reference}.",
            resource_type="tarefa",
            resource_id=task.id,
            resource_reference=incidente.reference,
            excepto=ctx.actor_id,
        )

    return TaskRead.model_validate(task)


@task_router.get("/{task_id}", response_model=TaskRead, summary="Detalhe da tarefa")
async def get_task(
    task_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.TASKS_READ))],
) -> TaskRead:
    result = await session.execute(
        select(Task).where(Task.id == task_id).options(selectinload(Task.assignee))
    )
    task = result.scalar_one_or_none()
    if task is None:
        raise NotFoundError("Tarefa", task_id)
    return TaskRead.model_validate(task)
