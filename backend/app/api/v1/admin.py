"""Administração — /api/users, /api/roles, /api/audit, /api/integrations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from pydantic import Field
from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.deps import AuditDep, CurrentUser, SessionDep, require
from app.core.enums import AuditOutcome, SourceKind
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.core.security import hash_password
from app.models.identity import ApiKey, Role, Team, User
from app.models.system import AuditLog, Integration, Notification
from app.schemas.auth import (
    PasswordResetRequest,
    RoleRead,
    TeamRead,
    UserCreate,
    UserDetail,
    UserRead,
    UserUpdate,
)
from app.schemas.common import ApiModel, MessageResponse
from app.services import auth_service, integration_service

user_router = APIRouter(prefix="/users", tags=["Utilizadores"])
role_router = APIRouter(prefix="/roles", tags=["Perfis e permissões"])
audit_router = APIRouter(prefix="/audit", tags=["Auditoria"])
integration_router = APIRouter(prefix="/integrations", tags=["Integrações"])
notification_router = APIRouter(prefix="/notifications", tags=["Notificações"])


def _to_detail(user: User) -> UserDetail:
    return UserDetail(
        id=user.id, email=user.email, full_name=user.full_name,
        is_active=user.is_active, must_change_password=user.must_change_password,
        role=user.role, team=user.team, last_login_at=user.last_login_at,
        created_at=user.created_at, locked_until=user.locked_until,
        permissions=user.permission_codes,
    )


# ------------------------------------------------------------- utilizadores
@user_router.get("", response_model=Page[UserRead], summary="Listar utilizadores")
async def list_users(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.USERS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query()] = None,
    perfil: Annotated[str | None, Query()] = None,
    apenas_activos: Annotated[bool, Query()] = False,
) -> Page[UserRead]:
    stmt = select(User).options(selectinload(User.role), selectinload(User.team))
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(User.email.ilike(pattern), User.full_name.ilike(pattern)))
    if perfil:
        stmt = stmt.join(Role, Role.id == User.role_id).where(Role.name == perfil.upper())
    if apenas_activos:
        stmt = stmt.where(User.is_active.is_(True))

    stmt = apply_sort(
        stmt, User, params.sort,
        allowed={"email", "full_name", "created_at", "last_login_at", "is_active"},
        default="full_name",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([UserRead.model_validate(u) for u in items], total, params)


@user_router.post(
    "", response_model=UserDetail, status_code=status.HTTP_201_CREATED,
    summary="Criar utilizador",
)
async def create_user(
    payload: UserCreate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.USERS_MANAGE))],
) -> UserDetail:
    existing = await session.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Já existe uma conta com o endereço '{payload.email}'.")

    role_result = await session.execute(
        select(Role).where(Role.name == payload.role_name.upper())
        .options(selectinload(Role.permissions))
    )
    role = role_result.scalar_one_or_none()
    if role is None:
        raise NotFoundError("Perfil", payload.role_name)

    if payload.team_id is not None and await session.get(Team, payload.team_id) is None:
        raise NotFoundError("Equipa", payload.team_id)

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=role.id,
        team_id=payload.team_id,
        must_change_password=payload.must_change_password,
        is_active=True,
    )
    session.add(user)
    await session.flush()

    await audit.record(
        session, ctx,
        action="CRIAR_UTILIZADOR", resource_type="utilizador", resource_id=user.id,
        description=f"Utilizador '{user.email}' criado com o perfil {role.name}.",
        # A palavra-passe nunca entra no registo de auditoria.
        new_value={"email": user.email, "nome": user.full_name, "perfil": role.name},
    )
    await session.refresh(user, ["role", "team"])
    return _to_detail(user)


@user_router.get("/{user_id}", response_model=UserDetail, summary="Detalhe do utilizador")
async def get_user(
    user_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.USERS_READ))],
) -> UserDetail:
    user = await auth_service.get_user_or_404(session, user_id)
    await session.refresh(user, ["team"])
    return _to_detail(user)


@user_router.patch("/{user_id}", response_model=UserDetail, summary="Editar utilizador")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    session: SessionDep,
    ctx: AuditDep,
    current: CurrentUser,
    _: Annotated[object, Depends(require(Permission.USERS_MANAGE))],
) -> UserDetail:
    user = await auth_service.get_user_or_404(session, user_id)
    changes = payload.model_dump(exclude_unset=True)

    if (role_name := changes.pop("role_name", None)) is not None:
        role_result = await session.execute(
            select(Role).where(Role.name == role_name.upper())
        )
        role = role_result.scalar_one_or_none()
        if role is None:
            raise NotFoundError("Perfil", role_name)
        user.role_id = role.id

    # Impede que um administrador se desactive a si próprio e perca o acesso.
    if changes.get("is_active") is False and user.id == current.id:
        raise ValidationError(
            "Não pode desactivar a sua própria conta.",
            code="AUTO_DESACTIVACAO",
        )

    for field, value in changes.items():
        setattr(user, field, value)

    await audit.record_change(
        session, ctx, user,
        action="EDITAR_UTILIZADOR", resource_type="utilizador",
        description=f"Utilizador '{user.email}' actualizado.",
    )

    # Desactivar uma conta termina as suas sessões de imediato; caso contrário
    # o token de acesso continuaria válido até expirar.
    if changes.get("is_active") is False:
        await auth_service.revoke_all_sessions(
            session, ctx, user_id=user.id, reason="conta_desactivada"
        )

    await session.refresh(user, ["role", "team"])
    return _to_detail(user)


@user_router.post(
    "/{user_id}/reset-password",
    response_model=MessageResponse,
    summary="Repor a palavra-passe de um utilizador",
    description="Termina todas as sessões activas dessa conta.",
)
async def reset_password(
    user_id: uuid.UUID,
    payload: PasswordResetRequest,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.USERS_MANAGE))],
) -> MessageResponse:
    user = await auth_service.get_user_or_404(session, user_id)
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = payload.must_change_password
    user.failed_login_count = 0
    user.locked_until = None

    revoked = await auth_service.revoke_all_sessions(
        session, ctx, user_id=user.id, reason="palavra_passe_reposta"
    )
    await audit.record(
        session, ctx,
        action="REPOR_PALAVRA_PASSE", resource_type="utilizador", resource_id=user.id,
        description=(
            f"Palavra-passe de '{user.email}' reposta por um administrador. "
            f"{revoked} sessão(ões) terminada(s)."
        ),
    )
    return MessageResponse(
        mensagem=f"Palavra-passe reposta. {revoked} sessão(ões) terminada(s)."
    )


@role_router.get("", response_model=list[RoleRead], summary="Listar perfis")
async def list_roles(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.USERS_READ))],
) -> list[RoleRead]:
    result = await session.execute(
        select(Role).options(selectinload(Role.permissions)).order_by(Role.name)
    )
    return [RoleRead.model_validate(r) for r in result.scalars().unique()]


@role_router.get("/teams", response_model=list[TeamRead], summary="Listar equipas")
async def list_teams(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.USERS_READ))],
) -> list[TeamRead]:
    result = await session.execute(select(Team).order_by(Team.name))
    return [TeamRead.model_validate(t) for t in result.scalars()]


# ------------------------------------------------------------------ auditoria
class AuditEntryRead(ApiModel):
    id: uuid.UUID
    created_at: datetime
    actor_email: str
    actor_role: str | None = None
    is_system_actor: bool
    action: str
    resource_type: str
    resource_id: uuid.UUID | None = None
    resource_reference: str | None = None
    description: str
    old_value: dict | None = None
    new_value: dict | None = None
    changed_fields: list[str] = Field(default_factory=list)
    origin: str
    ip_address: str | None = None
    request_id: str | None = None
    outcome: str
    failure_reason: str | None = None


@audit_router.get(
    "",
    response_model=Page[AuditEntryRead],
    summary="Consultar o registo de auditoria",
    description=(
        "Registo apenas de inserção: gatilhos do PostgreSQL recusam UPDATE, "
        "DELETE e TRUNCATE sobre esta tabela. Cada entrada inclui o valor "
        "anterior e o novo quando houve alteração."
    ),
)
async def list_audit(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.AUDIT_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query(description="Pesquisa na descrição.")] = None,
    accao: Annotated[list[str] | None, Query()] = None,
    tipo_recurso: Annotated[str | None, Query()] = None,
    recurso_id: Annotated[uuid.UUID | None, Query()] = None,
    actor: Annotated[str | None, Query(description="Endereço do actor.")] = None,
    resultado: Annotated[list[AuditOutcome] | None, Query()] = None,
    desde: Annotated[datetime | None, Query()] = None,
    ate: Annotated[datetime | None, Query()] = None,
) -> Page[AuditEntryRead]:
    stmt = select(AuditLog)
    if q:
        stmt = stmt.where(AuditLog.description.ilike(f"%{q.strip()}%"))
    if accao:
        stmt = stmt.where(AuditLog.action.in_(accao))
    if tipo_recurso:
        stmt = stmt.where(AuditLog.resource_type == tipo_recurso)
    if recurso_id:
        stmt = stmt.where(AuditLog.resource_id == recurso_id)
    if actor:
        stmt = stmt.where(AuditLog.actor_email.ilike(f"%{actor.strip()}%"))
    if resultado:
        stmt = stmt.where(AuditLog.outcome.in_(resultado))
    if desde:
        stmt = stmt.where(AuditLog.created_at >= desde)
    if ate:
        stmt = stmt.where(AuditLog.created_at <= ate)

    stmt = apply_sort(
        stmt, AuditLog, params.sort,
        allowed={"created_at", "action", "resource_type", "actor_email", "outcome"},
        default="-created_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([AuditEntryRead.model_validate(a) for a in items], total, params)


@audit_router.get(
    "/actions", response_model=list[str], summary="Tipos de acção registados"
)
async def audit_actions(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.AUDIT_READ))],
) -> list[str]:
    result = await session.execute(select(AuditLog.action).distinct().order_by(AuditLog.action))
    return [a for (a,) in result.all()]


# --------------------------------------------------------------- integrações
class IntegrationRead(ApiModel):
    id: uuid.UUID
    name: str
    kind: str
    direction: str
    description: str
    status: str
    is_enabled: bool
    config: dict = Field(default_factory=dict)
    #: Nomes das variáveis de ambiente esperadas. Os valores nunca são expostos.
    secret_env_vars: list[str] = Field(default_factory=list)
    variaveis_em_falta: list[str] = Field(default_factory=list)
    last_check_at: datetime | None = None
    last_check_ok: bool | None = None
    last_check_detail: str | None = None
    last_error: str | None = None
    events_received: int
    last_event_at: datetime | None = None
    actions_executed: int
    actions_failed: int
    supported_actions: list[str] = Field(default_factory=list)
    chaves_activas: int = 0


@integration_router.get(
    "",
    response_model=list[IntegrationRead],
    summary="Listar integrações",
    description=(
        "O estado reflecte a realidade verificada: uma integração só aparece "
        "como ACTIVA depois de um teste de ligação bem-sucedido ou de ter "
        "recebido eventos reais."
    ),
)
async def list_integrations(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INTEGRATIONS_READ))],
) -> list[IntegrationRead]:
    result = await session.execute(select(Integration).order_by(Integration.name))
    integrations = list(result.scalars())

    output: list[IntegrationRead] = []
    for integration in integrations:
        keys = await session.execute(
            select(ApiKey).where(
                ApiKey.integration_id == integration.id, ApiKey.is_active.is_(True)
            )
        )
        payload = IntegrationRead.model_validate(integration)
        payload.variaveis_em_falta = integration_service.missing_secrets(integration)
        payload.chaves_activas = len(list(keys.scalars()))
        output.append(payload)
    return output


@integration_router.post(
    "/{integration_id}/test",
    summary="Testar a ligação a um sistema externo",
    description=(
        "Contacta o serviço a sério. Nunca devolve sucesso sem resposta do "
        "outro lado; se faltarem credenciais, di-lo explicitamente."
    ),
)
async def test_integration(
    integration_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.INTEGRATIONS_MANAGE))],
) -> dict:
    integration = await integration_service.get_integration(session, integration_id)
    return await integration_service.test_connection(session, integration, ctx)


class ApiKeyCreate(ApiModel):
    name: str
    kind: SourceKind
    description: str = ""


@integration_router.post(
    "/api-keys",
    status_code=status.HTTP_201_CREATED,
    summary="Criar chave de ingestão",
    description=(
        "A chave em claro é devolvida uma única vez. A base de dados guarda "
        "apenas o seu hash."
    ),
)
async def create_api_key(
    payload: ApiKeyCreate,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[object, Depends(require(Permission.INTEGRATIONS_MANAGE))],
) -> dict:
    raw, api_key = await integration_service.create_ingestion_key(
        session,
        name=payload.name,
        kind=payload.kind.value,
        description=payload.description,
        created_by_id=user.id,
        ctx=ctx,
    )
    return {
        "id": str(api_key.id),
        "nome": api_key.name,
        "prefixo": api_key.key_prefix,
        "chave": raw,
        "aviso": (
            "Guarde esta chave agora: apenas o hash é persistido e não poderá "
            "voltar a ser apresentada."
        ),
    }


# ------------------------------------------------------------- notificações
class NotificationRead(ApiModel):
    id: uuid.UUID
    kind: str
    severity: str
    title: str
    body: str
    resource_type: str | None = None
    resource_id: uuid.UUID | None = None
    resource_reference: str | None = None
    read_at: datetime | None = None
    created_at: datetime


@notification_router.get(
    "", response_model=list[NotificationRead], summary="Notificações do utilizador"
)
async def my_notifications(
    session: SessionDep,
    user: CurrentUser,
    apenas_nao_lidas: Annotated[bool, Query()] = False,
    limite: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[NotificationRead]:
    stmt = select(Notification).where(Notification.user_id == user.id)
    if apenas_nao_lidas:
        stmt = stmt.where(Notification.read_at.is_(None))
    stmt = stmt.order_by(Notification.created_at.desc()).limit(limite)
    result = await session.execute(stmt)
    return [NotificationRead.model_validate(n) for n in result.scalars()]


@notification_router.post(
    "/{notification_id}/read", response_model=MessageResponse, summary="Marcar como lida"
)
async def mark_read(
    notification_id: uuid.UUID,
    session: SessionDep,
    user: CurrentUser,
) -> MessageResponse:
    from datetime import UTC

    notification = await session.get(Notification, notification_id)
    if notification is None or notification.user_id != user.id:
        raise NotFoundError("Notificação", notification_id)
    notification.read_at = datetime.now(UTC)
    return MessageResponse(mensagem="Notificação marcada como lida.")
