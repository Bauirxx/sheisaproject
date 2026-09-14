"""Rotas de autenticação — /api/auth."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.core.deps import AuditDep, CurrentUser, SessionDep
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    SessionRead,
    TokenResponse,
    UserDetail,
)
from app.schemas.common import MessageResponse
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["Autenticação"])


def _to_detail(user) -> UserDetail:
    return UserDetail(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        role=user.role,
        team=user.team,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        locked_until=user.locked_until,
        permissions=user.permission_codes,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Iniciar sessão",
    description=(
        "Autentica com credenciais e devolve um token de acesso de vida curta "
        "e um token de renovação. Após várias tentativas falhadas consecutivas "
        "a conta é temporariamente bloqueada."
    ),
)
async def login(
    payload: LoginRequest,
    session: SessionDep,
    ctx: AuditDep,
) -> TokenResponse:
    user, access, refresh_token, expires_at = await auth_service.authenticate(
        session, ctx, email=payload.email, password=payload.password
    )
    return TokenResponse(
        access_token=access,
        refresh_token=refresh_token,
        expires_at=expires_at,
        user=_to_detail(user),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renovar sessão",
    description=(
        "Troca um token de renovação por um novo par de tokens. O token "
        "anterior é revogado; reapresentá-lo revoga todas as sessões do "
        "utilizador, por ser indício de roubo de credenciais."
    ),
)
async def refresh(
    payload: RefreshRequest,
    session: SessionDep,
    ctx: AuditDep,
) -> TokenResponse:
    user, access, new_refresh, expires_at = await auth_service.refresh(
        session, ctx, raw_refresh_token=payload.refresh_token
    )
    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_at=expires_at,
        user=_to_detail(user),
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Terminar sessão",
)
async def logout(
    request: Request,
    session: SessionDep,
    ctx: AuditDep,
    user: CurrentUser,
) -> MessageResponse:
    await auth_service.logout(session, ctx, session_id=request.state.session_id)
    return MessageResponse(mensagem="Sessão terminada.")


@router.get(
    "/me",
    response_model=UserDetail,
    summary="Dados do utilizador autenticado",
    description="Inclui as permissões efectivas do perfil actual.",
)
async def me(user: CurrentUser) -> UserDetail:
    return _to_detail(user)


@router.get(
    "/sessions",
    response_model=list[SessionRead],
    summary="Sessões do utilizador autenticado",
    description="Permite ao utilizador detectar sessões que não reconhece.",
)
async def my_sessions(session: SessionDep, user: CurrentUser) -> list[SessionRead]:
    sessions = await auth_service.list_sessions(session, user.id)
    return [SessionRead.model_validate(s) for s in sessions]


@router.post(
    "/change-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Alterar a própria palavra-passe",
    description=(
        "Altera a palavra-passe do utilizador autenticado. As restantes "
        "sessões são terminadas."
    ),
)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    session: SessionDep,
    ctx: AuditDep,
    user: CurrentUser,
) -> MessageResponse:
    await auth_service.change_password(
        session,
        ctx,
        user=user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        current_session_id=getattr(request.state, "session_id", None),
    )
    return MessageResponse(
        mensagem="Palavra-passe alterada. As restantes sessões foram terminadas."
    )
