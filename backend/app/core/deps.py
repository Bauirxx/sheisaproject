"""Dependências de autenticação e autorização da API (§22, §23).

Decisão: **a autorização é sempre reconfirmada contra a base de dados.**

O access token transporta a lista de permissões, o que é conveniente para o
frontend saber o que apresentar. Mas a decisão de autorizar não usa essa lista:
usa o perfil actual do utilizador lido da base de dados. Caso contrário, revogar
uma permissão ou desactivar uma conta só teria efeito quando o token expirasse —
até 30 minutos de acesso indevido numa plataforma de segurança. O custo é uma
consulta indexada por pedido, com o perfil e as permissões carregados de uma vez.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.database import get_session
from app.core.errors import (
    AccountInactiveError,
    AuthenticationError,
    AuthorizationError,
    SessionExpiredError,
)
from app.core.permissions import Permission
from app.core.security import decode_access_token, hash_api_key
from app.models.identity import ApiKey, Role, User, UserSession

#: `auto_error=False` para que a ausência de credenciais produza o nosso formato
#: de erro em português em vez do formato por omissão do FastAPI.
_bearer = HTTPBearer(auto_error=False, description="Token de acesso (Bearer).")

SessionDep = Annotated[AsyncSession, Depends(get_session)]


def client_ip(request: Request) -> str | None:
    """IP do cliente, respeitando um proxy inverso de confiança.

    `X-Forwarded-For` só é considerado quando a aplicação está atrás de um
    proxy; caso contrário é trivialmente forjável por qualquer cliente e
    poluiria a auditoria com origens falsas.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and getattr(request.app.state, "trust_proxy_headers", False):
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def get_current_user(
    request: Request,
    session: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> User:
    if credentials is None or not credentials.credentials:
        raise AuthenticationError("É necessário autenticar-se para aceder a este recurso.")

    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise SessionExpiredError() from exc
    except jwt.PyJWTError as exc:
        raise AuthenticationError("Token de acesso inválido.") from exc

    try:
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
    except (KeyError, ValueError) as exc:
        raise AuthenticationError("Token de acesso malformado.") from exc

    # A sessão tem de continuar activa: é isto que torna a revogação imediata.
    user_session = await session.get(UserSession, session_id)
    if user_session is None or user_session.revoked_at is not None:
        raise SessionExpiredError("A sessão foi terminada.")
    if user_session.expires_at <= datetime.now(UTC):
        raise SessionExpiredError()
    if user_session.user_id != user_id:
        raise AuthenticationError("Token de acesso inconsistente.")

    result = await session.execute(
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.role).selectinload(Role.permissions))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise AuthenticationError("Utilizador não encontrado.")
    if not user.is_active:
        raise AccountInactiveError()

    request.state.user = user
    request.state.session_id = session_id
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_audit_context(request: Request) -> AuditContext:
    """Contexto de auditoria do pedido actual.

    Funciona com ou sem utilizador autenticado, para que tentativas de acesso
    não autenticadas também possam ser registadas.
    """
    user: User | None = getattr(request.state, "user", None)
    api_key: ApiKey | None = getattr(request.state, "api_key", None)

    return AuditContext(
        actor_id=user.id if user else None,
        actor_email=user.email if user else ("chave-api" if api_key else "anonimo"),
        actor_role=user.role.name if user and user.role else None,
        api_key_id=api_key.id if api_key else None,
        is_system=user is None,
        origin="ingestao" if api_key else "aplicacao_web",
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:255] or None,
        request_id=getattr(request.state, "request_id", None),
    )


AuditDep = Annotated[AuditContext, Depends(get_audit_context)]


def require(*permissions: Permission, require_all: bool = True):
    """Dependência que exige permissões, verificadas contra a base de dados.

    Uma negação é registada na auditoria com resultado NEGADO — saber o que foi
    tentado sem autorização é tão importante como saber o que foi feito.
    """
    codes = [p.value for p in permissions]

    async def _dependency(
        request: Request,
        session: SessionDep,
        user: CurrentUser,
        ctx: AuditDep,
    ) -> User:
        held = {p.code for p in user.role.permissions} if user.role else set()
        ok = held.issuperset(codes) if require_all else bool(held.intersection(codes))

        if not ok:
            missing = sorted(set(codes) - held)
            await audit.record_denied(
                session,
                ctx,
                action="ACESSO_NEGADO",
                resource_type=request.url.path,
                reason=f"permissões em falta: {', '.join(missing)}",
            )
            # Consolidamos o registo da negação: a excepção que se segue faz
            # rollback da transacção do pedido e levaria a auditoria com ela.
            await session.commit()
            raise AuthorizationError(required=", ".join(missing))

        return user

    return _dependency


async def authenticate_api_key(
    request: Request,
    session: AsyncSession,
    raw_key: str | None,
) -> ApiKey:
    """Valida uma chave de API de ingestão.

    A procura é feita pelo prefixo (indexado) e a confirmação pelo hash
    completo, evitando percorrer todas as chaves a cada evento recebido.
    """
    if not raw_key:
        raise AuthenticationError("Chave de API em falta.", code="CHAVE_API_EM_FALTA")

    prefix = raw_key[:8]
    key_hash = hash_api_key(raw_key)

    result = await session.execute(
        select(ApiKey).where(ApiKey.key_prefix == prefix, ApiKey.key_hash == key_hash)
    )
    api_key = result.scalar_one_or_none()

    if api_key is None or not api_key.is_active:
        raise AuthenticationError("Chave de API inválida.", code="CHAVE_API_INVALIDA")
    if api_key.expires_at is not None and api_key.expires_at <= datetime.now(UTC):
        raise AuthenticationError("Chave de API expirada.", code="CHAVE_API_EXPIRADA")

    api_key.last_used_at = datetime.now(UTC)
    api_key.use_count += 1
    request.state.api_key = api_key
    return api_key
