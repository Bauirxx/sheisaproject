"""Serviço de autenticação (§23).

Comportamentos com implicação de segurança, explicitados:

* **Resposta uniforme no login.** Utilizador inexistente, palavra-passe errada
  e conta inactiva produzem a mesma mensagem. Quando o utilizador não existe é
  feita uma verificação artificial de palavra-passe para que o tempo de
  resposta não denuncie a diferença (enumeração de contas).
* **Bloqueio progressivo.** Após `max_failed_logins` falhas consecutivas a
  conta fica bloqueada por `lockout_minutes`.
* **Rotação de refresh token.** Cada utilização emite um novo token e revoga o
  anterior. Se um token já usado reaparecer, é sinal de roubo: toda a família
  de sessões do utilizador é revogada.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.config import settings
from app.core.enums import AuditOutcome
from app.core.errors import (
    AccountInactiveError,
    AccountLockedError,
    InvalidCredentialsError,
    NotFoundError,
    SessionExpiredError,
    ValidationError,
)
from app.core.security import (
    create_access_token,
    dummy_verify,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    password_needs_rehash,
    verify_password,
)
from app.models.identity import Role, User, UserSession


async def _load_user_by_email(session: AsyncSession, email: str) -> User | None:
    result = await session.execute(
        select(User)
        .where(User.email == email.lower().strip())
        .options(selectinload(User.role).selectinload(Role.permissions))
    )
    return result.scalar_one_or_none()


async def _issue_session(
    session: AsyncSession,
    user: User,
    ctx: AuditContext,
) -> tuple[str, str, datetime, UserSession]:
    """Cria uma sessão e emite o par de tokens."""
    raw_refresh, refresh_hash = generate_refresh_token()

    user_session = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_hash,
        expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days),
        ip_address=ctx.ip_address,
        user_agent=ctx.user_agent,
        last_used_at=datetime.now(UTC),
    )
    session.add(user_session)
    # Necessário para obter o id da sessão antes de o inserir no access token.
    await session.flush()

    access_token, expires_at = create_access_token(
        subject=user.id,
        role=user.role.name,
        permissions=user.permission_codes,
        session_id=user_session.id,
    )
    return access_token, raw_refresh, expires_at, user_session


async def authenticate(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    email: str,
    password: str,
) -> tuple[User, str, str, datetime]:
    """Autentica e devolve (utilizador, access_token, refresh_token, expiração)."""
    user = await _load_user_by_email(session, email)
    now = datetime.now(UTC)

    if user is None:
        # Consome tempo comparável a uma verificação real.
        dummy_verify()
        await audit.record(
            session,
            ctx,
            action="LOGIN",
            resource_type="sessao",
            description=f"Tentativa de início de sessão para '{email}'.",
            outcome=AuditOutcome.FALHA,
            failure_reason="utilizador inexistente",
        )
        await session.commit()
        raise InvalidCredentialsError()

    ctx.actor_id = user.id
    ctx.actor_email = user.email

    if user.locked_until is not None and user.locked_until > now:
        await audit.record(
            session, ctx,
            action="LOGIN", resource_type="sessao", resource_id=user.id,
            description="Tentativa de acesso a conta bloqueada.",
            outcome=AuditOutcome.NEGADO, failure_reason="conta bloqueada",
        )
        await session.commit()
        raise AccountLockedError(
            "Conta bloqueada até "
            f"{user.locked_until.strftime('%H:%M')} por tentativas falhadas."
        )

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        reason = "palavra-passe incorrecta"
        if user.failed_login_count >= settings.max_failed_logins:
            user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            reason = (
                f"palavra-passe incorrecta ({user.failed_login_count} falhas) "
                "- conta bloqueada"
            )
        await audit.record(
            session, ctx,
            action="LOGIN", resource_type="sessao", resource_id=user.id,
            description="Início de sessão falhado.",
            outcome=AuditOutcome.FALHA, failure_reason=reason,
        )
        await session.commit()
        raise InvalidCredentialsError()

    if not user.is_active:
        await audit.record(
            session, ctx,
            action="LOGIN", resource_type="sessao", resource_id=user.id,
            description="Tentativa de acesso a conta desactivada.",
            outcome=AuditOutcome.NEGADO, failure_reason="conta inactiva",
        )
        await session.commit()
        raise AccountInactiveError()

    # Sucesso: limpa o contador e actualiza os parâmetros do hash se a política
    # de custo tiver subido desde a última vez.
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    access_token, raw_refresh, expires_at, user_session = await _issue_session(
        session, user, ctx
    )

    await audit.record(
        session, ctx,
        action="LOGIN", resource_type="sessao", resource_id=user_session.id,
        description=f"Sessão iniciada por {user.email}.",
    )
    return user, access_token, raw_refresh, expires_at


async def refresh(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    raw_refresh_token: str,
) -> tuple[User, str, str, datetime]:
    """Roda o refresh token e emite um novo par."""
    token_hash = hash_refresh_token(raw_refresh_token)
    result = await session.execute(
        select(UserSession).where(UserSession.refresh_token_hash == token_hash)
    )
    user_session = result.scalar_one_or_none()

    if user_session is None:
        raise SessionExpiredError("Token de renovação inválido.")

    now = datetime.now(UTC)

    if user_session.revoked_at is not None:
        # Um token já revogado a ser reapresentado indica reutilização: ou foi
        # roubado, ou houve uma condição de corrida. Em qualquer dos casos a
        # resposta segura é revogar todas as sessões do utilizador.
        await session.execute(
            update(UserSession)
            .where(
                UserSession.user_id == user_session.user_id,
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=now, revoked_reason="reutilizacao_de_token_detectada")
        )
        await audit.record(
            session, ctx,
            action="SESSAO_REVOGADA", resource_type="sessao",
            resource_id=user_session.user_id,
            description=(
                "Reutilização de token de renovação detectada. "
                "Todas as sessões do utilizador foram revogadas."
            ),
            outcome=AuditOutcome.NEGADO, failure_reason="reutilizacao_de_token",
        )
        await session.commit()
        raise SessionExpiredError(
            "Sessão terminada por motivos de segurança. Inicie sessão novamente."
        )

    if user_session.expires_at <= now:
        raise SessionExpiredError()

    result = await session.execute(
        select(User)
        .where(User.id == user_session.user_id)
        .options(selectinload(User.role).selectinload(Role.permissions))
    )
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise AccountInactiveError()

    ctx.actor_id = user.id
    ctx.actor_email = user.email

    # Rotação: a sessão anterior é revogada e substituída.
    user_session.revoked_at = now
    user_session.revoked_reason = "rotacao"

    access_token, raw_new_refresh, expires_at, new_session = await _issue_session(
        session, user, ctx
    )
    await audit.record(
        session, ctx,
        action="SESSAO_RENOVADA", resource_type="sessao", resource_id=new_session.id,
        description="Token de sessão renovado.",
    )
    return user, access_token, raw_new_refresh, expires_at


async def logout(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    session_id: uuid.UUID,
) -> None:
    user_session = await session.get(UserSession, session_id)
    if user_session is None or user_session.revoked_at is not None:
        return
    user_session.revoked_at = datetime.now(UTC)
    user_session.revoked_reason = "terminada_pelo_utilizador"
    await audit.record(
        session, ctx,
        action="LOGOUT", resource_type="sessao", resource_id=session_id,
        description="Sessão terminada pelo utilizador.",
    )


async def revoke_all_sessions(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    user_id: uuid.UUID,
    reason: str,
) -> int:
    """Revoga todas as sessões activas de um utilizador. Devolve quantas."""
    now = datetime.now(UTC)
    result = await session.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
        .returning(UserSession.id)
    )
    revoked = len(result.fetchall())
    if revoked:
        await audit.record(
            session, ctx,
            action="SESSOES_REVOGADAS", resource_type="utilizador", resource_id=user_id,
            description=f"{revoked} sessão(ões) revogada(s). Motivo: {reason}.",
        )
    return revoked


async def change_password(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    user: User,
    current_password: str,
    new_password: str,
    current_session_id: uuid.UUID | None = None,
) -> None:
    if not verify_password(current_password, user.password_hash):
        await audit.record(
            session, ctx,
            action="ALTERAR_PALAVRA_PASSE", resource_type="utilizador", resource_id=user.id,
            description="Tentativa falhada de alteração de palavra-passe.",
            outcome=AuditOutcome.FALHA, failure_reason="palavra-passe actual incorrecta",
        )
        await session.commit()
        raise InvalidCredentialsError("A palavra-passe actual está incorrecta.")

    if verify_password(new_password, user.password_hash):
        raise ValidationError("A nova palavra-passe tem de ser diferente da actual.")

    user.password_hash = hash_password(new_password)
    user.password_changed_at = datetime.now(UTC)
    user.must_change_password = False

    # Alterar a palavra-passe invalida as outras sessões: se a alteração foi
    # motivada por suspeita de compromisso, deixar sessões antigas abertas
    # anularia o efeito.
    now = datetime.now(UTC)
    stmt = update(UserSession).where(
        UserSession.user_id == user.id, UserSession.revoked_at.is_(None)
    )
    if current_session_id is not None:
        stmt = stmt.where(UserSession.id != current_session_id)
    await session.execute(
        stmt.values(revoked_at=now, revoked_reason="palavra_passe_alterada")
    )

    await audit.record(
        session, ctx,
        action="ALTERAR_PALAVRA_PASSE", resource_type="utilizador", resource_id=user.id,
        description="Palavra-passe alterada. Outras sessões foram terminadas.",
    )


async def list_sessions(session: AsyncSession, user_id: uuid.UUID) -> list[UserSession]:
    result = await session.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id)
        .order_by(UserSession.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


async def get_user_or_404(session: AsyncSession, user_id: uuid.UUID) -> User:
    result = await session.execute(
        select(User)
        .where(User.id == user_id)
        .options(selectinload(User.role).selectinload(Role.permissions))
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise NotFoundError("Utilizador", user_id)
    return user
