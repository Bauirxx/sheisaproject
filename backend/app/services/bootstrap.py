"""Inicialização da plataforma: permissões, perfis e conta de administração.

Idempotente por construção — correr de novo actualiza descrições e acrescenta
permissões novas sem destruir ajustes feitos pelo administrador. Em concreto,
se um administrador tiver removido uma permissão de um perfil, uma segunda
execução **não** a repõe: as permissões de semente aplicam-se apenas a perfis
criados nesse momento. Reinstalar silenciosamente permissões removidas seria
subverter uma decisão deliberada de segurança.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.permissions import (
    PERMISSION_DESCRIPTIONS,
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    RoleName,
)
from app.core.permissions import (
    Permission as PermissionCode,
)
from app.core.security import hash_password
from app.models.identity import Permission, Role, Team, User


async def sync_permissions(session: AsyncSession) -> tuple[int, int]:
    """Garante que todas as permissões do catálogo existem. (criadas, actualizadas)"""
    existing = {
        p.code: p for p in (await session.execute(select(Permission))).scalars().all()
    }
    created = updated = 0

    for code in PermissionCode:
        description = PERMISSION_DESCRIPTIONS.get(code, "")
        current = existing.get(code.value)
        if current is None:
            session.add(Permission(code=code.value, description=description))
            created += 1
        elif current.description != description:
            current.description = description
            updated += 1

    await session.flush()
    return created, updated


async def sync_roles(session: AsyncSession) -> tuple[int, int]:
    """Cria os perfis em falta. (criados, já existentes)"""
    all_permissions = {
        p.code: p for p in (await session.execute(select(Permission))).scalars().all()
    }
    existing = {
        r.name: r
        for r in (
            await session.execute(select(Role).options(selectinload(Role.permissions)))
        ).scalars().all()
    }
    created = kept = 0

    for role_name, permission_codes in ROLE_PERMISSIONS.items():
        description = ROLE_DESCRIPTIONS.get(role_name, "")
        role = existing.get(role_name.value)

        if role is None:
            role = Role(
                name=role_name.value,
                description=description,
                is_system=True,
                permissions=[
                    all_permissions[c.value]
                    for c in permission_codes
                    if c.value in all_permissions
                ],
            )
            session.add(role)
            created += 1
        else:
            # Só a descrição é sincronizada. As permissões atribuídas são
            # deixadas como estão, por respeito a ajustes deliberados.
            role.description = description
            kept += 1

    await session.flush()
    return created, kept


async def ensure_admin(
    session: AsyncSession,
    *,
    email: str,
    full_name: str = "Administrador",
    password: str | None = None,
) -> tuple[User, str | None]:
    """Cria a conta de administração se não existir.

    Devolve (utilizador, palavra-passe gerada ou None). A palavra-passe só é
    devolvida quando gerada nesta chamada — nunca é possível recuperá-la
    depois, porque apenas o hash é persistido.
    """
    email = email.lower().strip()
    result = await session.execute(
        select(User).where(User.email == email).options(selectinload(User.role))
    )
    user = result.scalar_one_or_none()
    if user is not None:
        return user, None

    role = (
        await session.execute(
            select(Role).where(Role.name == RoleName.ADMINISTRADOR.value)
        )
    ).scalar_one()

    generated = password is None
    raw_password = password or _generate_password()

    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(raw_password),
        role_id=role.id,
        is_active=True,
        # Obriga a alterar no primeiro acesso quando a palavra-passe foi gerada
        # e mostrada no terminal: um segredo que passou por um ecrã ou por um
        # ficheiro de log deixou de ser um segredo.
        must_change_password=generated,
        password_changed_at=datetime.now(UTC),
    )
    session.add(user)
    await session.flush()

    await audit.record(
        session,
        AuditContext(actor_email="sistema", is_system=True, origin="cli"),
        action="CRIAR_UTILIZADOR",
        resource_type="utilizador",
        resource_id=user.id,
        description=f"Conta de administração '{email}' criada na inicialização.",
    )
    return user, (raw_password if generated else None)


async def ensure_default_team(session: AsyncSession, name: str = "SOC") -> Team:
    result = await session.execute(select(Team).where(Team.name == name))
    team = result.scalar_one_or_none()
    if team is None:
        team = Team(
            name=name,
            description="Equipa de operações de segurança.",
            is_active=True,
        )
        session.add(team)
        await session.flush()
    return team


def _generate_password(length: int = 20) -> str:
    """Palavra-passe aleatória que satisfaz a política de complexidade."""
    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
        ):
            return candidate
