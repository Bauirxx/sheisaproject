"""Inicialização da plataforma: permissões, perfis e conta de administração.

Idempotente por construção — correr de novo actualiza descrições e acrescenta
permissões novas sem destruir ajustes feitos pelo administrador. Em concreto,
se um administrador tiver removido uma permissão de um perfil, uma segunda
execução **não** a repõe. Reinstalar silenciosamente permissões removidas seria
subverter uma decisão deliberada de segurança.

O que distingue as duas situações é a idade da permissão. Uma permissão **criada
nesta execução** — trazida por uma actualização — nunca pode ter sido retirada
por ninguém, e é atribuída aos perfis que a devem ter, incluindo os que já
existiam. Antes, só os perfis criados no momento a recebiam: numa instalação
actualizada, a funcionalidade nova ficava recusada a toda a gente, porque as
rotas verificam as permissões guardadas na base de dados.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Collection
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

logger = logging.getLogger("sheisa.arranque")


async def permissoes_ausentes_na_base(session: AsyncSession) -> list[str]:
    """Códigos de permissão que as rotas exigem e a base de dados não tem.

    As rotas verificam as permissões **guardadas na base**, não este catálogo.
    Uma permissão acrescentada ao código e nunca criada na base faz as rotas que
    a exigem responder 403 a todos os perfis, incluindo o ADMINISTRADOR, a quem
    `ROLE_PERMISSIONS` dá todas. É a falha fechada certa, mas indistinguível de
    "este perfil não tem essa permissão" — e é por isso que precisa de ser dita.
    """
    existentes = set(
        (await session.execute(select(Permission.code))).scalars().all()
    )
    return sorted({codigo.value for codigo in PermissionCode} - existentes)


async def avisar_de_permissoes_em_falta(session: AsyncSession) -> list[str]:
    """Regista o que falta e o comando que o resolve. Devolve o que encontrou."""
    em_falta = await permissoes_ausentes_na_base(session)
    if em_falta:
        logger.warning(
            "%d permissao(oes) exigida(s) pelas rotas nao existem na base de "
            "dados: %s. Enquanto assim for, essas rotas respondem 403 a TODOS os "
            "perfis. Corra `python -m scripts.manage init` (e idempotente).",
            len(em_falta),
            ", ".join(em_falta),
        )
    return em_falta


async def sync_permissions(session: AsyncSession) -> tuple[list[str], int]:
    """Garante que todas as permissões do catálogo existem.

    Devolve (códigos criados nesta execução, número de descrições actualizadas).
    Os códigos criados são o que `sync_roles` precisa para os atribuir.
    """
    existing = {
        p.code: p for p in (await session.execute(select(Permission))).scalars().all()
    }
    created: list[str] = []
    updated = 0

    for code in PermissionCode:
        description = PERMISSION_DESCRIPTIONS.get(code, "")
        current = existing.get(code.value)
        if current is None:
            session.add(Permission(code=code.value, description=description))
            created.append(code.value)
        elif current.description != description:
            current.description = description
            updated += 1

    await session.flush()
    return created, updated


async def sync_roles(
    session: AsyncSession, new_permissions: Collection[str] = ()
) -> tuple[int, int, int]:
    """Cria os perfis em falta e dá aos existentes as permissões novas que lhes cabem.

    `new_permissions` são os códigos que `sync_permissions` acabou de criar.
    Devolve (perfis criados, perfis já existentes, atribuições novas).
    """
    all_permissions = {
        p.code: p for p in (await session.execute(select(Permission))).scalars().all()
    }
    existing = {
        r.name: r
        for r in (
            await session.execute(select(Role).options(selectinload(Role.permissions)))
        ).scalars().all()
    }
    created = kept = granted = 0
    new_codes = set(new_permissions)

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
            # A descrição é sincronizada; das permissões, só se acrescentam as
            # que nasceram nesta execução. As restantes ficam como estão, por
            # respeito a ajustes deliberados.
            role.description = description
            held = {p.code for p in role.permissions}
            for code in sorted({c.value for c in permission_codes} & new_codes - held):
                role.permissions.append(all_permissions[code])
                granted += 1
            kept += 1

    await session.flush()
    return created, kept, granted


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
