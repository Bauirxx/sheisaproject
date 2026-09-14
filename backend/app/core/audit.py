"""Serviço de auditoria (§16).

A auditoria é escrita no backend, dentro da mesma transacção que a alteração
que descreve. Isto tem uma consequência importante e desejada: se a escrita da
auditoria falhar, a alteração também é revertida. Não existe estado alterado
sem registo correspondente.

O par (valor anterior, valor novo) é obrigatório nas actualizações. `diff_model`
calcula-o a partir do próprio objecto SQLAlchemy, usando o histórico de
alterações da sessão, em vez de exigir que cada serviço se lembre de capturar
os valores antigos à mão — o que mais cedo ou mais tarde alguém esqueceria.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Iterable

from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AuditOutcome
from app.models.system import AuditLog

#: Campos que nunca podem aparecer num registo de auditoria.
REDACTED_FIELDS = frozenset({
    "password", "password_hash", "senha", "refresh_token_hash",
    "key_hash", "api_key", "secret", "token",
})
REDACTED_PLACEHOLDER = "[omitido]"


def _serialise(value: Any) -> Any:
    """Converte um valor para algo representável em JSONB."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (list, tuple, set)):
        return [_serialise(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialise(v) for k, v in value.items()}
    return str(value)


def diff_model(instance: Any, *, only: Iterable[str] | None = None) -> tuple[dict, dict, list[str]]:
    """Extrai (valores anteriores, valores novos, campos alterados).

    Usa o histórico de atributos da sessão SQLAlchemy, pelo que tem de ser
    chamado **antes** do commit ou flush que consolida as alterações.
    """
    state = inspect(instance)
    allowed = set(only) if only is not None else None

    old: dict[str, Any] = {}
    new: dict[str, Any] = {}
    changed: list[str] = []

    for attr in state.mapper.column_attrs:
        name = attr.key
        if allowed is not None and name not in allowed:
            continue
        history = state.attrs[name].history
        if not history.has_changes():
            continue

        changed.append(name)
        if name in REDACTED_FIELDS:
            old[name] = REDACTED_PLACEHOLDER
            new[name] = REDACTED_PLACEHOLDER
            continue
        old[name] = _serialise(history.deleted[0]) if history.deleted else None
        new[name] = _serialise(history.added[0]) if history.added else None

    return old, new, changed


class AuditContext:
    """Identidade e origem de quem age. Preenchido pelas dependências da API."""

    __slots__ = (
        "actor_id", "actor_email", "actor_role", "api_key_id",
        "is_system", "origin", "ip_address", "user_agent", "request_id",
    )

    def __init__(
        self,
        *,
        actor_id: uuid.UUID | None = None,
        actor_email: str = "sistema",
        actor_role: str | None = None,
        api_key_id: uuid.UUID | None = None,
        is_system: bool = False,
        origin: str = "aplicacao_web",
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> None:
        self.actor_id = actor_id
        self.actor_email = actor_email
        self.actor_role = actor_role
        self.api_key_id = api_key_id
        self.is_system = is_system
        self.origin = origin
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.request_id = request_id

    @classmethod
    def system(cls, origin: str = "motor") -> "AuditContext":
        """Contexto para acções sem actor humano (motores, playbooks)."""
        return cls(actor_email="sistema", is_system=True, origin=origin)


async def record(
    session: AsyncSession,
    context: AuditContext,
    *,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | None = None,
    resource_reference: str | None = None,
    description: str = "",
    old_value: dict | None = None,
    new_value: dict | None = None,
    changed_fields: list[str] | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCESSO,
    failure_reason: str | None = None,
) -> AuditLog:
    """Escreve uma entrada de auditoria na sessão actual.

    Não faz commit: a entrada é consolidada com a transacção do pedido, o que
    garante o acoplamento entre alteração e registo.
    """
    entry = AuditLog(
        created_at=datetime.now(UTC),
        actor_id=context.actor_id,
        actor_email=context.actor_email,
        actor_role=context.actor_role,
        api_key_id=context.api_key_id,
        is_system_actor=context.is_system,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_reference=resource_reference,
        description=description,
        old_value=_serialise(old_value) if old_value else None,
        new_value=_serialise(new_value) if new_value else None,
        changed_fields=changed_fields or [],
        origin=context.origin,
        ip_address=context.ip_address,
        user_agent=context.user_agent,
        request_id=context.request_id,
        outcome=outcome,
        failure_reason=failure_reason,
    )
    session.add(entry)
    return entry


async def record_change(
    session: AsyncSession,
    context: AuditContext,
    instance: Any,
    *,
    action: str,
    resource_type: str,
    description: str = "",
    only: Iterable[str] | None = None,
) -> AuditLog | None:
    """Regista uma alteração calculando o diff a partir do objecto.

    Devolve `None` quando nada mudou de facto — registar uma "alteração" sem
    alterações apenas encheria o registo de ruído.
    """
    old, new, changed = diff_model(instance, only=only)
    if not changed:
        return None
    return await record(
        session,
        context,
        action=action,
        resource_type=resource_type,
        resource_id=getattr(instance, "id", None),
        resource_reference=getattr(instance, "reference", None),
        description=description,
        old_value=old,
        new_value=new,
        changed_fields=changed,
    )


async def record_denied(
    session: AsyncSession,
    context: AuditContext,
    *,
    action: str,
    resource_type: str,
    reason: str,
    resource_id: uuid.UUID | None = None,
) -> AuditLog:
    """Regista uma tentativa negada.

    Tão importante como registar o que foi feito é registar o que foi tentado
    sem autorização — é isso que revela uma conta comprometida ou um abuso.
    """
    return await record(
        session,
        context,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=f"Tentativa negada: {reason}",
        outcome=AuditOutcome.NEGADO,
        failure_reason=reason,
    )
