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
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

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


def _fit(value: str | None, limit: int) -> str | None:
    """Ajusta um texto ao comprimento da coluna, assinalando o corte."""
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "~"


def _serialise(value: Any) -> Any:
    """Converte um valor para algo representável em JSONB."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, list | tuple | set):
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
    """Identidade e origem de quem age.

    **A identidade é resolvida no momento em que é lida, não quando o contexto
    é construído.** Isto não é uma subtileza de estilo: o FastAPI resolve as
    dependências pela ordem em que aparecem na assinatura, e o contexto de
    auditoria é quase sempre declarado antes da dependência que autentica o
    utilizador. Se a identidade fosse capturada na construção, todas as acções
    autenticadas ficariam registadas como anónimas — exactamente o contrário do
    que o §16 exige, e com o efeito colateral de desactivar a separação de
    funções, que compara o autor de uma proposta com o seu aprovador.

    Cada campo pode ser sobreposto explicitamente (o serviço de autenticação
    fá-lo durante o login, quando ainda não existe sessão); na ausência de
    sobreposição, o valor é lido do pedido no instante do acesso.
    """

    __slots__ = (
        "_actor_email",
        "_actor_id",
        "_actor_role",
        "_api_key_id",
        "_ip_address",
        "_is_system",
        "_origin",
        "_request",
        "_request_id",
        "_user_agent",
    )

    def __init__(
        self,
        *,
        request: object | None = None,
        actor_id: uuid.UUID | None = None,
        actor_email: str | None = None,
        actor_role: str | None = None,
        api_key_id: uuid.UUID | None = None,
        is_system: bool | None = None,
        origin: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> None:
        self._request = request
        self._actor_id = actor_id
        self._actor_email = actor_email
        self._actor_role = actor_role
        self._api_key_id = api_key_id
        self._is_system = is_system
        self._ip_address = ip_address
        self._user_agent = user_agent
        self._request_id = request_id
        self._origin = origin

    @property
    def origin(self) -> str:
        """Origem da acção: só se sabe que é ingestão depois de validada a chave."""
        if self._origin is not None:
            return self._origin
        if self._state("api_key") is not None:
            return "ingestao"
        return "aplicacao_web"

    @origin.setter
    def origin(self, value: str) -> None:
        self._origin = value

    # --- resolução tardia a partir do pedido ---
    def _state(self, name: str):
        request = self._request
        if request is None:
            return None
        return getattr(request.state, name, None)

    @property
    def actor_id(self) -> uuid.UUID | None:
        if self._actor_id is not None:
            return self._actor_id
        user = self._state("user")
        return user.id if user is not None else None

    @actor_id.setter
    def actor_id(self, value: uuid.UUID | None) -> None:
        self._actor_id = value

    @property
    def actor_email(self) -> str:
        if self._actor_email is not None:
            return self._actor_email
        user = self._state("user")
        if user is not None:
            return user.email
        if self._state("api_key") is not None or self._api_key_id is not None:
            return "chave-api"
        return "sistema" if self._request is None else "anonimo"

    @actor_email.setter
    def actor_email(self, value: str) -> None:
        self._actor_email = value

    @property
    def actor_role(self) -> str | None:
        if self._actor_role is not None:
            return self._actor_role
        user = self._state("user")
        return user.role.name if user is not None and user.role else None

    @actor_role.setter
    def actor_role(self, value: str | None) -> None:
        self._actor_role = value

    @property
    def api_key_id(self) -> uuid.UUID | None:
        if self._api_key_id is not None:
            return self._api_key_id
        api_key = self._state("api_key")
        return api_key.id if api_key is not None else None

    @api_key_id.setter
    def api_key_id(self, value: uuid.UUID | None) -> None:
        self._api_key_id = value

    @property
    def is_system(self) -> bool:
        """Só é verdadeiro quando não existe nenhum actor identificável."""
        if self._is_system is not None:
            return self._is_system
        return self.actor_id is None and self.api_key_id is None

    @is_system.setter
    def is_system(self, value: bool) -> None:
        self._is_system = value

    @property
    def ip_address(self) -> str | None:
        return self._ip_address

    @ip_address.setter
    def ip_address(self, value: str | None) -> None:
        self._ip_address = value

    @property
    def user_agent(self) -> str | None:
        return self._user_agent

    @user_agent.setter
    def user_agent(self, value: str | None) -> None:
        self._user_agent = value

    @property
    def request_id(self) -> str | None:
        if self._request_id is not None:
            return self._request_id
        return self._state("request_id")

    @request_id.setter
    def request_id(self, value: str | None) -> None:
        self._request_id = value

    @classmethod
    def system(cls, origin: str = "motor") -> AuditContext:
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
    # Truncagem defensiva dos campos de comprimento limitado.
    #
    # Um valor demasiado longo faria a inserção falhar, e como a auditoria
    # partilha a transacção com a operação que descreve, a falha propagar-se-ia
    # ao pedido — chegámos a ver um 403 legítimo a transformar-se num 500 por
    # causa de um caminho com 55 caracteres numa coluna de 40. A auditoria
    # nunca deve ser a causa da falha daquilo que regista.
    entry = AuditLog(
        created_at=datetime.now(UTC),
        actor_id=context.actor_id,
        actor_email=_fit(context.actor_email, 254),
        actor_role=_fit(context.actor_role, 40),
        api_key_id=context.api_key_id,
        is_system_actor=context.is_system,
        action=_fit(action, 80),
        resource_type=_fit(resource_type, 40),
        resource_id=resource_id,
        resource_reference=_fit(resource_reference, 24),
        description=description,
        old_value=_serialise(old_value) if old_value else None,
        new_value=_serialise(new_value) if new_value else None,
        changed_fields=changed_fields or [],
        origin=_fit(context.origin, 30),
        ip_address=_fit(context.ip_address, 45),
        user_agent=_fit(context.user_agent, 255),
        request_id=_fit(context.request_id, 36),
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
