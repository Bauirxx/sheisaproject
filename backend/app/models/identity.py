"""Identidade, perfis, permissões e sessões (§22, §23)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, PGUUID, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    pass


#: Associação perfil <-> permissão. Tabela de junção pura, sem atributos
#: próprios, pelo que é declarada como Table em vez de modelo.
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id",
        PGUUID(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        PGUUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Permission(Base, TimestampMixin):
    """Permissão atómica no formato `recurso:acção`."""

    __tablename__ = "permissions"

    id: Mapped[uuid.UUID] = uuid_pk()
    code: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    roles: Mapped[list["Role"]] = relationship(
        secondary=role_permissions, back_populates="permissions", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover - diagnóstico
        return f"<Permission {self.code}>"


class Role(Base, TimestampMixin):
    """Perfil de acesso. As permissões efectivas vivem na base de dados, não no
    código, para que um administrador as possa ajustar sem um novo deploy."""

    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Perfis do sistema não podem ser eliminados; as suas permissões podem
    #: ainda assim ser ajustadas.
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    permissions: Mapped[list[Permission]] = relationship(
        secondary=role_permissions, back_populates="roles", lazy="selectin"
    )
    users: Mapped[list["User"]] = relationship(back_populates="role", lazy="noload")

    @property
    def permission_codes(self) -> list[str]:
        return sorted(p.code for p in self.permissions)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Role {self.name}>"


class Team(Base, TimestampMixin):
    """Equipa responsável (§7: o incidente tem responsável *e* equipa)."""

    __tablename__ = "teams"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    members: Mapped[list["User"]] = relationship(back_populates="team", lazy="noload")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: Argon2id. Nunca sai da base de dados nem aparece em serializações.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    role_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    #: Obriga a alterar a palavra-passe no primeiro início de sessão.
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # --- protecção contra ataques por força bruta (§23) ---
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    role: Mapped[Role] = relationship(back_populates="users", lazy="selectin")
    team: Mapped[Team | None] = relationship(back_populates="members", lazy="selectin")
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="noload"
    )

    @property
    def permission_codes(self) -> list[str]:
        return self.role.permission_codes if self.role else []

    def has_permission(self, code: str) -> bool:
        return any(p.code == code for p in self.role.permissions) if self.role else False

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.email}>"


class UserSession(Base, TimestampMixin):
    """Sessão de refresh. Guardamos apenas o hash do token.

    Persistir sessões é o que torna a revogação possível: terminar sessão,
    desactivar um utilizador ou detectar reutilização de um token roubado
    passam a ter efeito imediato, ao contrário de um JWT puro que continuaria
    válido até expirar.
    """

    __tablename__ = "user_sessions"
    __table_args__ = (
        Index("ix_user_sessions_user_active", "user_id", "revoked_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    refresh_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)

    #: Contexto de origem, útil na auditoria e na detecção de sessões anómalas.
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions", lazy="selectin")

    @property
    def is_active(self) -> bool:
        from datetime import UTC

        return self.revoked_at is None and self.expires_at > datetime.now(UTC)


class ApiKey(Base, TimestampMixin):
    """Credencial de máquina para fontes de ingestão (§8).

    Cada fonte de alertas recebe a sua chave, de modo que a origem de qualquer
    evento seja atribuível e revogável isoladamente. Persistimos apenas o hash,
    mais um prefixo em claro que serve de índice de procura e permite à UI
    identificar a chave sem a revelar.
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint("name", name="uq_api_keys_name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    integration: Mapped["Integration | None"] = relationship(  # noqa: F821
        back_populates="api_keys", lazy="selectin"
    )
