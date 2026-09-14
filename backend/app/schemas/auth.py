"""Esquemas de autenticação e de utilizadores."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.schemas.common import ApiInput, ApiModel, Email

#: Requisitos mínimos de palavra-passe. Alinhados com a NIST SP 800-63B:
#: privilegiar comprimento em vez de composição obrigatória, mas exigir alguma
#: variedade para travar as escolhas mais previsíveis.
MIN_PASSWORD_LENGTH = 12


def validate_password_strength(value: str) -> str:
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"A palavra-passe deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres."
        )
    if not re.search(r"[a-z]", value):
        raise ValueError("A palavra-passe deve conter pelo menos uma letra minúscula.")
    if not re.search(r"[A-Z]", value):
        raise ValueError("A palavra-passe deve conter pelo menos uma letra maiúscula.")
    if not re.search(r"\d", value):
        raise ValueError("A palavra-passe deve conter pelo menos um algarismo.")
    return value


# ------------------------------------------------------------------- entrada
class LoginRequest(ApiInput):
    email: Email
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(ApiInput):
    refresh_token: str = Field(min_length=1, max_length=512)


class ChangePasswordRequest(ApiInput):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(max_length=256)

    @field_validator("new_password")
    @classmethod
    def _strength(cls, v: str) -> str:
        return validate_password_strength(v)


class UserCreate(ApiInput):
    email: Email
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(max_length=256)
    role_name: str = Field(max_length=40)
    team_id: uuid.UUID | None = None
    must_change_password: bool = True

    @field_validator("password")
    @classmethod
    def _strength(cls, v: str) -> str:
        return validate_password_strength(v)


class UserUpdate(ApiInput):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    role_name: str | None = Field(default=None, max_length=40)
    team_id: uuid.UUID | None = None
    is_active: bool | None = None


class PasswordResetRequest(ApiInput):
    """Reposição de palavra-passe por um administrador."""

    new_password: str = Field(max_length=256)
    must_change_password: bool = True

    @field_validator("new_password")
    @classmethod
    def _strength(cls, v: str) -> str:
        return validate_password_strength(v)


# -------------------------------------------------------------------- saída
class PermissionRead(ApiModel):
    code: str
    description: str


class RoleRead(ApiModel):
    id: uuid.UUID
    name: str
    description: str
    is_system: bool
    permissions: list[PermissionRead]


class RoleSummary(ApiModel):
    id: uuid.UUID
    name: str
    description: str


class TeamRead(ApiModel):
    id: uuid.UUID
    name: str
    description: str
    is_active: bool


class UserRead(ApiModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    must_change_password: bool
    role: RoleSummary
    team: TeamRead | None = None
    last_login_at: datetime | None = None
    created_at: datetime


class UserDetail(UserRead):
    """Inclui as permissões efectivas, para o frontend adaptar a navegação."""

    permissions: list[str] = Field(default_factory=list)
    locked_until: datetime | None = None


class TokenResponse(ApiModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserDetail


class SessionRead(ApiModel):
    id: uuid.UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    ip_address: str | None
    user_agent: str | None
    revoked_at: datetime | None
