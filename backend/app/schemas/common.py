"""Tipos partilhados pelos esquemas da API."""

from __future__ import annotations

import contextlib
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field


class ApiModel(BaseModel):
    """Base dos esquemas de resposta, com leitura a partir de objectos ORM."""

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class ApiInput(BaseModel):
    """Base dos esquemas de entrada.

    `extra="forbid"` é deliberado: um campo desconhecido no corpo do pedido
    quase sempre significa um erro do cliente (nome trocado) e falhar em voz
    alta é preferível a ignorar silenciosamente uma alteração que o utilizador
    julga ter feito.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ErrorDetail(ApiModel):
    codigo: str
    mensagem: str
    detalhes: dict[str, Any] | None = None


class ErrorResponse(ApiModel):
    erro: ErrorDetail


class MessageResponse(ApiModel):
    mensagem: str


class UserSummary(ApiModel):
    """Representação mínima de um utilizador, usada em referências."""

    id: uuid.UUID
    full_name: str = Field(serialization_alias="nome")
    email: str

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class ReferenceSummary(ApiModel):
    """Referência genérica a um recurso, para navegação no frontend."""

    id: uuid.UUID
    referencia: str | None = None
    titulo: str | None = None
    tipo: str


class TimestampedModel(ApiModel):
    created_at: datetime
    updated_at: datetime


# ----------------------------------------------------------------- endereços
import email_validator as _email_validator  # noqa: E402

#: Domínios de uso interno que o `email_validator` recusa por omissão mas que
#: são correntes em redes corporativas e em laboratórios. Removê-los da lista
#: de nomes reservados é a forma documentada de os permitir. A plataforma nunca
#: envia correio, pelo que a entregabilidade é irrelevante: recusar
#: `admin@sheisa.local` seria rejeitar um identificador perfeitamente válido.
_DOMINIOS_INTERNOS_PERMITIDOS = ("local", "internal", "lan", "intranet", "corp", "home")

for _nome in _DOMINIOS_INTERNOS_PERMITIDOS:
    # `suppress` porque a lista varia entre versoes da biblioteca: um nome
    # ausente nao e erro, apenas significa que ja era permitido.
    with contextlib.suppress(ValueError):
        _email_validator.SPECIAL_USE_DOMAIN_NAMES.remove(_nome)


def _normalise_email(value: str) -> str:
    """Valida a sintaxe e normaliza um endereço de correio electrónico.

    A normalização para minúsculas garante que a unicidade imposta em base de
    dados não é contornável pela capitalização — sem ela, `Admin@x.pt` e
    `admin@x.pt` seriam duas contas distintas.
    """
    if not isinstance(value, str):
        raise ValueError("O endereço deve ser texto.")
    candidate = value.strip()
    if len(candidate) > 254:
        raise ValueError("O endereço é demasiado longo.")
    try:
        info = _email_validator.validate_email(candidate, check_deliverability=False)
    except _email_validator.EmailNotValidError as exc:
        raise ValueError(f"Endereço de correio electrónico inválido: {exc}") from exc
    return info.normalized.lower()


#: Endereço de correio electrónico validado e normalizado.
Email = Annotated[str, AfterValidator(_normalise_email)]
