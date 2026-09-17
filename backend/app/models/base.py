"""Blocos comuns a todos os modelos.

Convenções adoptadas:

* **Chaves primárias UUIDv4.** Numa plataforma de segurança, identificadores
  sequenciais na API expõem volume de operação (quantos incidentes existem) e
  permitem enumeração. O identificador legível para humanos (INC-000125) existe
  em paralelo, gerado por sequência da base de dados.
* **Instantes sempre com fuso (`timestamptz`).** Um SOC correlaciona eventos de
  origens distintas; um timestamp ingénuo é uma fonte silenciosa de erro.
* **Nomenclatura explícita de restrições.** Sem isto o Alembic gera nomes
  automáticos que diferem entre ambientes e as migrações deixam de ser
  reversíveis de forma fiável.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
Base.metadata = MetaData(naming_convention=NAMING_CONVENTION)


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4, sort_order=-100
    )


def enum_column(py_enum: type, **kwargs: Any) -> Any:
    """Coluna de enumeração como VARCHAR com restrição CHECK.

    Preferimos isto ao tipo ENUM nativo do PostgreSQL: acrescentar um estado ao
    ciclo de vida passa a ser uma alteração de restrição em vez de um
    `ALTER TYPE`, que não pode correr dentro de uma transacção em versões mais
    antigas e complica os rollbacks.
    """
    return SAEnum(
        py_enum,
        native_enum=False,
        length=40,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
        **kwargs,
    )


class TimestampMixin:
    """Instantes de criação e actualização mantidos pela base de dados.

    `clock_timestamp()` e não `now()`. O `now()` do PostgreSQL devolve o início
    da **transacção**, e repete-o em todas as linhas dela: um pedido que crie um
    incidente, mude o estado e escreva um comentário gravava tudo com o mesmo
    instante. A linha temporal, que ordena tudo num só eixo, contava então a
    história ao contrário — ver a migração `0005_instantes_reais`.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.clock_timestamp(),
        index=True,
        sort_order=100,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.clock_timestamp(),
        onupdate=func.clock_timestamp(),
        sort_order=101,
    )


__all__ = [
    "JSONB",
    "PGUUID",
    "Base",
    "TimestampMixin",
    "enum_column",
    "uuid_pk",
]
