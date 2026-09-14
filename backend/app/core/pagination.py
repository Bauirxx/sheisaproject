"""Paginação, ordenação e envelope de listagem (§27)."""

from __future__ import annotations

from typing import Annotated, Any, Generic, Sequence, TypeVar

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ValidationError

T = TypeVar("T")


class PageParams(BaseModel):
    """Parâmetros de paginação e ordenação comuns a todas as listagens."""

    page: int = Field(default=1, ge=1, description="Número da página (começa em 1).")
    size: int = Field(default=25, ge=1, le=200, description="Registos por página.")
    sort: str | None = Field(
        default=None,
        description="Campo de ordenação. Prefixe com '-' para ordem descendente.",
    )

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.size


def page_params(
    page: Annotated[int, Query(ge=1, description="Número da página.")] = 1,
    size: Annotated[int, Query(ge=1, le=200, description="Registos por página.")] = 25,
    sort: Annotated[str | None, Query(description="Ordenação, ex.: '-created_at'.")] = None,
) -> PageParams:
    return PageParams(page=page, size=size, sort=sort)


class Page(BaseModel, Generic[T]):
    """Envelope de resposta paginada."""

    itens: list[T]
    total: int = Field(description="Total de registos que satisfazem o filtro.")
    pagina: int
    tamanho: int
    total_paginas: int

    @classmethod
    def build(cls, items: Sequence[T], total: int, params: PageParams) -> "Page[T]":
        total_pages = (total + params.size - 1) // params.size if total else 0
        return cls(
            itens=list(items),
            total=total,
            pagina=params.page,
            tamanho=params.size,
            total_paginas=total_pages,
        )


def apply_sort(stmt: Select, model: Any, sort: str | None, *, allowed: set[str],
               default: str = "-created_at") -> Select:
    """Aplica ordenação validada contra uma lista branca.

    A lista branca não é cosmética: aceitar um nome de coluna arbitrário vindo
    do cliente permitiria ordenar por colunas sensíveis (por exemplo
    `password_hash`) e inferir o seu conteúdo a partir da ordem devolvida.
    """
    expression = sort or default
    descending = expression.startswith("-")
    field = expression.lstrip("-+")

    if field not in allowed:
        raise ValidationError(
            f"Não é possível ordenar por '{field}'.",
            code="ORDENACAO_INVALIDA",
            details={"campos_permitidos": sorted(allowed)},
        )

    column = getattr(model, field)
    return stmt.order_by(desc(column) if descending else asc(column))


async def paginate(
    session: AsyncSession,
    stmt: Select,
    params: PageParams,
) -> tuple[Sequence[Any], int]:
    """Executa a consulta paginada e devolve (registos, total).

    A contagem é feita sobre a mesma consulta sem ordenação nem limites,
    envolvida numa subconsulta, para que filtros e junções sejam exactamente os
    mesmos — um total calculado por uma consulta paralela divergiria assim que
    os filtros evoluíssem.
    """
    count_stmt = select(func.count()).select_from(
        stmt.order_by(None).options().subquery()
    )
    total = (await session.execute(count_stmt)).scalar_one()

    result = await session.execute(stmt.offset(params.offset).limit(params.size))
    return result.scalars().unique().all(), int(total)
