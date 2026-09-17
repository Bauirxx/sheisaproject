"""Referências a outros registos que chegam num pedido.

Um identificador de utilizador, equipa ou activo vindo do cliente não é uma
garantia de que o registo existe. Sem esta verificação, o identificador ia até à
base de dados, a chave estrangeira recusava-o, e a rota respondia 500 a um erro
do cliente. Onde a consulta era por lista (`id IN (...)`), os identificadores
inexistentes eram simplesmente ignorados: o incidente nascia sem o activo que o
analista tinha indicado, e nada o dizia.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection
from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError

Model = TypeVar("Model")


async def require_existing(
    session: AsyncSession, model: type[Any], identifier: uuid.UUID | None, name: str
) -> None:
    """Recusa com 404 um identificador que não corresponde a nenhum registo."""
    if identifier is not None and await session.get(model, identifier) is None:
        raise NotFoundError(name, identifier)


async def require_all_existing(
    session: AsyncSession, model: type[Model], identifiers: Collection[uuid.UUID], name: str
) -> list[Model]:
    """Devolve os registos pedidos, ou 404 com o primeiro que não existe."""
    wanted = list(dict.fromkeys(identifiers))
    if not wanted:
        return []
    found = {
        row.id: row
        for row in (await session.execute(select(model).where(model.id.in_(wanted)))).scalars()
    }
    for identifier in wanted:
        if identifier not in found:
            raise NotFoundError(name, identifier)
    return [found[identifier] for identifier in wanted]
