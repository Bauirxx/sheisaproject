"""Sessão e motor da base de dados.

Uma sessão por pedido, com commit explícito no fim do handler. Não usamos
autocommit: uma operação que falhe a meio (por exemplo, a criação de um
incidente cujo registo de auditoria rebenta) tem de reverter por inteiro, caso
contrário a auditoria deixaria de ser fiável (§16).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Base declarativa de todos os modelos."""

    type_annotation_map: dict[Any, Any] = {}


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.effective_database_url,
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
            future=True,
        )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
            # `autoflush=True` (o valor por omissão do SQLAlchemy) é aqui uma
            # decisão de correcção, não de conveniência. Com autoflush
            # desactivado, uma alteração ainda por escrever é invisível às
            # consultas seguintes da mesma transacção — e o motor de
            # inteligência, que lê o que acabou de ser escrito para calcular
            # pontuações, produzia resultados silenciosamente errados em vez de
            # falhar. Preferimos um flush a mais a uma pontuação inventada.
            autoflush=True,
        )
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """Dependência FastAPI: uma sessão transaccional por pedido."""
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
