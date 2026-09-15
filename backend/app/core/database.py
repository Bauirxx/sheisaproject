"""Sessão e motor da base de dados.

Uma sessão por pedido, com commit explícito no fim do handler. Não usamos
autocommit: uma operação que falhe a meio (por exemplo, a criação de um
incidente cujo registo de auditoria rebenta) tem de reverter por inteiro, caso
contrário a auditoria deixaria de ser fiável (§16).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Base declarativa de todos os modelos.

    `eager_defaults=True` não é uma afinação de desempenho — é uma correcção.

    Colunas geradas pelo servidor (`created_at`, e sobretudo `updated_at`, que
    tem `onupdate=func.now()`) são, por omissão, *expiradas* depois de um flush:
    o SQLAlchemy sabe que o valor em memória ficou obsoleto e vai relê-lo do
    servidor no próximo acesso. Esse acesso é síncrono, e numa aplicação
    assíncrona acontece tipicamente já durante a serialização da resposta —
    fora do contexto em que é possível fazer E/S. O resultado era um
    `MissingGreenlet` a transformar-se num 500.

    O sintoma era intermitente porque só surgia quando algo forçava um flush
    entre a alteração e a resposta: marcar um incidente como falso positivo
    consulta os alertas associados, e essa consulta faz autoflush. A mesma rota
    com outro estado de destino funcionava.

    Com `eager_defaults`, o PostgreSQL devolve os valores gerados na própria
    instrução (RETURNING). Nada fica expirado, não há leitura tardia, e não há
    viagem adicional à base de dados.
    """

    __mapper_args__: ClassVar[dict[str, Any]] = {"eager_defaults": True}
    type_annotation_map: ClassVar[dict[Any, Any]] = {}


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
