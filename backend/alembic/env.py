"""Ambiente Alembic (assíncrono).

A URL de ligação vem sempre de `app.core.config`, isto é, das variáveis de
ambiente — nunca do `alembic.ini`, que é versionado.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy import pool

from app.core.config import settings

# Importar o pacote de modelos regista todas as tabelas no metadata.
import app.models  # noqa: F401
from app.models import Base

config = context.config
config.set_main_option("sqlalchemy.url", settings.effective_database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Ignora objectos que não pertencem ao esquema da aplicação."""
    if type_ == "table" and name in {"spatial_ref_sys"}:
        return False
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=settings.effective_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
elif (injected := config.attributes.get("connection")) is not None:
    # Ligação fornecida por quem chama (a suite de testes migra a base de dados
    # de teste a partir de um ciclo de eventos já a correr). Sem este ramo,
    # `asyncio.run` abaixo rebentaria com "cannot be called from a running
    # event loop" e as migrações só seriam aplicáveis pela linha de comandos —
    # o que obrigaria os testes a criar o esquema a partir dos metadados e a
    # perder os gatilhos de imutabilidade da auditoria, que só existem nas
    # migrações.
    _do_run_migrations(injected)
else:
    asyncio.run(run_migrations_online())
