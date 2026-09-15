"""Infraestrutura da suite de testes (§32).

Quatro decisões governam este ficheiro. Nenhuma é arbitrária e todas têm
consequências se forem invertidas, por isso ficam explicadas.

**1. O esquema é criado pelas migrações, não por `Base.metadata.create_all`.**
A imutabilidade da auditoria não vive no modelo SQLAlchemy: vive em gatilhos
PostgreSQL criados pelas migrações `0002` e `0003`. Um esquema criado a partir
dos metadados teria as tabelas todas e nenhuma das garantias — e o teste que
verifica que um UPDATE à auditoria é recusado passaria a testar nada. Correr
`alembic upgrade head` também põe as próprias migrações sob teste.

**2. Cada teste corre dentro de uma transacção que é revertida no fim.**
A alternativa habitual — limpar as tabelas entre testes — é impossível aqui por
construção: os gatilhos de `audit_logs` recusam DELETE e TRUNCATE. Não é um
inconveniente, é a funcionalidade a fazer o seu trabalho. A sessão é ligada a
uma ligação com transacção aberta e `join_transaction_mode="create_savepoint"`,
pelo que os `commit()` que a aplicação faz de verdade libertam um savepoint em
vez de escreverem definitivamente, e o rollback exterior leva tudo.

**3. As permissões, os perfis e as contas são semeados uma vez por sessão.**
O Argon2id é deliberadamente lento — é essa a sua utilidade. Criar quatro
contas por teste multiplicaria esse custo por todos os testes da suite. A
semente é escrita de verdade, fora do alcance do rollback de cada teste.

**4. A limitação de taxa está desligada por omissão.**
Com 10 autenticações por minuto, uma suite que faz login em cada teste bateria
no limite e produziria falhas que nada têm a ver com o que se está a testar.
`settings.rate_limit_enabled` é lido a cada pedido, pelo que o teste que
verifica a limitação volta a ligá-la só para si (ver `rate_limit_ligado`).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

# O ambiente tem de ser fixado antes de `app.core.config` ser importado: as
# definições são um singleton e `effective_database_url` decide com base nele.
os.environ["SHEISA_ENVIRONMENT"] = "test"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.database import get_session
from app.core.security import hash_password
from app.main import app as fastapi_app

#: Palavras-passe das contas de teste. Cumprem `validate_password_strength`
#: (>= 12 caracteres, minúscula, maiúscula e algarismo) para que as contas
#: possam ser criadas pelo mesmo caminho que a aplicação usa.
SENHA = "TesteSeguro2026"

#: Contas criadas uma vez por sessão, uma por perfil relevante.
CONTAS: dict[str, str] = {
    "admin": "ADMINISTRADOR",
    "analista": "ANALISTA_SOC",
    "investigador": "INVESTIGADOR",
    "gestor": "GESTOR",
}


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def semente() -> dict:
    """Migra a base de dados de teste e semeia permissões, perfis e contas.

    É uma fixture **síncrona** que abre o seu próprio ciclo de eventos, e não
    uma fixture assíncrona de âmbito de sessão. A razão é concreta: o
    pytest-asyncio desta versão corre as fixtures de sessão e os testes em
    ciclos distintos, e uma ligação asyncpg aberta num ciclo não pode ser usada
    noutro — dá "attached to a different loop". Fechando aqui o ciclo por
    inteiro, nada da preparação atravessa a fronteira: o que sai é um
    dicionário de identificadores.

    Escrita definitiva, fora do rollback de cada teste: isto é o estado inicial
    de uma instalação, não dados de um teste.
    """
    import asyncio

    assert settings.environment == "test", (
        "A suite tem de correr com SHEISA_ENVIRONMENT=test; caso contrário "
        "escreveria na base de dados de desenvolvimento."
    )
    return asyncio.run(_preparar())


async def _preparar() -> dict:
    from sqlalchemy import select

    from app.models.identity import Role, User
    from app.services import bootstrap

    motor = create_async_engine(settings.test_database_url, poolclass=NullPool)
    try:
        await _migrar(motor)

        factory = async_sessionmaker(bind=motor, expire_on_commit=False)
        async with factory() as sessao:
            await bootstrap.sync_permissions(sessao)
            await bootstrap.sync_roles(sessao)
            equipa = await bootstrap.ensure_default_team(sessao)

            identificadores: dict[str, uuid.UUID] = {}
            for alcunha, perfil in CONTAS.items():
                email = f"{alcunha}@teste.local"
                existente = (
                    await sessao.execute(select(User).where(User.email == email))
                ).scalar_one_or_none()
                if existente is not None:
                    identificadores[alcunha] = existente.id
                    continue

                papel = (
                    await sessao.execute(select(Role).where(Role.name == perfil))
                ).scalar_one()
                utilizador = User(
                    email=email,
                    full_name=f"Conta de teste ({perfil})",
                    password_hash=hash_password(SENHA),
                    role_id=papel.id,
                    team_id=equipa.id,
                    is_active=True,
                    must_change_password=False,
                    password_changed_at=datetime.now(UTC),
                )
                sessao.add(utilizador)
                await sessao.flush()
                identificadores[alcunha] = utilizador.id

            await sessao.commit()
            equipa_id = equipa.id
    finally:
        await motor.dispose()

    return {"equipa_id": equipa_id, "utilizadores": identificadores}


async def _migrar(motor: AsyncEngine) -> None:
    """Aplica `alembic upgrade head` à base de dados de teste.

    Pelas migrações e não por `Base.metadata.create_all`: ver o cabeçalho.
    """
    from alembic import command
    from alembic.config import Config
    from app.core.config import PROJECT_ROOT

    cfg = Config(str(PROJECT_ROOT / "backend" / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "backend" / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.test_database_url)

    def _correr(ligacao) -> None:
        cfg.attributes["connection"] = ligacao
        command.upgrade(cfg, "head")

    async with motor.begin() as ligacao:
        await ligacao.run_sync(_correr)


@pytest_asyncio.fixture
async def engine(semente: dict) -> AsyncIterator[AsyncEngine]:
    """Motor criado dentro do ciclo de eventos do próprio teste.

    `NullPool` porque o motor vive apenas o tempo do teste: manter um pool
    seria guardar ligações para um ciclo que está prestes a fechar.
    """
    motor = create_async_engine(settings.test_database_url, poolclass=NullPool)
    yield motor
    await motor.dispose()


@pytest_asyncio.fixture
async def ligacao(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """Ligação com transacção aberta que é revertida no fim do teste."""
    conn = await engine.connect()
    transaccao = await conn.begin()
    try:
        yield conn
    finally:
        await transaccao.rollback()
        await conn.close()


@pytest_asyncio.fixture
async def sessao(ligacao: AsyncConnection) -> AsyncIterator[AsyncSession]:
    """Sessão de base de dados confinada à transacção do teste.

    `join_transaction_mode="create_savepoint"` é o que torna isto seguro: um
    `commit()` da aplicação liberta um savepoint e abre outro, de modo que o
    código sob teste corre exactamente como em produção — com commits reais —
    sem que nada escape ao rollback exterior.
    """
    factory = async_sessionmaker(
        bind=ligacao,
        expire_on_commit=False,
        autoflush=True,
        join_transaction_mode="create_savepoint",
    )
    async with factory() as s:
        yield s


@pytest_asyncio.fixture
async def cliente(ligacao: AsyncConnection) -> AsyncIterator[AsyncClient]:
    """Cliente HTTP contra a aplicação real, na transacção do teste.

    Cada pedido recebe uma **sessão nova**, como em produção, ligada à mesma
    ligação e portanto à mesma transacção do teste. Partilhar um único objecto
    `Session` entre pedidos seria mais simples e estaria errado: depois de um
    pedido falhar e fazer rollback, o pedido seguinte herdaria o mapa de
    identidade com objectos expirados e falharia a carregar relações — uma
    avaria que só existe no teste e que mascararia o comportamento real.

    A sessão do teste (`sessao`) vê tudo o que os pedidos escrevem, e
    vice-versa, por partilharem a ligação.
    """
    fabrica = async_sessionmaker(
        bind=ligacao,
        expire_on_commit=False,
        autoflush=True,
        join_transaction_mode="create_savepoint",
    )

    async def _sessao_de_teste() -> AsyncIterator[AsyncSession]:
        async with fabrica() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    anterior = settings.rate_limit_enabled
    settings.rate_limit_enabled = False
    fastapi_app.dependency_overrides[get_session] = _sessao_de_teste
    try:
        async with AsyncClient(
            transport=ASGITransport(app=fastapi_app),
            base_url="http://teste",
        ) as c:
            yield c
    finally:
        fastapi_app.dependency_overrides.pop(get_session, None)
        settings.rate_limit_enabled = anterior


@pytest.fixture
def rate_limit_ligado() -> AsyncIterator[None]:
    """Volta a ligar a limitação de taxa só para o teste que a verifica."""
    anterior = settings.rate_limit_enabled
    settings.rate_limit_enabled = True
    yield
    settings.rate_limit_enabled = anterior


# ------------------------------------------------------------------ auxiliares
async def autenticar(cliente: AsyncClient, alcunha: str) -> str:
    """Devolve um token de acesso para a conta de teste indicada."""
    resposta = await cliente.post(
        "/api/auth/login",
        json={"email": f"{alcunha}@teste.local", "password": SENHA},
    )
    assert resposta.status_code == 200, resposta.text
    return resposta.json()["access_token"]


def cabecalho(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def token_admin(cliente: AsyncClient) -> str:
    return await autenticar(cliente, "admin")


@pytest_asyncio.fixture
async def token_analista(cliente: AsyncClient) -> str:
    return await autenticar(cliente, "analista")


@pytest_asyncio.fixture
async def token_gestor(cliente: AsyncClient) -> str:
    return await autenticar(cliente, "gestor")


@pytest_asyncio.fixture
async def chave_ingestao(sessao: AsyncSession) -> str:
    """Chave de API de ingestão válida, criada pelo caminho real."""
    from app.core.security import generate_api_key
    from app.models.identity import ApiKey

    bruta, prefixo, resumo = generate_api_key()
    sessao.add(
        ApiKey(
            name=f"Chave de teste {prefixo}",
            key_prefix=prefixo,
            key_hash=resumo,
            is_active=True,
        )
    )
    await sessao.flush()
    return bruta
