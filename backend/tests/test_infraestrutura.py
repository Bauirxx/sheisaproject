"""Verifica que a propria infraestrutura de teste faz o que promete.

Um teste que passa por a base de dados estar suja, ou por a transaccao nao ser
revertida, e pior do que nenhum teste: da confianca sem a justificar.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from app.core.config import settings
from app.models import Base
from app.models.identity import User
from tests.conftest import cabecalho


async def test_corre_contra_a_base_de_dados_de_teste():
    assert settings.environment == "test"
    assert "15434" in settings.effective_database_url
    assert "sheisa_test" in settings.effective_database_url


async def test_semente_criou_as_contas(sessao):
    total = await sessao.scalar(
        select(func.count()).select_from(User).where(User.email.like("%@teste.local"))
    )
    assert total == 4


async def test_a_transaccao_do_teste_e_revertida_parte_1(sessao):
    """Escreve um utilizador. O teste seguinte confirma que desapareceu."""
    from app.core.security import hash_password

    papel = (await sessao.execute(select(User).where(User.email == "admin@teste.local"))).scalar_one()
    sessao.add(
        User(
            email="efemero@teste.local",
            full_name="Existe so dentro desta transaccao",
            password_hash=hash_password("TesteSeguro2026"),
            role_id=papel.role_id,
            is_active=True,
        )
    )
    await sessao.commit()  # commit real da aplicacao, contido num savepoint
    existe = await sessao.scalar(
        select(func.count()).select_from(User).where(User.email == "efemero@teste.local")
    )
    assert existe == 1


async def test_a_transaccao_do_teste_e_revertida_parte_2(sessao):
    """O utilizador escrito (e com commit feito) pelo teste anterior nao existe."""
    existe = await sessao.scalar(
        select(func.count()).select_from(User).where(User.email == "efemero@teste.local")
    )
    assert existe == 0


async def test_autenticacao_das_quatro_contas(cliente):
    from tests.conftest import CONTAS, autenticar

    for alcunha in CONTAS:
        token = await autenticar(cliente, alcunha)
        resposta = await cliente.get("/api/auth/me", headers=cabecalho(token))
        assert resposta.status_code == 200, resposta.text
        assert resposta.json()["email"] == f"{alcunha}@teste.local"


async def test_o_esquema_migrado_corresponde_aos_modelos(ligacao):
    """O metadata dos modelos tem de descrever o esquema que as migrações criam.

    Não é zelo: o autogenerate compara os dois, e o que existe na base sem estar
    no metadata é lido como **a mais**. Quatro índices criados por SQL directo
    nas migrações 0002 e 0004 não estavam declarados, pelo que a próxima migração
    gerada os apagaria em silêncio — incluindo
    `uq_recommendations_pendente_por_alvo`, que é o que impede o motor de
    empilhar propostas duplicadas. Nada falharia; o motor voltava simplesmente a
    poder acumular duplicados.

    Compara-se contra a base de teste, que é migrada pelo `conftest` a partir do
    zero, pelo que o que aqui se vê é exactamente o que as migrações produzem.
    """
    def _diferencas(sync_conn):
        contexto = MigrationContext.configure(
            sync_conn,
            opts={"include_object": _ignorar_alheios, "compare_type": True},
        )
        return compare_metadata(contexto, Base.metadata)

    diferencas = await ligacao.run_sync(_diferencas)

    assert not diferencas, (
        "o esquema e os modelos divergiram. Um índice ou coluna criado por SQL "
        "directo numa migração tem de ser declarado no modelo, senão o "
        f"autogenerate propõe removê-lo: {diferencas}"
    )


async def test_a_base_recusa_um_valor_de_enumeracao_invalido(
    cliente, sessao, token_analista
):
    """A restrição CHECK (migração 0007) fecha a porta que o ORM deixava aberta.

    Um valor fora do domínio, escrito por SQL directo — sem passar pela validação
    da aplicação —, é recusado pela própria base. Sem a restrição, passaria.
    """
    criado = await cliente.post(
        "/api/incidents",
        json={
            "title": "Incidente para a restrição CHECK",
            "description": "x",
            "category": "INTRUSAO",
            "severity": "ALTA",
        },
        headers=cabecalho(token_analista),
    )
    assert criado.status_code == 201, criado.text
    iid = criado.json()["id"]

    # Um valor do domínio passa (controlo).
    async with sessao.begin_nested():
        await sessao.execute(
            text("UPDATE incidents SET status = 'ABERTO' WHERE id = :i"), {"i": iid}
        )

    # Um valor fora do domínio é recusado pela base.
    with pytest.raises(IntegrityError):
        async with sessao.begin_nested():
            await sessao.execute(
                text("UPDATE incidents SET status = 'INEXISTENTE' WHERE id = :i"),
                {"i": iid},
            )


def _ignorar_alheios(obj, name, type_, reflected, compare_to) -> bool:
    """Exclui o que não pertence ao esquema da aplicação.

    `alembic_version` é do próprio Alembic e `spatial_ref_sys` vem de extensões;
    nenhum consta dos modelos, e compará-los daria uma diferença permanente.
    """
    return not (type_ == "table" and name in {"alembic_version", "spatial_ref_sys"})
