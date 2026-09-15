"""Verifica que a propria infraestrutura de teste faz o que promete.

Um teste que passa por a base de dados estar suja, ou por a transaccao nao ser
revertida, e pior do que nenhum teste: da confianca sem a justificar.
"""

from __future__ import annotations

from sqlalchemy import func, select

from app.core.config import settings
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
