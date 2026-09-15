"""Autenticação e gestão de sessão (§23).

Cobre o que distingue uma autenticação defensável de uma que apenas funciona:
não revelar que contas existem, bloquear a força bruta, rodar os tokens de
renovação e detectar a reutilização de um token já gasto.
"""

from __future__ import annotations

from sqlalchemy import select

from app.models.identity import User, UserSession
from tests.conftest import SENHA, cabecalho


async def test_login_valido_devolve_tokens(cliente):
    resposta = await cliente.post(
        "/api/auth/login",
        json={"email": "analista@teste.local", "password": SENHA},
    )
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["access_token"]
    assert corpo["refresh_token"]
    assert corpo["access_token"] != corpo["refresh_token"]


async def test_palavra_passe_errada_e_conta_inexistente_sao_indistinguiveis(cliente):
    """§23: a resposta não pode revelar se a conta existe.

    Se a mensagem ou o código diferissem, um atacante enumerava contas válidas
    antes de tentar sequer adivinhar palavras-passe.
    """
    inexistente = await cliente.post(
        "/api/auth/login",
        json={"email": "nao-existe@teste.local", "password": "QualquerCoisa123"},
    )
    errada = await cliente.post(
        "/api/auth/login",
        json={"email": "analista@teste.local", "password": "PalavraErrada123"},
    )

    assert inexistente.status_code == errada.status_code == 401
    assert inexistente.json()["erro"]["mensagem"] == errada.json()["erro"]["mensagem"]
    assert inexistente.json()["erro"]["codigo"] == errada.json()["erro"]["codigo"]


async def test_tentativas_falhadas_bloqueiam_a_conta(cliente, sessao):
    """Ao fim de `max_failed_logins` a conta fica bloqueada."""
    from app.core.config import settings

    for _ in range(settings.max_failed_logins):
        await cliente.post(
            "/api/auth/login",
            json={"email": "gestor@teste.local", "password": "PalavraErrada123"},
        )

    # Mesmo com a palavra-passe certa, o acesso é recusado enquanto durar o
    # bloqueio — caso contrário o contador não protegeria de nada.
    resposta = await cliente.post(
        "/api/auth/login",
        json={"email": "gestor@teste.local", "password": SENHA},
    )
    assert resposta.status_code in (401, 423)

    utilizador = (
        await sessao.execute(select(User).where(User.email == "gestor@teste.local"))
    ).scalar_one()
    assert utilizador.locked_until is not None
    assert utilizador.failed_login_count >= settings.max_failed_logins


async def test_login_com_sucesso_limpa_o_contador(cliente, sessao):
    await cliente.post(
        "/api/auth/login",
        json={"email": "investigador@teste.local", "password": "PalavraErrada123"},
    )
    await cliente.post(
        "/api/auth/login",
        json={"email": "investigador@teste.local", "password": SENHA},
    )
    utilizador = (
        await sessao.execute(
            select(User).where(User.email == "investigador@teste.local")
        )
    ).scalar_one()
    assert utilizador.failed_login_count == 0


async def test_renovacao_roda_o_token(cliente):
    """Cada renovação emite um token novo e invalida o anterior."""
    inicio = (
        await cliente.post(
            "/api/auth/login",
            json={"email": "analista@teste.local", "password": SENHA},
        )
    ).json()

    renovado = await cliente.post(
        "/api/auth/refresh", json={"refresh_token": inicio["refresh_token"]}
    )
    assert renovado.status_code == 200
    novo = renovado.json()
    assert novo["refresh_token"] != inicio["refresh_token"]


async def test_reutilizar_token_de_renovacao_revoga_a_sessao(cliente, sessao):
    """Um token de renovação já gasto sinaliza roubo de credencial.

    A resposta correcta não é apenas recusar: é revogar a sessão inteira, porque
    a reutilização significa que duas partes têm o mesmo segredo e não se sabe
    qual delas é a legítima.
    """
    inicio = (
        await cliente.post(
            "/api/auth/login",
            json={"email": "analista@teste.local", "password": SENHA},
        )
    ).json()
    gasto = inicio["refresh_token"]

    primeira = await cliente.post("/api/auth/refresh", json={"refresh_token": gasto})
    assert primeira.status_code == 200

    segunda = await cliente.post("/api/auth/refresh", json={"refresh_token": gasto})
    assert segunda.status_code == 401

    # O token de acesso emitido na renovação legítima também deixa de servir.
    depois = await cliente.get(
        "/api/auth/me", headers=cabecalho(primeira.json()["access_token"])
    )
    assert depois.status_code == 401


async def test_terminar_sessao_invalida_o_token_de_acesso(cliente):
    inicio = (
        await cliente.post(
            "/api/auth/login",
            json={"email": "analista@teste.local", "password": SENHA},
        )
    ).json()
    token = inicio["access_token"]

    assert (await cliente.get("/api/auth/me", headers=cabecalho(token))).status_code == 200

    saida = await cliente.post(
        "/api/auth/logout",
        json={"refresh_token": inicio["refresh_token"]},
        headers=cabecalho(token),
    )
    assert saida.status_code in (200, 204)

    # A revogação é imediata porque a sessão é reconfirmada a cada pedido, e
    # não apenas quando o token expira.
    assert (await cliente.get("/api/auth/me", headers=cabecalho(token))).status_code == 401


async def test_sem_token_devolve_401_no_formato_da_aplicacao(cliente):
    resposta = await cliente.get("/api/auth/me")
    assert resposta.status_code == 401
    assert "erro" in resposta.json()
    assert resposta.json()["erro"]["mensagem"]


async def test_token_malformado_nao_expoe_detalhes(cliente):
    resposta = await cliente.get("/api/auth/me", headers=cabecalho("isto-nao-e-um-jwt"))
    assert resposta.status_code == 401
    mensagem = resposta.json()["erro"]["mensagem"].lower()
    assert "jwt" not in mensagem or "inválido" in mensagem


async def test_login_cria_registo_de_sessao(cliente, sessao):
    antes = len(
        (await sessao.execute(select(UserSession))).scalars().all()
    )
    await cliente.post(
        "/api/auth/login",
        json={"email": "analista@teste.local", "password": SENHA},
    )
    depois = len((await sessao.execute(select(UserSession))).scalars().all())
    assert depois == antes + 1
