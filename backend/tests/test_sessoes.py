"""Sessões e palavra-passe do próprio utilizador (`services/auth_service.py`).

`test_autenticacao.py` cobre o início de sessão e a renovação. Aqui fica o resto,
e dois defeitos encontrados:

* **A palavra-passe actual podia ser adivinhada sem limite.** O login conta
  tentativas falhadas e bloqueia a conta à quinta; `POST /auth/change-password`
  verifica a palavra-passe actual sem contar nada, e a limitação de taxa trata-a
  como rota comum (300 por minuto). Quem tivesse um token de acesso roubado podia
  tentar até acertar, trocar a palavra-passe e ficar com a conta. É a armadilha
  5.15: a regra estava numa porta e não na outra.
* **A hora do bloqueio vinha em UTC sem o dizer.** "Conta bloqueada até 08:15"
  para quem está em Maputo (UTC+2) significa 10:15; quem voltasse às 08:15
  continuava bloqueado sem perceber porquê.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.config import settings
from app.models.identity import User, UserSession
from app.models.system import AuditLog
from tests.conftest import SENHA, cabecalho

EMAIL = "titular@soc.local"
SENHA_NOVA = "NovaSegura2026x"


async def _conta(cliente, token_admin, sessao) -> User:
    resposta = await cliente.post(
        "/api/users",
        json={"email": EMAIL, "full_name": "Titular", "password": SENHA,
              "role_name": "ANALISTA_SOC", "must_change_password": False},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 201, resposta.text
    return await sessao.get(User, uuid.UUID(resposta.json()["id"]))


async def _login(cliente, senha=SENHA):
    return await cliente.post("/api/auth/login", json={"email": EMAIL, "password": senha})


async def _token(cliente, senha=SENHA) -> str:
    resposta = await _login(cliente, senha)
    assert resposta.status_code == 200, resposta.text
    return resposta.json()["access_token"]


async def _mudar(cliente, token, actual, nova=SENHA_NOVA):
    return await cliente.post(
        "/api/auth/change-password",
        json={"current_password": actual, "new_password": nova},
        headers=cabecalho(token),
    )


async def _eu(cliente, token) -> int:
    return (await cliente.get("/api/auth/me", headers=cabecalho(token))).status_code


# ------------------------------------------------- mudar a palavra-passe
async def test_mudar_termina_as_outras_sessoes_e_mantem_esta(cliente, sessao, token_admin):
    await _conta(cliente, token_admin, sessao)
    esta, outra = await _token(cliente), await _token(cliente)

    resposta = await _mudar(cliente, esta, SENHA)

    assert resposta.status_code == 200, resposta.text
    assert (await _eu(cliente, esta), await _eu(cliente, outra)) == (200, 401)
    assert (await _login(cliente, SENHA)).status_code == 401
    assert (await _login(cliente, SENHA_NOVA)).status_code == 200


async def test_a_nova_tem_de_ser_diferente_e_forte(cliente, sessao, token_admin):
    await _conta(cliente, token_admin, sessao)
    token = await _token(cliente)

    igual = await _mudar(cliente, token, SENHA, nova=SENHA)
    fraca = await _mudar(cliente, token, SENHA, nova="fraca")

    assert (igual.status_code, fraca.status_code) == (422, 422)


async def test_palavra_passe_actual_errada_fica_auditada(cliente, sessao, token_admin):
    conta = await _conta(cliente, token_admin, sessao)
    token = await _token(cliente)

    resposta = await _mudar(cliente, token, "NaoEAActual2026")

    assert resposta.status_code == 401
    entrada = (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "ALTERAR_PALAVRA_PASSE", AuditLog.resource_id == conta.id
            )
        )
    ).scalar_one()
    assert entrada.outcome.value == "FALHA"


async def test_adivinhar_a_palavra_passe_actual_bloqueia_como_no_login(
    cliente, sessao, token_admin
):
    """Regressão: com um token roubado, tentava-se a palavra-passe sem limite."""
    conta = await _conta(cliente, token_admin, sessao)
    token = await _token(cliente)

    for tentativa in range(settings.max_failed_logins):
        resposta = await _mudar(cliente, token, f"Adivinha{tentativa}2026x")
        assert resposta.status_code == 401

    await sessao.refresh(conta)
    assert conta.locked_until is not None, "a conta não foi bloqueada"
    assert await _eu(cliente, token) == 401, "o token usado para adivinhar continua válido"
    assert (await _login(cliente, SENHA)).json()["erro"]["codigo"] == "CONTA_BLOQUEADA"


# ------------------------------------------------------ início de sessão
async def test_conta_bloqueada_recusa_a_palavra_passe_certa_e_diz_a_hora_em_utc(
    cliente, sessao, token_admin
):
    """Regressão: a hora vinha em UTC sem o dizer."""
    conta = await _conta(cliente, token_admin, sessao)
    conta.locked_until = datetime.now(UTC) + timedelta(minutes=10)
    await sessao.flush()

    resposta = await _login(cliente)

    assert resposta.status_code == 401
    erro = resposta.json()["erro"]
    assert erro["codigo"] == "CONTA_BLOQUEADA"
    assert "UTC" in erro["mensagem"], erro["mensagem"]


async def test_conta_desactivada_nao_inicia_sessao(cliente, sessao, token_admin):
    conta = await _conta(cliente, token_admin, sessao)
    conta.is_active = False
    await sessao.flush()

    resposta = await _login(cliente)

    assert resposta.json()["erro"]["codigo"] == "CONTA_INACTIVA"


async def test_renovar_uma_sessao_expirada_e_recusado(cliente, sessao, token_admin):
    conta = await _conta(cliente, token_admin, sessao)
    renovacao = (await _login(cliente)).json()["refresh_token"]
    for registo in (
        await sessao.execute(select(UserSession).where(UserSession.user_id == conta.id))
    ).scalars():
        registo.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await sessao.flush()

    resposta = await cliente.post("/api/auth/refresh", json={"refresh_token": renovacao})

    assert resposta.status_code == 401
    assert resposta.json()["erro"]["codigo"] == "SESSAO_EXPIRADA"


async def test_as_sessoes_do_proprio_sao_listadas(cliente, sessao, token_admin):
    await _conta(cliente, token_admin, sessao)
    token = await _token(cliente)
    await _token(cliente)

    resposta = await cliente.get("/api/auth/sessions", headers=cabecalho(token))

    assert resposta.status_code == 200, resposta.text
    assert len(resposta.json()) == 2
