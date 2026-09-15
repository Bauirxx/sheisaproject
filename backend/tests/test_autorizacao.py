"""Autorização (§22).

O princípio declarado é que a autorização é verificada no servidor e sempre
contra a base de dados. Estes testes obrigam-no a ser verdade: se alguém
optimizar a verificação para ler as permissões do token, o teste da revogação
imediata falha.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.enums import AuditOutcome
from app.models.identity import Role
from app.models.system import AuditLog
from tests.conftest import SENHA, cabecalho


async def test_analista_nao_gere_utilizadores(cliente, token_analista):
    resposta = await cliente.get("/api/users", headers=cabecalho(token_analista))
    assert resposta.status_code == 403
    assert resposta.json()["erro"]["codigo"]


async def test_administrador_gere_utilizadores(cliente, token_admin):
    resposta = await cliente.get("/api/users", headers=cabecalho(token_admin))
    assert resposta.status_code == 200


async def test_negacao_fica_registada_na_auditoria(cliente, token_analista, sessao):
    """Saber o que foi tentado sem autorização vale tanto como saber o que foi feito."""
    await cliente.get("/api/users", headers=cabecalho(token_analista))

    registos = (
        await sessao.execute(
            select(AuditLog)
            .where(AuditLog.outcome == AuditOutcome.NEGADO)
            .order_by(AuditLog.created_at.desc())
        )
    ).scalars().all()

    assert registos, "a negação não foi registada"
    ultimo = registos[0]
    assert ultimo.actor_email == "analista@teste.local"
    # A rota de listagem exige `users:read`; o motivo nomeia a permissão em falta.
    assert "users:read" in (ultimo.failure_reason or "")
    # O tipo de recurso é um tipo, não um caminho: já houve um 403 a virar 500
    # por o caminho não caber na coluna de 40 caracteres.
    assert len(ultimo.resource_type) <= 40


async def test_permissao_revogada_tem_efeito_imediato(cliente, sessao):
    """Revogar uma permissão não pode esperar que o token expire.

    O token transporta as permissões para conveniência do frontend, mas a
    decisão de autorizar lê o perfil actual da base de dados. Se assim não
    fosse, revogar um acesso numa plataforma de segurança demoraria até 30
    minutos a produzir efeito.
    """
    entrada = await cliente.post(
        "/api/auth/login", json={"email": "admin@teste.local", "password": SENHA}
    )
    token = entrada.json()["access_token"]

    assert (
        await cliente.get("/api/users", headers=cabecalho(token))
    ).status_code == 200

    papel = (
        await sessao.execute(
            select(Role)
            .where(Role.name == "ADMINISTRADOR")
            .options(selectinload(Role.permissions))
        )
    ).scalar_one()
    papel.permissions.remove(
        next(p for p in papel.permissions if p.code == "users:read")
    )
    await sessao.commit()

    # Mesmo token, mesma sessão: o acesso deixa de existir na chamada seguinte.
    assert (
        await cliente.get("/api/users", headers=cabecalho(token))
    ).status_code == 403


async def test_conta_desactivada_perde_acesso_imediatamente(cliente, sessao):
    from app.models.identity import User

    entrada = await cliente.post(
        "/api/auth/login", json={"email": "analista@teste.local", "password": SENHA}
    )
    token = entrada.json()["access_token"]
    assert (await cliente.get("/api/auth/me", headers=cabecalho(token))).status_code == 200

    utilizador = (
        await sessao.execute(select(User).where(User.email == "analista@teste.local"))
    ).scalar_one()
    utilizador.is_active = False
    await sessao.commit()

    assert (await cliente.get("/api/auth/me", headers=cabecalho(token))).status_code == 401


@pytest.mark.parametrize(
    ("caminho", "alcunha", "esperado"),
    [
        ("/api/alerts", "analista", 200),
        ("/api/incidents", "analista", 200),
        ("/api/audit", "analista", 403),   # auditoria é do gestor e do administrador
        ("/api/audit", "gestor", 200),
        ("/api/recommendations", "analista", 200),
        ("/api/recommendations", "gestor", 200),
    ],
)
async def test_matriz_de_acesso(cliente, caminho, alcunha, esperado):
    from tests.conftest import autenticar

    token = await autenticar(cliente, alcunha)
    resposta = await cliente.get(caminho, headers=cabecalho(token))
    assert resposta.status_code == esperado, f"{caminho} como {alcunha}: {resposta.text}"


async def test_gestor_nao_decide_recomendacoes(cliente, token_gestor):
    """O gestor lê recomendações mas não as decide — é o analista que investiga."""
    lista = await cliente.get("/api/recommendations", headers=cabecalho(token_gestor))
    assert lista.status_code == 200

    decisao = await cliente.post(
        "/api/recommendations/generate", headers=cabecalho(token_gestor)
    )
    assert decisao.status_code == 403


async def test_ingestao_exige_chave_de_api_e_nao_aceita_token(cliente, token_admin):
    """A ingestão é de máquinas: um token de utilizador não a autoriza."""
    resposta = await cliente.post(
        "/api/ingest/wazuh", json={}, headers=cabecalho(token_admin)
    )
    assert resposta.status_code == 401
    assert "CHAVE_API" in resposta.json()["erro"]["codigo"]
