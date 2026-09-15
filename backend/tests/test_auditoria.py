"""Auditoria: imutabilidade e atribuição correcta (§16).

A imutabilidade não é uma convenção do código da aplicação — é imposta pelo
PostgreSQL através de gatilhos criados nas migrações `0002` e `0003`. Estes
testes atacam a tabela directamente, por SQL, precisamente para provar que a
garantia não depende de ninguém se lembrar de a respeitar.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import AuditOutcome
from app.models.system import AuditLog
from tests.conftest import SENHA, cabecalho


async def _registo_de_teste(sessao) -> AuditLog:
    entrada = await audit.record(
        sessao,
        AuditContext(actor_email="teste@teste.local", origin="teste"),
        action="ACCAO_DE_TESTE",
        resource_type="teste",
        description="Linha escrita para verificar a imutabilidade.",
    )
    await sessao.flush()
    return entrada


async def test_update_a_auditoria_e_recusado(sessao):
    entrada = await _registo_de_teste(sessao)
    original = entrada.description

    with pytest.raises(DBAPIError):
        async with sessao.begin_nested():
            await sessao.execute(
                text("UPDATE audit_logs SET description = 'adulterado' WHERE id = :i"),
                {"i": entrada.id},
            )

    # A linha tem de continuar exactamente como estava.
    lida = await sessao.scalar(
        select(AuditLog.description).where(AuditLog.id == entrada.id)
    )
    assert lida == original


async def test_delete_a_auditoria_e_recusado(sessao):
    entrada = await _registo_de_teste(sessao)

    with pytest.raises(DBAPIError):
        async with sessao.begin_nested():
            await sessao.execute(
                text("DELETE FROM audit_logs WHERE id = :i"), {"i": entrada.id}
            )

    ainda_la = await sessao.scalar(
        select(func.count()).select_from(AuditLog).where(AuditLog.id == entrada.id)
    )
    assert ainda_la == 1


async def test_truncate_a_auditoria_e_recusado(sessao):
    """O TRUNCATE não dispara gatilhos de linha — daí o gatilho de statement."""
    await _registo_de_teste(sessao)
    antes = await sessao.scalar(select(func.count()).select_from(AuditLog))
    assert antes > 0

    with pytest.raises(DBAPIError):
        async with sessao.begin_nested():
            await sessao.execute(text("TRUNCATE TABLE audit_logs"))

    depois = await sessao.scalar(select(func.count()).select_from(AuditLog))
    assert depois == antes


async def test_insercao_continua_a_ser_permitida(sessao):
    """A tabela é append-only, não read-only: sem INSERT não haveria auditoria."""
    antes = await sessao.scalar(select(func.count()).select_from(AuditLog))
    await _registo_de_teste(sessao)
    depois = await sessao.scalar(select(func.count()).select_from(AuditLog))
    assert depois == antes + 1


async def test_o_actor_registado_e_o_utilizador_autenticado(cliente, sessao):
    """O contexto de auditoria resolve a identidade tarde, não na dependência.

    O FastAPI resolve dependências pela ordem da assinatura, e a de auditoria
    costuma vir antes da que autentica. Quando a identidade era lida no momento
    em que o contexto era construído, tudo ficava registado como sistema — e a
    separação de funções, que compara actores, deixava de funcionar.
    """
    entrada = await cliente.post(
        "/api/auth/login", json={"email": "admin@teste.local", "password": SENHA}
    )
    token = entrada.json()["access_token"]

    await cliente.post(
        "/api/users",
        headers=cabecalho(token),
        json={
            "email": "novo@teste.local",
            "full_name": "Conta criada no teste",
            "password": "TesteSeguro2026",
            "role_name": "ANALISTA_SOC",
            "must_change_password": False,
        },
    )

    registo = (
        await sessao.execute(
            select(AuditLog)
            .where(AuditLog.action == "CRIAR_UTILIZADOR")
            .order_by(AuditLog.created_at.desc())
            .limit(1)
        )
    ).scalar_one()

    assert registo.actor_email == "admin@teste.local"
    assert registo.is_system_actor is False
    assert registo.actor_role == "ADMINISTRADOR"


async def test_a_palavra_passe_nunca_entra_na_auditoria(cliente, token_admin, sessao):
    await cliente.post(
        "/api/users",
        headers=cabecalho(token_admin),
        json={
            "email": "outro@teste.local",
            "full_name": "Outra conta",
            "password": "SegredoQueNaoSai9",
            "role_name": "ANALISTA_SOC",
            "must_change_password": False,
        },
    )

    registos = (
        await sessao.execute(select(AuditLog).where(AuditLog.action == "CRIAR_UTILIZADOR"))
    ).scalars().all()

    for registo in registos:
        texto = f"{registo.description} {registo.new_value} {registo.old_value}"
        assert "SegredoQueNaoSai9" not in texto


async def test_auditoria_nunca_faz_falhar_o_que_regista(sessao):
    """Campos longos são truncados em vez de rebentarem a inserção.

    A auditoria partilha a transacção com a operação que descreve: se a escrita
    do registo falhasse, arrastaria consigo a operação legítima. Já aconteceu —
    um caminho de URL de 55 caracteres numa coluna de 40 transformava um 403
    num 500.
    """
    entrada = await audit.record(
        sessao,
        AuditContext(actor_email="e" * 400, origin="o" * 200),
        action="A" * 200,
        resource_type="R" * 200,
        resource_reference="X" * 200,
        description="descrição longa " * 200,
        outcome=AuditOutcome.SUCESSO,
    )
    await sessao.flush()

    assert len(entrada.action) <= 80
    assert len(entrada.resource_type) <= 40
    assert len(entrada.resource_reference) <= 24
    assert len(entrada.actor_email) <= 254


async def test_login_falhado_fica_registado(cliente, sessao):
    await cliente.post(
        "/api/auth/login",
        json={"email": "analista@teste.local", "password": "PalavraErrada123"},
    )
    registo = (
        await sessao.execute(
            select(AuditLog)
            .where(AuditLog.action == "LOGIN", AuditLog.outcome == AuditOutcome.FALHA)
            .order_by(AuditLog.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    assert registo is not None
    assert registo.failure_reason
