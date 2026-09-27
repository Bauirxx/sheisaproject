"""Notificações dirigidas a um utilizador.

O modelo `Notification` e a página existiam, mas só dois dos oito tipos eram
alguma vez emitidos — os outros eram vocabulário sem uso. Estes testes fixam os
eventos que passam a produzir uma notificação, e a regra que atravessa todos:
**ninguém é notificado da sua própria acção.**
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.enums import NotificationKind
from app.models.identity import User
from app.models.system import Notification
from tests.conftest import cabecalho


async def _por_email(sessao, email: str) -> User:
    return (
        await sessao.execute(select(User).where(User.email == email))
    ).scalar_one()


async def _notificacoes(sessao, user_id, kind: NotificationKind) -> list[Notification]:
    return list(
        (
            await sessao.execute(
                select(Notification).where(
                    Notification.user_id == user_id, Notification.kind == kind
                )
            )
        ).scalars()
    )


async def _incidente(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={
            "title": "Incidente para notificações",
            "description": "x",
            "category": "INTRUSAO",
            "severity": "ALTA",
        },
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _atribuir(cliente, token, incidente_id, assignee_id) -> object:
    return await cliente.post(
        f"/api/incidents/{incidente_id}/assign",
        json={"assignee_id": str(assignee_id)},
        headers=cabecalho(token),
    )


async def test_atribuir_incidente_notifica_o_responsavel(cliente, sessao, token_admin):
    analista = await _por_email(sessao, "analista@teste.local")
    incidente = await _incidente(cliente, token_admin)

    resposta = await _atribuir(cliente, token_admin, incidente["id"], analista.id)
    assert resposta.status_code == 200, resposta.text

    notifs = await _notificacoes(sessao, analista.id, NotificationKind.INCIDENTE_ATRIBUIDO)
    assert len(notifs) == 1
    assert notifs[0].resource_reference == incidente["reference"]
    assert notifs[0].read_at is None


async def test_atribuir_a_si_mesmo_nao_notifica(cliente, sessao, token_analista):
    """Quem se atribui a si mesmo já sabe — notificá-lo seria ruído."""
    analista = await _por_email(sessao, "analista@teste.local")
    incidente = await _incidente(cliente, token_analista)

    resposta = await _atribuir(cliente, token_analista, incidente["id"], analista.id)
    assert resposta.status_code == 200, resposta.text

    notifs = await _notificacoes(sessao, analista.id, NotificationKind.INCIDENTE_ATRIBUIDO)
    assert notifs == []


async def test_escalar_incidente_notifica_o_responsavel(cliente, sessao, token_admin):
    analista = await _por_email(sessao, "analista@teste.local")
    incidente = await _incidente(cliente, token_admin)
    await _atribuir(cliente, token_admin, incidente["id"], analista.id)

    async def _transitar(estado):
        return await cliente.post(
            f"/api/incidents/{incidente['id']}/transition",
            json={"status": estado},
            headers=cabecalho(token_admin),
        )

    await _transitar("TRIAGEM")
    resposta = await _transitar("ESCALADO")
    assert resposta.status_code == 200, resposta.text

    notifs = await _notificacoes(sessao, analista.id, NotificationKind.INCIDENTE_ESCALADO)
    assert len(notifs) == 1
    assert notifs[0].resource_reference == incidente["reference"]


async def test_criar_tarefa_com_responsavel_notifica(cliente, sessao, token_admin):
    analista = await _por_email(sessao, "analista@teste.local")
    incidente = await _incidente(cliente, token_admin)

    resposta = await cliente.post(
        f"/api/tasks?incident_id={incidente['id']}",
        json={"title": "Recolher registos do servidor", "assignee_id": str(analista.id)},
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 201, resposta.text

    notifs = await _notificacoes(sessao, analista.id, NotificationKind.TAREFA_ATRIBUIDA)
    assert len(notifs) == 1
