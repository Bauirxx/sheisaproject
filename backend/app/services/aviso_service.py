"""Avisos a pessoas e equipas: notificação na plataforma **e** email.

Quando um incidente é atribuído a alguém, entregue a uma equipa, ou escalado,
quem passa a responder por ele tem de saber — e não pode depender de estar com a
plataforma aberta. Por isso cada aviso tem duas formas: a notificação interna
(`notification_service`) e um email para o endereço da conta.

Regras que atravessam todos os avisos:

* **Ninguém é avisado da sua própria acção** — quem atribui ou escala já sabe.
* **Contas desactivadas não recebem nada**: sair da organização não pode
  continuar a trazer incidentes por email.
* **Cada pessoa é avisada uma vez por acontecimento**, mesmo que seja ao mesmo
  tempo a responsável e membro da equipa atribuída.
* **O email nunca faz falhar a operação.** A atribuição ou o escalamento já
  estão feitos; um servidor de correio em baixo não os desfaz. Mas também nunca
  se afirma um envio que não houve: cada vaga de avisos fica na auditoria com
  quem recebeu (e o `Message-ID` que o servidor atribuiu), quem falhou e porquê,
  ou que o canal não está configurado.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.config import settings
from app.core.enums import AuditOutcome, NotificationKind
from app.models.identity import Team, User
from app.models.incident import Incident
from app.services import email_service, notification_service

logger = logging.getLogger("sheisa.avisos")


async def membros_activos(session: AsyncSession, team_id: uuid.UUID | None) -> list[User]:
    """Membros activos de uma equipa, por nome. Lista vazia se não houver equipa."""
    if team_id is None:
        return []
    resultado = await session.execute(
        select(User)
        .where(User.team_id == team_id, User.is_active.is_(True))
        .order_by(User.full_name)
    )
    return list(resultado.scalars())


def _destinatarios(candidatos: Iterable[User | None], excepto: uuid.UUID | None) -> list[User]:
    vistos: set[uuid.UUID] = set()
    finais: list[User] = []
    for pessoa in candidatos:
        if pessoa is None or not pessoa.is_active or pessoa.id == excepto:
            continue
        if pessoa.id in vistos:
            continue
        vistos.add(pessoa.id)
        finais.append(pessoa)
    return finais


def _corpo(
    pessoa: User,
    incidente: Incident,
    *,
    motivo: str,
    equipa: Team | None,
    responsavel: User | None,
    autor: str,
) -> str:
    ligacao = f"{settings.url_da_interface.rstrip('/')}/incidentes/{incidente.id}"
    linhas = [
        f"{pessoa.full_name},",
        "",
        motivo,
        "",
        f"Referência:  {incidente.reference}",
        f"Título:      {incidente.title}",
        f"Severidade:  {incidente.severity.value}",
        f"Estado:      {incidente.status.value}",
        f"Equipa:      {equipa.name if equipa else '(nenhuma)'}",
        f"Responsável: {responsavel.full_name if responsavel else '(por atribuir)'}",
        f"Por:         {autor}",
        "",
        f"Abrir o incidente: {ligacao}",
        "",
        "-- ",
        "Mensagem automática da plataforma SHEISA. Não responda a este endereço;",
        "trate o incidente na plataforma.",
    ]
    return "\n".join(linhas)


async def avisar(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    incidente: Incident,
    destinatarios: Iterable[User | None],
    kind: NotificationKind,
    titulo: str,
    motivo: str,
    equipa: Team | None = None,
    responsavel: User | None = None,
) -> list[User]:
    """Avisa cada destinatário na plataforma e por email. Devolve quem foi avisado.

    `motivo` é a frase que abre o email ("Foi-lhe atribuído…", "O incidente foi
    escalado para a equipa…"). `titulo` é o da notificação interna e o assunto do
    email, depois da referência.
    """
    pessoas = _destinatarios(destinatarios, excepto=ctx.actor_id)
    if not pessoas:
        return []

    for pessoa in pessoas:
        notification_service.notificar(
            session,
            user_id=pessoa.id,
            kind=kind,
            severity=incidente.severity,
            title=f"{titulo}: {incidente.reference}",
            body=f"{motivo} {incidente.reference} — {incidente.title}.",
            resource_type="incidente",
            resource_id=incidente.id,
            resource_reference=incidente.reference,
        )

    await _enviar_emails(
        session, ctx,
        pessoas=pessoas, incidente=incidente, titulo=titulo, motivo=motivo,
        equipa=equipa, responsavel=responsavel,
    )
    return pessoas


async def _enviar_emails(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    pessoas: list[User],
    incidente: Incident,
    titulo: str,
    motivo: str,
    equipa: Team | None,
    responsavel: User | None,
) -> None:
    if not settings.envio_de_email_configurado:
        await audit.record(
            session, ctx,
            action="AVISAR_POR_EMAIL", resource_type="incidente",
            resource_id=incidente.id, resource_reference=incidente.reference,
            description=(
                f"Aviso por email de {incidente.reference} não enviado: o canal de "
                "correio não está configurado. As notificações na plataforma "
                "foram criadas."
            ),
            new_value={"nao_enviado_a": [p.email for p in pessoas]},
            outcome=AuditOutcome.FALHA,
            failure_reason="canal de correio não configurado",
        )
        return

    enviados: list[dict[str, str]] = []
    falhados: list[dict[str, str]] = []
    assunto = f"[{incidente.reference}] {titulo}"
    for pessoa in pessoas:
        corpo = _corpo(
            pessoa, incidente,
            motivo=motivo, equipa=equipa, responsavel=responsavel,
            autor=ctx.actor_email,
        )
        try:
            identificador = await asyncio.to_thread(
                email_service.enviar, para=pessoa.email, assunto=assunto, corpo=corpo
            )
        except Exception as exc:  # noqa: BLE001 - a falha de um envio é um resultado, não um erro da operação
            logger.warning(
                "Falhou o aviso de %s para %s: %s", incidente.reference, pessoa.email, exc
            )
            falhados.append({"para": pessoa.email, "erro": str(exc)[:300]})
            continue
        enviados.append({"para": pessoa.email, "message_id": identificador})

    partes = []
    if enviados:
        partes.append("enviado a " + ", ".join(e["para"] for e in enviados))
    if falhados:
        partes.append("falhou para " + ", ".join(f["para"] for f in falhados))
    await audit.record(
        session, ctx,
        action="AVISAR_POR_EMAIL", resource_type="incidente",
        resource_id=incidente.id, resource_reference=incidente.reference,
        description=f"Aviso por email de {incidente.reference} ({titulo}): {'; '.join(partes)}.",
        new_value={"enviados": enviados, "falhados": falhados},
        outcome=AuditOutcome.FALHA if falhados else AuditOutcome.SUCESSO,
        failure_reason=("; ".join(f"{f['para']}: {f['erro']}" for f in falhados)[:500]
                        if falhados else None),
    )
