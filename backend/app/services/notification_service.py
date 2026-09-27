"""Criação de notificações dirigidas a um utilizador.

Centraliza o padrão que estava repetido à mão: nunca notificar alguém da sua
própria acção — seria ruído, quem faz já sabe — e nunca criar uma notificação
sem destinatário. As notificações são lidas em `/api/notifications` e marcadas
como lidas em `/api/notifications/{id}/read`.

Nem todos os valores de `NotificationKind` são emitidos: `CORRELACAO_DETECTADA` e
`RECOMENDACAO_NOVA` são eventos de sistema anteriores à atribuição de um
incidente, sem um destinatário individual óbvio, e ficam por emitir até haver
uma decisão sobre a quem se dirigem (um papel, uma equipa). Não são apresentados
na interface como se ocorressem.
"""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import NotificationKind, Severity
from app.models.system import Notification


def notificar(
    session: AsyncSession,
    *,
    user_id: uuid.UUID | None,
    kind: NotificationKind,
    title: str,
    body: str,
    severity: Severity = Severity.MEDIA,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    resource_reference: str | None = None,
    excepto: uuid.UUID | None = None,
) -> Notification | None:
    """Cria uma notificação para `user_id`, quando faz sentido.

    Não cria nada (e devolve ``None``) se não houver destinatário, ou se o
    destinatário for `excepto` — tipicamente quem desencadeou a acção, que não
    precisa de ser avisado de algo que acabou de fazer. Acrescenta à sessão sem
    fazer `flush`: a transacção de quem chama é que decide quando gravar.
    """
    if user_id is None or user_id == excepto:
        return None
    notificacao = Notification(
        user_id=user_id,
        kind=kind,
        severity=severity,
        title=title,
        body=body,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_reference=resource_reference,
    )
    session.add(notificacao)
    return notificacao
