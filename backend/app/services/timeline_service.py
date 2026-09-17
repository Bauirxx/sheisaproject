"""Linha temporal unificada de um incidente (§31).

Reúne numa única sequência ordenada tudo o que aconteceu: registo de auditoria,
comentários, alertas associados, evidências, tarefas e acções de resposta.

É esta vista que responde à exigência do §31 — reconstruir *o que aconteceu,
quando, como foi detectado, quem investigou, que evidências existem, que
decisões foram tomadas, que acções foram executadas e qual foi o resultado*.
Nenhum destes elementos é suficiente isoladamente; a narrativa só existe quando
estão ordenados no mesmo eixo temporal.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.incident import Incident
from app.models.investigation import Comment, Evidence, Task
from app.models.response import Action
from app.models.system import AuditLog
from app.models.telemetry import Alert
from app.schemas.incident import IncidentTimelineEntry
from app.services.incident_service import PREFIXO_COMENTARIO_DE_TRANSICAO

#: Acções de auditoria que não entram na linha temporal porque o acontecimento já
#: lá está numa entrada mais rica. A auditoria de um comentário diz apenas
#: "comentário adicionado"; o comentário em si traz o texto.
#:
#: **Não confundir com "tirar os comentários de sistema".** Só são duplicados os
#: pares em que a auditoria está ligada ao próprio incidente. A decisão sobre uma
#: acção e os passos de um playbook deixam auditoria ligada à acção ou à
#: execução, que não aparece aqui — e o comentário de sistema é então o único
#: rasto no incidente. Tirá-lo apagaria a aprovação da história.
AUDITORIA_REPRESENTADA_NOUTRA_ENTRADA: frozenset[str] = frozenset({"COMENTAR"})


def _e_comentario_de_transicao(comment: Comment) -> bool:
    """O comentário de sistema que duplica uma auditoria `ALTERAR_ESTADO`.

    Das duas representações da mesma mudança de estado fica a auditoria, que
    traz o valor anterior e o novo; o comentário só os repete em texto.
    """
    return comment.is_system and comment.body.startswith(PREFIXO_COMENTARIO_DE_TRANSICAO)


async def build_timeline(
    session: AsyncSession, incident: Incident
) -> list[IncidentTimelineEntry]:
    entries: list[IncidentTimelineEntry] = []

    # --- auditoria: a espinha dorsal, com valor anterior e novo ---
    audit_rows = await session.execute(
        select(AuditLog)
        .where(AuditLog.resource_id == incident.id)
        .order_by(AuditLog.created_at.asc())
        .limit(500)
    )
    for entry in audit_rows.scalars():
        if entry.action in AUDITORIA_REPRESENTADA_NOUTRA_ENTRADA:
            continue
        dados: dict = {}
        if entry.old_value or entry.new_value:
            dados = {
                "valor_anterior": entry.old_value,
                "valor_novo": entry.new_value,
                "campos": entry.changed_fields,
            }
        entries.append(
            IncidentTimelineEntry(
                instante=entry.created_at,
                tipo="auditoria",
                titulo=entry.action.replace("_", " ").capitalize(),
                detalhe=entry.description,
                autor=entry.actor_email,
                referencia=entry.resource_reference,
                recurso_id=entry.id,
                dados={**dados, "resultado": entry.outcome.value, "origem": entry.origin},
            )
        )

    # --- comentários ---
    comments = await session.execute(
        select(Comment)
        .where(Comment.incident_id == incident.id)
        .options(selectinload(Comment.author))
        .order_by(Comment.created_at.asc())
    )
    for comment in comments.scalars():
        if _e_comentario_de_transicao(comment):
            continue
        entries.append(
            IncidentTimelineEntry(
                instante=comment.created_at,
                tipo="comentario",
                titulo="Comentário do sistema" if comment.is_system else "Comentário",
                detalhe=comment.body,
                autor=(comment.author.full_name if comment.author else "sistema"),
                recurso_id=comment.id,
                dados={"interno": comment.is_internal, "automatico": comment.is_system},
            )
        )

    # --- alertas associados ---
    alerts = await session.execute(
        select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.first_event_at)
    )
    for alert in alerts.scalars():
        entries.append(
            IncidentTimelineEntry(
                # O instante relevante é o do primeiro evento, não o da
                # associação: é quando a actividade de facto ocorreu.
                instante=alert.first_event_at,
                tipo="alerta",
                titulo=f"Alerta {alert.reference}: {alert.title}",
                detalhe=alert.correlation_rationale or alert.triage_rationale,
                autor=alert.source_name,
                referencia=alert.reference,
                recurso_id=alert.id,
                dados={
                    "severidade": alert.severity.value,
                    "pontuacao_triagem": alert.triage_score,
                    "eventos": alert.event_count,
                    "fonte": alert.source_kind.value,
                    "regra": alert.rule_id,
                },
            )
        )

    # --- evidências ---
    evidence_rows = await session.execute(
        select(Evidence)
        .where(Evidence.incident_id == incident.id)
        .options(selectinload(Evidence.uploaded_by))
        .order_by(Evidence.created_at.asc())
    )
    for item in evidence_rows.scalars():
        entries.append(
            IncidentTimelineEntry(
                instante=item.created_at,
                tipo="evidencia",
                titulo=f"Evidência: {item.name}",
                detalhe=item.description or item.original_filename,
                autor=(item.uploaded_by.full_name if item.uploaded_by else "sistema"),
                recurso_id=item.id,
                dados={
                    "tipo_evidencia": item.evidence_type.value,
                    "sha256": item.sha256,
                    "bytes": item.size_bytes,
                },
            )
        )

    # --- tarefas ---
    tasks = await session.execute(
        select(Task)
        .where(Task.incident_id == incident.id)
        .options(selectinload(Task.assignee))
        .order_by(Task.created_at.asc())
    )
    for task in tasks.scalars():
        entries.append(
            IncidentTimelineEntry(
                instante=task.created_at,
                tipo="tarefa",
                titulo=f"Tarefa: {task.title}",
                detalhe=task.outcome or task.description,
                autor=(task.assignee.full_name if task.assignee else None),
                recurso_id=task.id,
                dados={"estado": task.status.value, "prioridade": task.priority.value},
            )
        )

    # --- acções de resposta ---
    actions = await session.execute(
        select(Action)
        .where(Action.incident_id == incident.id)
        .options(selectinload(Action.approvals))
        .order_by(Action.created_at.asc())
    )
    for action in actions.scalars():
        decisions = [
            {
                "decisao": approval.decision.value,
                "decidido_em": (
                    approval.decided_at.isoformat() if approval.decided_at else None
                ),
                "justificacao": approval.justification,
            }
            for approval in action.approvals
        ]
        entries.append(
            IncidentTimelineEntry(
                instante=action.created_at,
                tipo="accao",
                titulo=f"Acção {action.reference}: {action.title}",
                detalhe=action.rationale,
                referencia=action.reference,
                recurso_id=action.id,
                dados={
                    "tipo": action.action_kind.value,
                    "risco": action.risk_level.value,
                    "estado": action.status.value,
                    "alvo": action.target,
                    "resultado": action.result,
                    "erro": action.error,
                    "aprovacoes": decisions,
                },
            )
        )

    entries.sort(key=lambda e: e.instante)
    return entries
