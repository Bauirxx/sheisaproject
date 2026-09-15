"""Geração de relatórios (§31).

O relatório de incidente responde, por construção, às oito perguntas do §31:

    O QUE ACONTECEU → QUANDO → COMO FOI DETECTADO → QUEM INVESTIGOU
    → QUE EVIDÊNCIAS EXISTEM → QUE DECISÕES FORAM TOMADAS
    → QUE ACÇÕES FORAM EXECUTADAS → QUAL FOI O RESULTADO

Cada secção é preenchida a partir de registos reais. Quando não há dados para
uma secção, o relatório di-lo — "nenhuma evidência foi recolhida" é uma
conclusão legítima e, num relatório de incidente, uma informação importante.

O conteúdo é persistido no momento da geração. Um relatório é um instantâneo:
regenerá-lo dias depois, com os dados já alterados, deixaria de descrever o que
foi apresentado a quem o leu.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import (
    ActionStatus,
    ApprovalDecision,
    ReportKind,
)
from app.core.references import ReferenceKind, next_reference
from app.models.incident import Incident, IncidentTechnique
from app.models.investigation import Comment, Evidence, Observation, Task
from app.models.response import Action, PlaybookExecution
from app.models.system import AuditLog, Report
from app.models.telemetry import Alert
from app.services import analytics_service


def _duration(seconds: int | None) -> str | None:
    if seconds is None:
        return None
    if seconds < 60:
        return f"{seconds} segundo(s)"
    if seconds < 3600:
        return f"{seconds // 60} minuto(s)"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}min"
    return f"{seconds // 86400} dia(s) {(seconds % 86400) // 3600}h"


async def build_incident_report(
    session: AsyncSession, incident: Incident
) -> dict:
    """Reconstitui um incidente do princípio ao fim."""
    alerts = (
        await session.execute(
            select(Alert).where(Alert.incident_id == incident.id)
            .order_by(Alert.first_event_at)
        )
    ).scalars().all()

    observations = (
        await session.execute(
            select(Observation)
            .where(Observation.incident_id == incident.id)
            .options(selectinload(Observation.ioc))
            .order_by(Observation.observed_at)
        )
    ).scalars().all()

    evidence = (
        await session.execute(
            select(Evidence)
            .where(Evidence.incident_id == incident.id)
            .options(selectinload(Evidence.uploaded_by))
            .order_by(Evidence.created_at)
        )
    ).scalars().all()

    tasks = (
        await session.execute(
            select(Task).where(Task.incident_id == incident.id)
            .options(selectinload(Task.assignee)).order_by(Task.ordering)
        )
    ).scalars().all()

    actions = (
        await session.execute(
            select(Action).where(Action.incident_id == incident.id)
            .options(selectinload(Action.approvals)).order_by(Action.created_at)
        )
    ).scalars().all()

    techniques = (
        await session.execute(
            select(IncidentTechnique)
            .where(IncidentTechnique.incident_id == incident.id)
            .options(selectinload(IncidentTechnique.technique))
        )
    ).scalars().all()

    executions = (
        await session.execute(
            select(PlaybookExecution)
            .where(PlaybookExecution.incident_id == incident.id)
            .options(selectinload(PlaybookExecution.playbook))
            .order_by(PlaybookExecution.created_at)
        )
    ).scalars().all()

    decisions = (
        await session.execute(
            select(AuditLog)
            .where(
                AuditLog.resource_id == incident.id,
                AuditLog.action.in_([
                    "ALTERAR_ESTADO", "ATRIBUIR_INCIDENTE", "EDITAR_INCIDENTE",
                    "DECIDIR_ACCAO", "PROMOVER_ALERTA", "RELACIONAR_INCIDENTES",
                ]),
            )
            .order_by(AuditLog.created_at)
        )
    ).scalars().all()

    comments = (
        await session.execute(
            select(Comment).where(Comment.incident_id == incident.id)
            .options(selectinload(Comment.author)).order_by(Comment.created_at)
        )
    ).scalars().all()

    await session.refresh(incident, ["assets", "assignee", "reporter", "team"])

    # --- 1. O QUE ACONTECEU ---
    o_que_aconteceu = {
        "referencia": incident.reference,
        "titulo": incident.title,
        "descricao": incident.description,
        "categoria": incident.category.value,
        "subtipo": incident.subtype,
        "severidade": incident.severity.value,
        "prioridade": incident.priority.value,
        "estado_final": incident.status.value,
        "confianca": incident.confidence.value,
        "activos_afectados": [
            {
                "identificador": a.identifier, "nome": a.name,
                "criticidade": a.criticality.value, "ip": a.ip_address,
            }
            for a in incident.assets
        ],
        "utilizadores_afectados": incident.affected_users,
    }

    # --- 2. QUANDO ---
    quando = {
        "detectado_em": incident.detected_at.isoformat(),
        "reconhecido_em": (
            incident.acknowledged_at.isoformat() if incident.acknowledged_at else None
        ),
        "contido_em": incident.contained_at.isoformat() if incident.contained_at else None,
        "erradicado_em": (
            incident.eradicated_at.isoformat() if incident.eradicated_at else None
        ),
        "resolvido_em": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "encerrado_em": incident.closed_at.isoformat() if incident.closed_at else None,
        "prazo": incident.due_at.isoformat() if incident.due_at else None,
        "tempo_ate_reconhecimento": _duration(incident.time_to_acknowledge_seconds),
        "tempo_ate_resolucao": _duration(incident.time_to_resolve_seconds),
        "cumpriu_prazo": (
            (incident.resolved_at <= incident.due_at)
            if incident.resolved_at and incident.due_at
            else None
        ),
    }

    # --- 3. COMO FOI DETECTADO ---
    como_detectado = {
        "origem": incident.origin.value,
        "fonte": incident.source_kind.value,
        "detalhe_da_fonte": incident.source_detail,
        "alertas": [
            {
                "referencia": a.reference, "titulo": a.title,
                "fonte": a.source_kind.value, "regra": a.rule_id,
                "nome_da_regra": a.rule_name,
                "severidade": a.severity.value, "eventos_agregados": a.event_count,
                "pontuacao_triagem": a.triage_score,
                "justificacao_triagem": a.triage_rationale,
                "justificacao_correlacao": a.correlation_rationale,
                "primeiro_evento": a.first_event_at.isoformat(),
                "ultimo_evento": a.last_event_at.isoformat(),
            }
            for a in alerts
        ],
        "total_eventos": sum(a.event_count for a in alerts),
    }
    if not alerts:
        como_detectado["nota"] = (
            "Incidente registado manualmente; não teve origem em alertas automáticos."
        )

    # --- 4. QUEM INVESTIGOU ---
    participantes = {
        c.author.full_name for c in comments if c.author is not None
    } | {t.assignee.full_name for t in tasks if t.assignee is not None}
    quem_investigou = {
        "responsavel": incident.assignee.full_name if incident.assignee else None,
        "equipa": incident.team.name if incident.team else None,
        "registado_por": incident.reporter.full_name if incident.reporter else None,
        "participantes": sorted(participantes),
        "comentarios": len([c for c in comments if not c.is_system]),
        "notas_do_sistema": len([c for c in comments if c.is_system]),
    }

    # --- 5. QUE EVIDÊNCIAS EXISTEM ---
    evidencias = {
        "total": len(evidence),
        "itens": [
            {
                "nome": e.name, "tipo": e.evidence_type.value,
                "ficheiro_original": e.original_filename, "bytes": e.size_bytes,
                "sha256": e.sha256,
                "integridade_verificada_em": (
                    e.integrity_verified_at.isoformat() if e.integrity_verified_at else None
                ),
                "integra": e.integrity_ok,
                "recolhida_por": e.uploaded_by.full_name if e.uploaded_by else None,
                "origem": e.source,
            }
            for e in evidence
        ],
    }
    if not evidence:
        evidencias["nota"] = "Nenhuma evidência foi recolhida para este incidente."

    # --- indicadores e MITRE ---
    indicadores = {
        "total": len({o.ioc_id for o in observations}),
        "itens": [
            {
                "tipo": o.ioc.ioc_type.value, "valor": o.ioc.value,
                "papel": o.role.value, "reputacao": o.ioc.reputation.value,
                "observado_em": o.observed_at.isoformat(),
                "avistamentos_globais": o.ioc.sighting_count,
                "origem_do_registo": "automático" if o.is_automatic else "analista",
            }
            for o in observations
        ],
    }
    mitre = {
        "afirmadas": [
            {
                "tecnica": t.technique.technique_id, "nome": t.technique.name,
                "confianca": t.confidence.value, "justificacao": t.rationale,
            }
            for t in techniques if t.is_asserted
        ],
        "hipoteses": [
            {
                "tecnica": t.technique.technique_id, "nome": t.technique.name,
                "confianca": t.confidence.value, "justificacao": t.rationale,
            }
            for t in techniques if not t.is_asserted
        ],
        "nota": (
            "As hipóteses foram inferidas pelo motor e não constituem "
            "confirmação de que a técnica ocorreu."
        ),
    }

    # --- 6. QUE DECISÕES FORAM TOMADAS ---
    decisoes = [
        {
            "instante": d.created_at.isoformat(),
            "accao": d.action,
            "autor": d.actor_email,
            "descricao": d.description,
            "valor_anterior": d.old_value,
            "valor_novo": d.new_value,
        }
        for d in decisions
    ]

    # --- 7. QUE ACÇÕES FORAM EXECUTADAS ---
    accoes = []
    for action in actions:
        aprovacoes = [
            {
                "decisao": ap.decision.value,
                "decidido_em": ap.decided_at.isoformat() if ap.decided_at else None,
                "permissao_exigida": ap.required_permission,
                "justificacao": ap.justification,
            }
            for ap in action.approvals
        ]
        accoes.append({
            "referencia": action.reference,
            "tipo": action.action_kind.value,
            "titulo": action.title,
            "risco": action.risk_level.value,
            "estado": action.status.value,
            "alvo": action.target,
            "justificacao": action.rationale,
            "proposta_pelo_motor": action.proposed_by_engine,
            "executada_em": action.executed_at.isoformat() if action.executed_at else None,
            "resultado": action.result,
            "erro": action.error,
            "aprovacoes": aprovacoes,
        })

    playbooks = [
        {
            "referencia": e.reference,
            "playbook": e.playbook.name if e.playbook else "?",
            "versao": e.playbook_version,
            "estado": e.status.value,
            "automatico": e.triggered_automatically,
            "resumo": e.result_summary,
            "erro": e.error,
        }
        for e in executions
    ]

    # --- 8. QUAL FOI O RESULTADO ---
    executed = [a for a in actions if a.status == ActionStatus.EXECUTADA]
    failed = [a for a in actions if a.status == ActionStatus.FALHADA]
    rejected = [
        a for a in actions
        if any(ap.decision == ApprovalDecision.REJEITADA for ap in a.approvals)
    ]
    resultado = {
        "estado_final": incident.status.value,
        "resumo_da_resolucao": incident.resolution_summary,
        "motivo_falso_positivo": incident.false_positive_reason,
        "licoes_aprendidas": incident.lessons_learned,
        "accoes_executadas": len(executed),
        "accoes_falhadas": len(failed),
        "accoes_rejeitadas": len(rejected),
        "tarefas": {
            "total": len(tasks),
            "concluidas": len([t for t in tasks if t.status.value == "CONCLUIDA"]),
            "itens": [
                {
                    "titulo": t.title, "estado": t.status.value,
                    "responsavel": t.assignee.full_name if t.assignee else None,
                    "resultado": t.outcome,
                }
                for t in tasks
            ],
        },
    }
    if incident.resolution_summary is None and incident.status.value not in (
        "RESOLVIDO", "ENCERRADO"
    ):
        resultado["nota"] = "O incidente ainda não foi resolvido."

    return {
        "tipo": "relatorio_de_incidente",
        "gerado_em": datetime.now(UTC).isoformat(),
        "o_que_aconteceu": o_que_aconteceu,
        "quando": quando,
        "como_foi_detectado": como_detectado,
        "quem_investigou": quem_investigou,
        "que_evidencias_existem": evidencias,
        "indicadores_observados": indicadores,
        "tecnicas_mitre": mitre,
        "que_decisoes_foram_tomadas": decisoes,
        "que_accoes_foram_executadas": {"accoes": accoes, "playbooks": playbooks},
        "qual_foi_o_resultado": resultado,
    }


async def build_period_report(
    session: AsyncSession, *, start: datetime, end: datetime
) -> dict:
    """Relatório de actividade num intervalo."""
    days = max(1, (end - start).days)

    incidents = (
        await session.execute(
            select(Incident)
            .where(Incident.detected_at >= start, Incident.detected_at <= end)
            .order_by(Incident.detected_at)
        )
    ).scalars().all()

    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for incident in incidents:
        by_severity[incident.severity.value] = by_severity.get(incident.severity.value, 0) + 1
        by_category[incident.category.value] = by_category.get(incident.category.value, 0) + 1
        by_status[incident.status.value] = by_status.get(incident.status.value, 0) + 1

    alerts_total = (
        await session.execute(
            select(func.count()).select_from(Alert)
            .where(Alert.created_at >= start, Alert.created_at <= end)
        )
    ).scalar_one()

    actions_total = (
        await session.execute(
            select(func.count()).select_from(Action)
            .where(Action.created_at >= start, Action.created_at <= end)
        )
    ).scalar_one()

    metrics = await analytics_service.response_metrics(session, days=days)

    return {
        "tipo": "relatorio_de_periodo",
        "gerado_em": datetime.now(UTC).isoformat(),
        "periodo": {
            "inicio": start.isoformat(), "fim": end.isoformat(), "dias": days,
        },
        "totais": {
            "incidentes": len(incidents),
            "alertas": int(alerts_total or 0),
            "accoes": int(actions_total or 0),
        },
        "distribuicao": {
            "por_severidade": by_severity,
            "por_categoria": by_category,
            "por_estado": by_status,
        },
        "metricas_de_resposta": metrics,
        "incidentes": [
            {
                "referencia": i.reference, "titulo": i.title,
                "severidade": i.severity.value, "categoria": i.category.value,
                "estado": i.status.value,
                "detectado_em": i.detected_at.isoformat(),
                "resolvido_em": i.resolved_at.isoformat() if i.resolved_at else None,
                "tempo_ate_resolucao": _duration(i.time_to_resolve_seconds),
            }
            for i in incidents
        ],
    }


async def persist_report(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    kind: ReportKind,
    title: str,
    content: dict,
    parameters: dict,
    incident_id: uuid.UUID | None = None,
    period_start: datetime | None = None,
    period_end: datetime | None = None,
    record_count: int = 0,
) -> Report:
    reference = await next_reference(session, ReferenceKind.REPORT)
    report = Report(
        reference=reference,
        kind=kind,
        title=title[:250],
        parameters=parameters,
        content=content,
        period_start=period_start,
        period_end=period_end,
        incident_id=incident_id,
        generated_by_id=ctx.actor_id,
        record_count=record_count,
    )
    session.add(report)
    await session.flush()

    await audit.record(
        session, ctx,
        action="GERAR_RELATORIO", resource_type="relatorio",
        resource_id=report.id, resource_reference=report.reference,
        description=f"Relatório {reference} ({kind.value}) gerado: {title}.",
    )
    return report
