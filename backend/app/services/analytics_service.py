"""Painel, centro de operações e grafo investigativo (§17, §18, §21).

Todos os números vêm de contagens sobre a base de dados, calculadas no momento
do pedido. Não existe cache nem valor pré-calculado: o §17 exige um painel
totalmente dinâmico, e um número em cache é um número potencialmente falso.

Cada indicador é acompanhado da consulta conceptual que o produz, para que
possa ser confirmado manualmente em SQL durante uma defesa.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.enums import (
    INCIDENT_ACTIVE_STATUSES,
    ActionStatus,
    AlertStatus,
    ApprovalDecision,
    IncidentStatus,
    PlaybookExecutionStatus,
    Severity,
    TaskStatus,
)
from app.models.catalog import Asset, Ioc
from app.models.identity import User
from app.models.incident import Incident, IncidentRelation, incident_assets
from app.models.investigation import Observation, Task
from app.models.response import Action, ActionApproval, PlaybookExecution
from app.models.telemetry import Alert, Event


def _not_expired():
    """Pedido de aprovação ainda dentro do prazo.

    Um pedido caducado não pode ser decidido; contá-lo como pendente inflacionava
    o painel e o centro de operações até alguém abrir a fila de aprovação.
    """
    return or_(ActionApproval.expires_at.is_(None), ActionApproval.expires_at > func.now())


async def _scalar(session: AsyncSession, stmt) -> int:
    return int((await session.execute(stmt)).scalar_one() or 0)


async def dashboard_overview(session: AsyncSession, *, days: int = 30) -> dict:
    """Indicadores do painel principal."""
    since = datetime.now(UTC) - timedelta(days=days)

    total_incidents = await _scalar(session, select(func.count()).select_from(Incident))
    active = await _scalar(
        session,
        select(func.count()).select_from(Incident)
        .where(Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES))),
    )
    critical = await _scalar(
        session,
        select(func.count()).select_from(Incident).where(
            Incident.severity == Severity.CRITICA,
            Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)),
        ),
    )
    investigating = await _scalar(
        session,
        select(func.count()).select_from(Incident)
        .where(Incident.status == IncidentStatus.INVESTIGACAO),
    )
    resolved = await _scalar(
        session,
        select(func.count()).select_from(Incident)
        .where(Incident.status == IncidentStatus.RESOLVIDO),
    )
    closed = await _scalar(
        session,
        select(func.count()).select_from(Incident)
        .where(Incident.status == IncidentStatus.ENCERRADO),
    )
    false_positives = await _scalar(
        session,
        select(func.count()).select_from(Incident)
        .where(Incident.status == IncidentStatus.FALSO_POSITIVO),
    )
    overdue = await _scalar(
        session,
        select(func.count()).select_from(Incident).where(
            Incident.due_at.isnot(None),
            Incident.due_at < datetime.now(UTC),
            Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)),
        ),
    )
    unassigned = await _scalar(
        session,
        select(func.count()).select_from(Incident).where(
            Incident.assignee_id.is_(None),
            Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)),
        ),
    )

    alerts_total = await _scalar(session, select(func.count()).select_from(Alert))
    alerts_pending = await _scalar(
        session,
        select(func.count()).select_from(Alert)
        .where(Alert.status.in_([AlertStatus.NOVO, AlertStatus.EM_TRIAGEM])),
    )
    alerts_period = await _scalar(
        session,
        select(func.count()).select_from(Alert).where(Alert.created_at >= since),
    )
    alerts_false_positive = await _scalar(
        session,
        select(func.count()).select_from(Alert)
        .where(Alert.status.in_([AlertStatus.FALSO_POSITIVO, AlertStatus.DESCARTADO])),
    )
    events_total = await _scalar(session, select(func.count()).select_from(Event))

    approvals_pending = await _scalar(
        session,
        select(func.count()).select_from(ActionApproval)
        .where(ActionApproval.decision == ApprovalDecision.PENDENTE, _not_expired()),
    )
    actions_executed = await _scalar(
        session,
        select(func.count()).select_from(Action)
        .where(Action.status == ActionStatus.EXECUTADA),
    )
    tasks_pending = await _scalar(
        session,
        select(func.count()).select_from(Task)
        .where(Task.status.in_([TaskStatus.PENDENTE, TaskStatus.EM_CURSO])),
    )
    iocs_malicious = await _scalar(
        session,
        select(func.count()).select_from(Ioc)
        .where(Ioc.reputation.in_(["MALICIOSA", "SUSPEITA"])),
    )

    return {
        "periodo_dias": days,
        "incidentes": {
            "total": total_incidents,
            "activos": active,
            "criticos": critical,
            "em_investigacao": investigating,
            "resolvidos": resolved,
            "encerrados": closed,
            "falsos_positivos": false_positives,
            "fora_de_prazo": overdue,
            "sem_responsavel": unassigned,
        },
        "alertas": {
            "total": alerts_total,
            "por_triar": alerts_pending,
            "no_periodo": alerts_period,
            "descartados_ou_falsos_positivos": alerts_false_positive,
            "taxa_falsos_positivos_percentagem": (
                round(alerts_false_positive / alerts_total * 100, 1)
                if alerts_total
                else 0.0
            ),
        },
        "eventos": {"total": events_total},
        "resposta": {
            "aprovacoes_pendentes": approvals_pending,
            "accoes_executadas": actions_executed,
            "tarefas_pendentes": tasks_pending,
        },
        "inteligencia": {"indicadores_adversos": iocs_malicious},
    }


async def distribution(session: AsyncSession, *, days: int = 30) -> dict:
    """Distribuições por severidade, categoria, estado e fonte."""
    since = datetime.now(UTC) - timedelta(days=days)

    async def _group(column) -> dict[str, int]:
        result = await session.execute(
            select(column, func.count())
            .where(Incident.detected_at >= since)
            .group_by(column)
        )
        return {str(getattr(k, "value", k)): int(v) for k, v in result.all()}

    severity = await _group(Incident.severity)
    category = await _group(Incident.category)
    status = await _group(Incident.status)
    source = await _group(Incident.source_kind)

    alerts_by_source = await session.execute(
        select(Alert.source_kind, func.count())
        .where(Alert.created_at >= since)
        .group_by(Alert.source_kind)
    )

    return {
        "periodo_dias": days,
        "incidentes_por_severidade": severity,
        "incidentes_por_categoria": category,
        "incidentes_por_estado": status,
        "incidentes_por_fonte": source,
        "alertas_por_fonte": {
            str(getattr(k, "value", k)): int(v) for k, v in alerts_by_source.all()
        },
    }


async def response_metrics(session: AsyncSession, *, days: int = 30) -> dict:
    """Tempos médios de reconhecimento e resolução (§17).

    Calculados em SQL a partir dos marcos temporais reais. Incidentes sem o
    marco correspondente ficam de fora da média em vez de contarem como zero —
    contá-los baixaria artificialmente os tempos.
    """
    since = datetime.now(UTC) - timedelta(days=days)

    ack_seconds = func.extract(
        "epoch", Incident.acknowledged_at - Incident.detected_at
    )
    res_seconds = func.extract("epoch", Incident.resolved_at - Incident.detected_at)

    result = await session.execute(
        select(
            func.avg(ack_seconds).filter(Incident.acknowledged_at.isnot(None)),
            func.percentile_cont(0.5).within_group(ack_seconds)
            .filter(Incident.acknowledged_at.isnot(None)),
            func.count().filter(Incident.acknowledged_at.isnot(None)),
            func.avg(res_seconds).filter(Incident.resolved_at.isnot(None)),
            func.percentile_cont(0.5).within_group(res_seconds)
            .filter(Incident.resolved_at.isnot(None)),
            func.count().filter(Incident.resolved_at.isnot(None)),
        ).where(Incident.detected_at >= since)
    )
    avg_ack, med_ack, n_ack, avg_res, med_res, n_res = result.one()

    # Cumprimento de prazo entre os incidentes já resolvidos.
    sla = await session.execute(
        select(
            func.count(),
            func.count().filter(Incident.resolved_at <= Incident.due_at),
        ).where(
            Incident.detected_at >= since,
            Incident.resolved_at.isnot(None),
            Incident.due_at.isnot(None),
        )
    )
    sla_total, sla_ok = sla.one()

    return {
        "periodo_dias": days,
        "tempo_medio_reconhecimento_segundos": int(avg_ack) if avg_ack else None,
        "tempo_mediano_reconhecimento_segundos": int(med_ack) if med_ack else None,
        "incidentes_reconhecidos": int(n_ack or 0),
        "tempo_medio_resolucao_segundos": int(avg_res) if avg_res else None,
        "tempo_mediano_resolucao_segundos": int(med_res) if med_res else None,
        "incidentes_resolvidos": int(n_res or 0),
        "cumprimento_prazo": {
            "avaliados": int(sla_total or 0),
            "dentro_do_prazo": int(sla_ok or 0),
            "percentagem": (
                round((sla_ok or 0) / sla_total * 100, 1) if sla_total else None
            ),
        },
        "nota": (
            "As médias consideram apenas incidentes com o marco temporal "
            "correspondente registado."
        ),
    }


async def trend(session: AsyncSession, *, days: int = 30) -> list[dict]:
    """Série diária de incidentes e alertas."""
    since = datetime.now(UTC) - timedelta(days=days)

    incidents = await session.execute(
        select(
            func.date_trunc("day", Incident.detected_at).label("dia"),
            func.count(),
            func.count().filter(Incident.severity.in_([Severity.ALTA, Severity.CRITICA])),
        )
        .where(Incident.detected_at >= since)
        .group_by("dia")
        .order_by("dia")
    )
    incident_map = {
        d.date().isoformat(): {"incidentes": int(t), "incidentes_graves": int(g)}
        for d, t, g in incidents.all()
    }

    alerts = await session.execute(
        select(func.date_trunc("day", Alert.created_at).label("dia"), func.count())
        .where(Alert.created_at >= since)
        .group_by("dia")
        .order_by("dia")
    )
    alert_map = {d.date().isoformat(): int(t) for d, t in alerts.all()}

    # Série contínua: dias sem actividade aparecem com zero, para que um
    # gráfico não sugira continuidade onde houve silêncio.
    series: list[dict] = []
    start = (datetime.now(UTC) - timedelta(days=days)).date()
    for offset in range(days + 1):
        day = (start + timedelta(days=offset)).isoformat()
        entry = incident_map.get(day, {"incidentes": 0, "incidentes_graves": 0})
        series.append({"dia": day, **entry, "alertas": alert_map.get(day, 0)})
    return series


async def analyst_workload(session: AsyncSession) -> list[dict]:
    """Carga por analista, medida em incidentes activos e tarefas pendentes."""
    result = await session.execute(
        select(
            User.id,
            User.full_name,
            User.email,
            func.count(Incident.id).filter(
                Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES))
            ),
            func.count(Incident.id).filter(
                Incident.severity.in_([Severity.ALTA, Severity.CRITICA]),
                Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)),
            ),
        )
        .outerjoin(Incident, Incident.assignee_id == User.id)
        .where(User.is_active.is_(True))
        .group_by(User.id, User.full_name, User.email)
        .order_by(func.count(Incident.id).desc())
    )
    rows = result.all()

    tasks = await session.execute(
        select(Task.assignee_id, func.count())
        .where(Task.status.in_([TaskStatus.PENDENTE, TaskStatus.EM_CURSO]))
        .group_by(Task.assignee_id)
    )
    task_map = {k: int(v) for k, v in tasks.all() if k is not None}

    return [
        {
            "utilizador_id": str(user_id),
            "nome": name,
            "email": email,
            "incidentes_activos": int(active),
            "incidentes_graves": int(severe),
            "tarefas_pendentes": task_map.get(user_id, 0),
        }
        for user_id, name, email, active, severe in rows
    ]


async def soc_center(session: AsyncSession, *, limit: int = 10) -> dict:
    """Vista operacional do centro de operações (§18).

    Reúne numa só resposta o que o analista precisa de ver ao entrar ao
    serviço, de modo a não ter de percorrer seis ecrãs para saber o estado.
    """
    active_incidents = await session.execute(
        select(Incident)
        .where(Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)))
        .options(selectinload(Incident.assignee))
        .order_by(Incident.risk_score.desc(), Incident.detected_at.desc())
        .limit(limit)
    )
    recent_alerts = await session.execute(
        select(Alert)
        .where(Alert.status.in_([AlertStatus.NOVO, AlertStatus.EM_TRIAGEM]))
        .order_by(Alert.triage_score.desc(), Alert.last_event_at.desc())
        .limit(limit)
    )
    pending_approvals = await session.execute(
        select(Action)
        .join(ActionApproval, ActionApproval.action_id == Action.id)
        .where(ActionApproval.decision == ApprovalDecision.PENDENTE, _not_expired())
        .options(selectinload(Action.approvals))
        .order_by(Action.created_at.asc())
        .limit(limit)
    )
    running_playbooks = await session.execute(
        select(PlaybookExecution)
        .where(
            PlaybookExecution.status.in_([
                PlaybookExecutionStatus.EM_EXECUCAO,
                PlaybookExecutionStatus.AGUARDA_APROVACAO,
            ])
        )
        .options(selectinload(PlaybookExecution.playbook))
        .order_by(PlaybookExecution.started_at.desc())
        .limit(limit)
    )
    top_iocs = await session.execute(
        select(Ioc)
        .where(Ioc.is_allowlisted.is_(False))
        .order_by(Ioc.sighting_count.desc(), Ioc.last_seen.desc())
        .limit(limit)
    )
    affected_assets = await session.execute(
        select(Asset, func.count(Incident.id))
        .join(incident_assets, incident_assets.c.asset_id == Asset.id)
        .join(Incident, Incident.id == incident_assets.c.incident_id)
        .where(Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES)))
        .group_by(Asset.id)
        .order_by(func.count(Incident.id).desc())
        .limit(limit)
    )
    open_tasks = await session.execute(
        select(Task)
        .where(Task.status.in_([TaskStatus.PENDENTE, TaskStatus.EM_CURSO]))
        .options(selectinload(Task.assignee))
        .order_by(Task.due_at.asc().nulls_last(), Task.created_at.asc())
        .limit(limit)
    )

    return {
        "incidentes_activos": [
            {
                "id": str(i.id), "referencia": i.reference, "titulo": i.title,
                "severidade": i.severity.value, "estado": i.status.value,
                "prioridade": i.priority.value, "pontuacao_risco": i.risk_score,
                "responsavel": i.assignee.full_name if i.assignee else None,
                "detectado_em": i.detected_at.isoformat(),
                "prazo": i.due_at.isoformat() if i.due_at else None,
            }
            for i in active_incidents.scalars()
        ],
        "alertas_recentes": [
            {
                "id": str(a.id), "referencia": a.reference, "titulo": a.title,
                "severidade": a.severity.value, "pontuacao": a.triage_score,
                "fonte": a.source_kind.value, "eventos": a.event_count,
                "ultimo_evento": a.last_event_at.isoformat(),
                "probabilidade_falso_positivo": a.false_positive_score,
            }
            for a in recent_alerts.scalars()
        ],
        "aprovacoes_pendentes": [
            {
                "id": str(a.id), "referencia": a.reference, "titulo": a.title,
                "tipo": a.action_kind.value, "risco": a.risk_level.value,
                "alvo": a.target, "justificacao": a.rationale,
                "solicitado_em": a.created_at.isoformat(),
            }
            for a in pending_approvals.scalars().unique()
        ],
        "playbooks_em_execucao": [
            {
                "id": str(e.id), "referencia": e.reference,
                "playbook": e.playbook.name if e.playbook else "?",
                "estado": e.status.value,
                "iniciado_em": e.started_at.isoformat() if e.started_at else None,
            }
            for e in running_playbooks.scalars().unique()
        ],
        "indicadores_frequentes": [
            {
                "id": str(i.id), "tipo": i.ioc_type.value, "valor": i.value,
                "reputacao": i.reputation.value, "avistamentos": i.sighting_count,
                "ultima_observacao": i.last_seen.isoformat() if i.last_seen else None,
            }
            for i in top_iocs.scalars()
        ],
        "activos_afectados": [
            {
                "id": str(a.id), "identificador": a.identifier, "nome": a.name,
                "criticidade": a.criticality.value, "incidentes_activos": int(n),
            }
            for a, n in affected_assets.all()
        ],
        "tarefas_pendentes": [
            {
                "id": str(t.id), "titulo": t.title, "estado": t.status.value,
                "prioridade": t.priority.value,
                "responsavel": t.assignee.full_name if t.assignee else None,
                "prazo": t.due_at.isoformat() if t.due_at else None,
            }
            for t in open_tasks.scalars()
        ],
    }


# ------------------------------------------------------------------ grafo
async def investigation_graph(
    session: AsyncSession,
    *,
    incident_id: uuid.UUID,
    depth: int = 1,
) -> dict:
    """Grafo investigativo centrado num incidente (§21).

    Nós: incidentes, indicadores, activos e alertas.
    Arestas: observações (com o papel do artefacto), afectação de activos,
    origem de alertas e relações entre incidentes.

    A profundidade controla a expansão para incidentes vizinhos: com `depth=1`
    vê-se o incidente e o que lhe pertence; com `depth=2` juntam-se os
    incidentes que partilham indicadores, que é como se descobre uma campanha
    sem perder o contexto do caso inicial.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    visited: set[uuid.UUID] = set()
    # Uma relação liga dois incidentes e é encontrada a partir de cada um deles;
    # sem esta memória, com profundidade 2 era desenhada (e contada) duas vezes.
    drawn_relations: set[uuid.UUID] = set()
    frontier = [incident_id]

    def add_node(key: str, **data) -> None:
        if key not in nodes:
            nodes[key] = {"id": key, **data}

    for level in range(max(1, depth)):
        next_frontier: list[uuid.UUID] = []

        for current_id in frontier:
            if current_id in visited:
                continue
            visited.add(current_id)

            incident = await session.get(Incident, current_id)
            if incident is None:
                continue

            add_node(
                f"incidente:{incident.id}",
                tipo="incidente",
                rotulo=incident.reference,
                titulo=incident.title,
                severidade=incident.severity.value,
                estado=incident.status.value,
                principal=(incident.id == incident_id),
                nivel=level,
            )

            # --- observações: incidente -> indicador, com o papel na aresta ---
            observations = await session.execute(
                select(Observation)
                .where(Observation.incident_id == incident.id)
                .options(selectinload(Observation.ioc), selectinload(Observation.asset))
            )
            for obs in observations.scalars():
                ioc_key = f"ioc:{obs.ioc.id}"
                add_node(
                    ioc_key,
                    tipo="indicador",
                    subtipo=obs.ioc.ioc_type.value,
                    rotulo=obs.ioc.value,
                    reputacao=obs.ioc.reputation.value,
                    avistamentos=obs.ioc.sighting_count,
                )
                edges.append({
                    "origem": f"incidente:{incident.id}",
                    "destino": ioc_key,
                    "tipo": "observou",
                    "rotulo": obs.role.value,
                    "instante": obs.observed_at.isoformat(),
                    "automatico": obs.is_automatic,
                })

            # --- activos afectados ---
            await session.refresh(incident, ["assets"])
            for asset in incident.assets:
                asset_key = f"activo:{asset.id}"
                add_node(
                    asset_key,
                    tipo="activo",
                    rotulo=asset.identifier,
                    nome=asset.name,
                    criticidade=asset.criticality.value,
                    subtipo=asset.asset_type.value,
                )
                edges.append({
                    "origem": f"incidente:{incident.id}",
                    "destino": asset_key,
                    "tipo": "afectou",
                    "rotulo": "activo afectado",
                })

            # --- alertas de origem ---
            alerts = await session.execute(
                select(Alert).where(Alert.incident_id == incident.id).limit(50)
            )
            for alert in alerts.scalars():
                alert_key = f"alerta:{alert.id}"
                add_node(
                    alert_key,
                    tipo="alerta",
                    rotulo=alert.reference,
                    titulo=alert.title,
                    severidade=alert.severity.value,
                    fonte=alert.source_kind.value,
                    pontuacao=alert.triage_score,
                )
                edges.append({
                    "origem": alert_key,
                    "destino": f"incidente:{incident.id}",
                    "tipo": "originou",
                    "rotulo": alert.correlation_outcome.value,
                })

            # --- relações declaradas entre incidentes ---
            relations = await session.execute(
                select(IncidentRelation).where(
                    (IncidentRelation.source_incident_id == incident.id)
                    | (IncidentRelation.target_incident_id == incident.id)
                )
            )
            for relation in relations.scalars():
                if relation.id in drawn_relations:
                    continue
                drawn_relations.add(relation.id)
                other_id = (
                    relation.target_incident_id
                    if relation.source_incident_id == incident.id
                    else relation.source_incident_id
                )
                other = await session.get(Incident, other_id)
                if other is None:
                    continue
                add_node(
                    f"incidente:{other.id}",
                    tipo="incidente",
                    rotulo=other.reference,
                    titulo=other.title,
                    severidade=other.severity.value,
                    estado=other.status.value,
                    principal=False,
                    nivel=level + 1,
                )
                edges.append({
                    "origem": f"incidente:{relation.source_incident_id}",
                    "destino": f"incidente:{relation.target_incident_id}",
                    "tipo": "relacionado",
                    "rotulo": relation.relation_type.value,
                    "justificacao": relation.rationale,
                })
                next_frontier.append(other_id)

        # Expansão por indicadores partilhados: é isto que revela campanhas.
        if level + 1 < depth:
            shared = await session.execute(
                select(Observation.incident_id)
                .join(Ioc, Ioc.id == Observation.ioc_id)
                .where(
                    Ioc.id.in_(
                        select(Observation.ioc_id).where(
                            Observation.incident_id.in_(list(visited))
                        )
                    ),
                    Observation.incident_id.notin_(list(visited)),
                    Ioc.is_allowlisted.is_(False),
                )
                .distinct()
                .limit(20)
            )
            next_frontier.extend(i for (i,) in shared.all())

        frontier = next_frontier
        if not frontier:
            break

    return {
        "nos": list(nodes.values()),
        "arestas": edges,
        "centro": f"incidente:{incident_id}",
        "profundidade": depth,
        "resumo": {
            "nos": len(nodes),
            "arestas": len(edges),
            "incidentes": sum(1 for n in nodes.values() if n["tipo"] == "incidente"),
            "indicadores": sum(1 for n in nodes.values() if n["tipo"] == "indicador"),
            "activos": sum(1 for n in nodes.values() if n["tipo"] == "activo"),
            "alertas": sum(1 for n in nodes.values() if n["tipo"] == "alerta"),
        },
    }


async def ioc_graph(session: AsyncSession, *, ioc_id: uuid.UUID) -> dict:
    """Grafo centrado num indicador: onde foi visto e com que mais coexiste."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    ioc = await session.get(Ioc, ioc_id)
    if ioc is None:
        return {"nos": [], "arestas": [], "centro": None}

    centre = f"ioc:{ioc.id}"
    nodes[centre] = {
        "id": centre, "tipo": "indicador", "subtipo": ioc.ioc_type.value,
        "rotulo": ioc.value, "reputacao": ioc.reputation.value,
        "avistamentos": ioc.sighting_count, "principal": True,
    }

    observations = await session.execute(
        select(Observation)
        .where(Observation.ioc_id == ioc.id)
        .options(selectinload(Observation.asset))
        .order_by(Observation.observed_at.desc())
        .limit(100)
    )
    incident_ids: set[uuid.UUID] = set()
    for obs in observations.scalars():
        incident = await session.get(Incident, obs.incident_id)
        if incident is None:
            continue
        incident_ids.add(incident.id)
        key = f"incidente:{incident.id}"
        nodes.setdefault(key, {
            "id": key, "tipo": "incidente", "rotulo": incident.reference,
            "titulo": incident.title, "severidade": incident.severity.value,
            "estado": incident.status.value, "principal": False,
        })
        edges.append({
            "origem": key, "destino": centre, "tipo": "observou",
            "rotulo": obs.role.value, "instante": obs.observed_at.isoformat(),
        })

    # Indicadores que coocorrem: vistos nos mesmos incidentes que este.
    if incident_ids:
        co_occurring = await session.execute(
            select(Ioc, func.count(Observation.id))
            .join(Observation, Observation.ioc_id == Ioc.id)
            .where(
                Observation.incident_id.in_(list(incident_ids)),
                Ioc.id != ioc.id,
            )
            .group_by(Ioc.id)
            .order_by(func.count(Observation.id).desc())
            .limit(25)
        )
        for other, count in co_occurring.all():
            key = f"ioc:{other.id}"
            nodes.setdefault(key, {
                "id": key, "tipo": "indicador", "subtipo": other.ioc_type.value,
                "rotulo": other.value, "reputacao": other.reputation.value,
                "avistamentos": other.sighting_count, "principal": False,
            })
            edges.append({
                "origem": centre, "destino": key, "tipo": "coocorre",
                "rotulo": f"{count} coocorrência(s)",
            })

    return {
        "nos": list(nodes.values()),
        "arestas": edges,
        "centro": centre,
        "resumo": {"nos": len(nodes), "arestas": len(edges)},
    }
