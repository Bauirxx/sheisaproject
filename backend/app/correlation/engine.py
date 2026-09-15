"""Motor de correlação (§9).

Responde à pergunta que distingue esta plataforma de um sistema de bilhetes:
*estes alertas são a mesma actividade?*

O TheHive oferece "procurar semelhantes" — uma pesquisa. Aqui a correlação é
avaliada por regras configuráveis, cada uma com uma estratégia própria:

``ENTIDADE_PARTILHADA``
    Alertas distintos que partilham um artefacto **do lado do atacante** (o
    mesmo endereço de origem, o mesmo destino de comando e controlo, o mesmo
    artefacto). Responde a "é o mesmo actor?". Artefactos do lado da vítima
    são deliberadamente ignorados — ver `ATTACKER_SIDE_ROLES`.

``LIMIAR``
    N ocorrências da mesma detecção dentro da janela. Responde a "isto está a
    acontecer repetidamente?".

``SEQUENCIA_TEMPORAL``
    Categorias de detecção a ocorrer pela ordem de uma cadeia de ataque
    (recolha → acesso inicial → execução). Responde a "isto progrediu?".

``ACTIVO_ALVO``
    Detecções heterogéneas a convergir no mesmo activo. Responde a "este
    sistema está sob ataque por várias frentes?".

O resultado nunca é aplicado em silêncio: cada decisão traz a justificação
textual do que foi correlacionado e porquê, guardada no alerta e no incidente.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AlertStatus,
    CorrelationOutcome,
    CorrelationStrategy,
    IncidentStatus,
    ObservationRole,
    Severity,
)
from app.models.catalog import Ioc
from app.models.incident import Incident
from app.models.investigation import Observation
from app.models.telemetry import Alert, CorrelationRule, Event

logger = logging.getLogger("sheisa.correlacao")

#: Estados de incidente que ainda aceitam novos alertas. Ligar um alerta a um
#: incidente encerrado reescreveria um registo já concluído.
LINKABLE_STATUSES = [
    IncidentStatus.NOVO, IncidentStatus.ABERTO, IncidentStatus.TRIAGEM,
    IncidentStatus.INVESTIGACAO, IncidentStatus.CONTENCAO,
    IncidentStatus.ERRADICACAO, IncidentStatus.RECUPERACAO,
    IncidentStatus.SUSPENSO, IncidentStatus.ESCALADO,
]


@dataclass(slots=True)
class CorrelationDecision:
    """O que o motor concluiu sobre um alerta."""

    outcome: CorrelationOutcome
    rule: CorrelationRule | None = None
    incident_id: uuid.UUID | None = None
    related_alert_ids: list[uuid.UUID] = field(default_factory=list)
    rationale: str = ""
    suggested_severity: Severity | None = None

    @property
    def matched(self) -> bool:
        return self.outcome != CorrelationOutcome.SEM_CORRELACAO


#: Papéis que identificam o *lado do atacante*.
#:
#: A estratégia ENTIDADE_PARTILHADA responde a "é o mesmo actor?". Se
#: considerasse todos os papéis, dois ataques sem qualquer relação contra o
#: mesmo servidor seriam correlacionados como "mesmo actor" por partilharem o
#: nome do host — que é a *vítima*, não o agressor. Partilhar um alvo é uma
#: pergunta diferente, e tem estratégia própria (ACTIVO_ALVO).
ATTACKER_SIDE_ROLES: frozenset[str] = frozenset({
    ObservationRole.ORIGEM.value,    # endereço de origem
    ObservationRole.DESTINO.value,   # destino externo: tipicamente C2
    ObservationRole.PAYLOAD.value,   # hash do artefacto usado
    ObservationRole.ACTOR.value,     # conta que executou a acção
})


async def _alert_indicator_values(
    session: AsyncSession, alert: Alert, *, roles: frozenset[str] | None = None
) -> set[str]:
    """Valores dos indicadores observados nos eventos do alerta.

    `roles` restringe os papéis considerados. `None` significa todos.
    """
    result = await session.execute(
        select(Event.normalized_extra).where(Event.alert_id == alert.id).limit(100)
    )
    values: set[str] = set()
    for (extra,) in result.all():
        for item in (extra or {}).get("indicadores", []):
            value = item.get("valor")
            if not value:
                continue
            if roles is not None and item.get("papel") not in roles:
                continue
            values.add(value)
    return values


async def _alert_field_values(
    session: AsyncSession, alert: Alert, fields: list[str]
) -> dict[str, set[str]]:
    """Valores dos campos indicados, recolhidos dos eventos do alerta."""
    if not fields:
        return {}
    columns = [getattr(Event, f) for f in fields if hasattr(Event, f)]
    if not columns:
        return {}
    result = await session.execute(
        select(*columns).where(Event.alert_id == alert.id).limit(100)
    )
    collected: dict[str, set[str]] = {f: set() for f in fields if hasattr(Event, f)}
    names = [f for f in fields if hasattr(Event, f)]
    for row in result.all():
        for name, value in zip(names, row, strict=False):
            if value:
                collected[name].add(str(value))
    return collected


def _passes_conditions(alert: Alert, conditions: dict) -> bool:
    """Filtros que restringem os alertas a que a regra se aplica."""
    if not conditions:
        return True

    if minimum := conditions.get("severity_min"):
        try:
            if alert.severity.rank < Severity(minimum).rank:
                return False
        except ValueError:
            pass

    if groups := conditions.get("rule_groups_any"):
        if not set(alert.tags).intersection(groups):
            return False

    if (sources := conditions.get("source_kinds")) and alert.source_kind.value not in sources:
        return False

    if minimum_score := conditions.get("triage_score_min"):
        if alert.triage_score < int(minimum_score):
            return False

    return True


async def _candidates_in_window(
    session: AsyncSession, alert: Alert, window_minutes: int
) -> list[Alert]:
    """Outros alertas abertos ou já correlacionados dentro da janela."""
    since = alert.last_event_at - timedelta(minutes=window_minutes)
    result = await session.execute(
        select(Alert)
        .where(
            Alert.id != alert.id,
            Alert.last_event_at >= since,
            Alert.last_event_at <= alert.last_event_at + timedelta(minutes=window_minutes),
            Alert.status.in_([
                AlertStatus.NOVO, AlertStatus.EM_TRIAGEM, AlertStatus.CORRELACIONADO,
                AlertStatus.PROMOVIDO,
            ]),
        )
        .order_by(Alert.last_event_at.desc())
        .limit(200)
    )
    return list(result.scalars())


# ------------------------------------------------------------------ estratégias
async def _match_shared_entity(
    session: AsyncSession, alert: Alert, rule: CorrelationRule
) -> tuple[list[Alert], str] | None:
    """Alertas que partilham um artefacto do lado do atacante com este."""
    # A regra pode alargar ou restringir os papéis considerados; por omissão
    # só conta o lado do atacante, para não confundir "mesmo agressor" com
    # "mesma vítima".
    configured = rule.conditions.get("papeis")
    roles = frozenset(configured) if configured else ATTACKER_SIDE_ROLES

    own_values: set[str] = set()

    # Sem campos declarados, usamos os indicadores extraídos — é o caso mais
    # comum e evita ter de enumerar colunas em cada regra.
    if rule.match_fields:
        field_values = await _alert_field_values(session, alert, rule.match_fields)
        for values in field_values.values():
            own_values.update(values)
    else:
        own_values = await _alert_indicator_values(session, alert, roles=roles)

    if not own_values:
        return None

    matches: list[Alert] = []
    shared: set[str] = set()

    for candidate in await _candidates_in_window(session, alert, rule.window_minutes):
        if not _passes_conditions(candidate, rule.conditions):
            continue
        if rule.match_fields:
            candidate_values = set()
            for values in (
                await _alert_field_values(session, candidate, rule.match_fields)
            ).values():
                candidate_values.update(values)
        else:
            candidate_values = await _alert_indicator_values(
                session, candidate, roles=roles
            )

        common = own_values.intersection(candidate_values)
        if common:
            matches.append(candidate)
            shared.update(common)

    if len(matches) + 1 < rule.min_alerts:
        return None

    artefactos = ", ".join(sorted(shared)[:4])
    return matches, (
        f"{len(matches) + 1} alertas em {rule.window_minutes} minutos partilham "
        f"o(s) artefacto(s): {artefactos}."
    )


async def _match_threshold(
    session: AsyncSession, alert: Alert, rule: CorrelationRule
) -> tuple[list[Alert], str] | None:
    """N ocorrências da mesma detecção dentro da janela."""
    if not alert.rule_id:
        return None

    since = alert.last_event_at - timedelta(minutes=rule.window_minutes)
    result = await session.execute(
        select(Alert)
        .where(
            Alert.id != alert.id,
            Alert.rule_id == alert.rule_id,
            Alert.last_event_at >= since,
            Alert.status.in_([
                AlertStatus.NOVO, AlertStatus.EM_TRIAGEM,
                AlertStatus.CORRELACIONADO, AlertStatus.PROMOVIDO,
            ]),
        )
        .limit(200)
    )
    matches = [a for a in result.scalars() if _passes_conditions(a, rule.conditions)]

    # O limiar conta ocorrências, não alertas: um alerta com 300 eventos
    # agregados já satisfaz um limiar de 50 sozinho.
    total_events = alert.event_count + sum(a.event_count for a in matches)
    if total_events < rule.min_alerts and len(matches) + 1 < rule.min_alerts:
        return None

    return matches, (
        f"Limiar atingido: {len(matches) + 1} alertas / {total_events} eventos da "
        f"regra {alert.rule_id} em {rule.window_minutes} minutos."
    )


async def _match_sequence(
    session: AsyncSession, alert: Alert, rule: CorrelationRule
) -> tuple[list[Alert], str] | None:
    """Categorias de detecção a ocorrer pela ordem de uma cadeia de ataque."""
    expected = [s.lower() for s in rule.sequence]
    if not expected:
        return None

    candidates = await _candidates_in_window(session, alert, rule.window_minutes)
    timeline = sorted([*candidates, alert], key=lambda a: a.last_event_at)

    matched: list[Alert] = []
    position = 0
    for item in timeline:
        if position >= len(expected):
            break
        labels = {t.lower() for t in item.tags}
        if item.rule_name:
            labels.add(item.rule_name.lower())
        if any(expected[position] in label for label in labels):
            matched.append(item)
            position += 1

    # A sequência só conta se estiver completa e incluir o alerta actual —
    # caso contrário reabriríamos correlações antigas a cada novo alerta.
    if position < len(expected) or alert not in matched:
        return None

    others = [a for a in matched if a.id != alert.id]
    etapas = " -> ".join(rule.sequence)
    return others, (
        f"Sequência de cadeia de ataque observada em {rule.window_minutes} minutos: "
        f"{etapas}."
    )


async def _match_target_asset(
    session: AsyncSession, alert: Alert, rule: CorrelationRule
) -> tuple[list[Alert], str] | None:
    """Detecções heterogéneas a convergir no mesmo activo."""
    if alert.asset_id is None:
        return None

    since = alert.last_event_at - timedelta(minutes=rule.window_minutes)
    result = await session.execute(
        select(Alert)
        .where(
            Alert.id != alert.id,
            Alert.asset_id == alert.asset_id,
            Alert.last_event_at >= since,
            Alert.status.in_([
                AlertStatus.NOVO, AlertStatus.EM_TRIAGEM,
                AlertStatus.CORRELACIONADO, AlertStatus.PROMOVIDO,
            ]),
        )
        .limit(200)
    )
    matches = [a for a in result.scalars() if _passes_conditions(a, rule.conditions)]

    # Exigimos regras *distintas*: várias ocorrências da mesma detecção são
    # repetição, não convergência de vectores.
    distinct_rules = {a.rule_id for a in matches if a.rule_id}
    distinct_rules.add(alert.rule_id)
    if len(distinct_rules) < rule.min_alerts:
        return None

    return matches, (
        f"{len(distinct_rules)} detecções distintas convergem no mesmo activo em "
        f"{rule.window_minutes} minutos."
    )


_STRATEGIES = {
    CorrelationStrategy.ENTIDADE_PARTILHADA: _match_shared_entity,
    CorrelationStrategy.LIMIAR: _match_threshold,
    CorrelationStrategy.SEQUENCIA_TEMPORAL: _match_sequence,
    CorrelationStrategy.ACTIVO_ALVO: _match_target_asset,
}


# --------------------------------------------------------------------- motor
async def correlate_alert(
    session: AsyncSession, alert: Alert
) -> CorrelationDecision:
    """Avalia as regras activas contra um alerta.

    A primeira regra que corresponder decide — as regras estão ordenadas por
    prioridade, e permitir que várias actuassem sobre o mesmo alerta
    produziria incidentes duplicados a partir da mesma actividade.
    """
    result = await session.execute(
        select(CorrelationRule)
        .where(CorrelationRule.is_enabled.is_(True))
        .order_by(CorrelationRule.priority.asc(), CorrelationRule.created_at.asc())
    )
    rules = list(result.scalars())

    for rule in rules:
        if not _passes_conditions(alert, rule.conditions):
            continue

        strategy = _STRATEGIES.get(rule.strategy)
        if strategy is None:
            continue

        outcome = await strategy(session, alert, rule)
        if outcome is None:
            continue

        matches, rationale = outcome

        # Se algum dos alertas correlacionados já pertence a um incidente
        # aberto, juntamo-nos a esse em vez de abrir um paralelo.
        existing_incident = await _find_linkable_incident(session, matches)

        severity = rule.resulting_severity or max(
            [alert.severity, *(a.severity for a in matches)],
            key=lambda s: s.rank,
        )

        rule.match_count += 1
        rule.last_matched_at = datetime.now(UTC)

        full_rationale = f"Regra '{rule.name}': {rationale}"

        if existing_incident is not None:
            return CorrelationDecision(
                outcome=CorrelationOutcome.LIGADO_A_INCIDENTE,
                rule=rule,
                incident_id=existing_incident,
                related_alert_ids=[a.id for a in matches],
                rationale=full_rationale,
                suggested_severity=severity,
            )

        return CorrelationDecision(
            outcome=CorrelationOutcome.NOVO_INCIDENTE,
            rule=rule,
            related_alert_ids=[a.id for a in matches],
            rationale=full_rationale,
            suggested_severity=severity,
        )

    return CorrelationDecision(
        outcome=CorrelationOutcome.SEM_CORRELACAO,
        rationale="Nenhuma regra de correlação correspondeu a este alerta.",
    )


async def _find_linkable_incident(
    session: AsyncSession, alerts: list[Alert]
) -> uuid.UUID | None:
    """Incidente aberto ao qual algum dos alertas já pertence."""
    incident_ids = [a.incident_id for a in alerts if a.incident_id is not None]
    if not incident_ids:
        return None

    result = await session.execute(
        select(Incident.id)
        .where(Incident.id.in_(incident_ids), Incident.status.in_(LINKABLE_STATUSES))
        .order_by(Incident.detected_at.asc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def find_related_incidents(
    session: AsyncSession, incident: Incident, *, days: int = 30, limit: int = 10
) -> list[tuple[Incident, list[str]]]:
    """Incidentes que partilham indicadores com este.

    Base da proposta de campanha (§20) e da navegação investigativa (§21).
    Devolve pares (incidente, artefactos em comum).
    """
    own = await session.execute(
        select(Ioc.id, Ioc.value).join(
            Observation, Observation.ioc_id == Ioc.id
        ).where(Observation.incident_id == incident.id)
    )
    own_iocs = dict(own.all())
    if not own_iocs:
        return []

    since = datetime.now(UTC) - timedelta(days=days)
    result = await session.execute(
        select(Incident, func.array_agg(Ioc.value))
        .join(Observation, Observation.incident_id == Incident.id)
        .join(Ioc, Ioc.id == Observation.ioc_id)
        .where(
            Incident.id != incident.id,
            Ioc.id.in_(list(own_iocs)),
            Incident.detected_at >= since,
        )
        .group_by(Incident.id)
        .order_by(func.count(Ioc.id).desc())
        .limit(limit)
    )
    return [(row[0], sorted(set(row[1]))) for row in result.all()]
