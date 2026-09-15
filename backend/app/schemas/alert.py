"""Esquemas de alertas e eventos."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.core.enums import (
    AlertStatus,
    Confidence,
    IncidentCategory,
    Severity,
)
from app.schemas.common import ApiInput, ApiModel, UserSummary
from app.schemas.incident import AssetSummary


# ------------------------------------------------------------------- entrada
class AlertTriage(ApiInput):
    """Decisão de triagem sobre um alerta."""

    status: AlertStatus
    note: str | None = Field(default=None, max_length=2000)
    duplicate_of_id: uuid.UUID | None = Field(
        default=None, description="Obrigatório ao marcar como DUPLICADO."
    )


class AlertPromote(ApiInput):
    """Promoção de um alerta a incidente (§6)."""

    title: str | None = Field(default=None, min_length=4, max_length=300)
    category: IncidentCategory | None = None
    severity: Severity | None = None
    confidence: Confidence = Confidence.MEDIA
    assignee_id: uuid.UUID | None = None
    rationale: str = Field(
        default="", max_length=2000,
        description="Justificação da promoção, registada na auditoria.",
    )


class AlertLink(ApiInput):
    """Ligação de um alerta a um incidente existente."""

    incident_id: uuid.UUID
    rationale: str = Field(default="", max_length=2000)


# -------------------------------------------------------------------- saída
class TriageFactor(ApiModel):
    pontos: int
    razao: str
    dados: dict = Field(default_factory=dict)


class AlertListItem(ApiModel):
    id: uuid.UUID
    reference: str
    title: str
    source_kind: str
    source_name: str
    severity: str
    status: str
    triage_score: int
    false_positive_score: int
    event_count: int
    first_event_at: datetime
    last_event_at: datetime
    rule_id: str | None = None
    rule_name: str | None = None
    incident_id: uuid.UUID | None = None
    correlation_outcome: str
    asset: AssetSummary | None = None
    is_demo_data: bool
    tags: list[str] = Field(default_factory=list)
    created_at: datetime


class AlertRead(AlertListItem):
    description: str
    dedup_key: str
    #: Decomposição da pontuação: cada factor com pontos e razão (§12).
    triage_factors: dict = Field(default_factory=dict)
    triage_rationale: str
    scored_at: datetime | None = None
    correlation_rationale: str | None = None
    correlated_at: datetime | None = None
    correlation_rule_id: uuid.UUID | None = None
    duplicate_of_id: uuid.UUID | None = None
    triaged_by: UserSummary | None = None
    triaged_at: datetime | None = None
    triage_note: str | None = None
    incident_reference: str | None = None
    transicoes_permitidas: list[str] = Field(default_factory=list)


class EventRead(ApiModel):
    id: uuid.UUID
    source_kind: str
    source_name: str
    source_event_id: str
    occurred_at: datetime
    received_at: datetime
    severity: str
    source_severity: str | None = None
    event_type: str
    description: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    host: str | None = None
    username: str | None = None
    process: str | None = None
    file_hash: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    rule_groups: list[str] = Field(default_factory=list)
    reported_techniques: list[str] = Field(default_factory=list)
    normalized_extra: dict = Field(default_factory=dict)
    alert_id: uuid.UUID | None = None
    created_at: datetime


class EventDetail(EventRead):
    """Inclui o payload original tal como a fonte o enviou.

    Serve de prova de origem: qualquer valor apresentado ao analista pode ser
    confrontado com o que foi de facto recebido (§4).
    """

    raw_payload: dict = Field(default_factory=dict)


class CorrelationRuleRead(ApiModel):
    id: uuid.UUID
    name: str
    description: str
    is_enabled: bool
    priority: int
    strategy: str
    window_minutes: int
    min_alerts: int
    match_fields: list[str] = Field(default_factory=list)
    conditions: dict = Field(default_factory=dict)
    sequence: list[str] = Field(default_factory=list)
    resulting_severity: str | None = None
    resulting_category: str | None = None
    incident_title_template: str
    #: Estatísticas reais de utilização, base do §36.
    match_count: int
    false_positive_count: int
    last_matched_at: datetime | None = None
    created_at: datetime


class CorrelationRuleWrite(ApiInput):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=4000)
    is_enabled: bool = True
    priority: int = Field(default=100, ge=1, le=1000)
    strategy: str
    window_minutes: int = Field(default=60, ge=1, le=10080)
    min_alerts: int = Field(default=2, ge=1, le=10000)
    match_fields: list[str] = Field(default_factory=list)
    conditions: dict = Field(default_factory=dict)
    sequence: list[str] = Field(default_factory=list)
    resulting_severity: Severity | None = None
    resulting_category: IncidentCategory | None = None
    incident_title_template: str = Field(
        default="Actividade correlacionada", max_length=300
    )
