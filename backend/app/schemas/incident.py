"""Esquemas de incidentes, investigação e artefactos associados."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field, field_validator

from app.core.enums import (
    Confidence,
    IncidentCategory,
    IncidentStatus,
    ObservationRole,
    Priority,
    RelationType,
    Severity,
    TaskStatus,
)
from app.schemas.common import ApiInput, ApiModel, UserSummary


# ------------------------------------------------------------------- entrada
class IncidentCreate(ApiInput):
    title: str = Field(min_length=4, max_length=300)
    description: str = Field(default="", max_length=20000)
    category: IncidentCategory = IncidentCategory.OUTRO
    subtype: str | None = Field(default=None, max_length=80)
    severity: Severity = Severity.MEDIA
    priority: Priority | None = None
    confidence: Confidence = Confidence.MEDIA
    detected_at: datetime | None = Field(
        default=None,
        description="Instante da ocorrência. Por omissão, o instante do registo.",
    )
    assignee_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    asset_ids: list[uuid.UUID] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("detected_at")
    @classmethod
    def _not_in_future(cls, v: datetime | None) -> datetime | None:
        if v is not None:
            from datetime import UTC, timedelta

            # Tolerância de 5 minutos para desvios de relógio entre sistemas.
            if v > datetime.now(UTC) + timedelta(minutes=5):
                raise ValueError("A data de detecção não pode estar no futuro.")
        return v


class IncidentUpdate(ApiInput):
    title: str | None = Field(default=None, min_length=4, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    category: IncidentCategory | None = None
    subtype: str | None = Field(default=None, max_length=80)
    severity: Severity | None = None
    priority: Priority | None = None
    confidence: Confidence | None = None
    affected_users: list[str] | None = None
    tags: list[str] | None = None
    lessons_learned: str | None = Field(default=None, max_length=20000)


class IncidentTransition(ApiInput):
    status: IncidentStatus
    note: str | None = Field(default=None, max_length=2000)
    resolution_summary: str | None = Field(
        default=None, max_length=20000,
        description="Obrigatório ao passar para RESOLVIDO.",
    )
    false_positive_reason: str | None = Field(
        default=None, max_length=2000,
        description="Obrigatório ao marcar como FALSO_POSITIVO.",
    )
    team_id: uuid.UUID | None = Field(
        default=None,
        description="Só com ESCALADO: a equipa para que se escala. Os membros "
        "activos são avisados na plataforma e por email.",
    )
    assignee_id: uuid.UUID | None = Field(
        default=None,
        description="Só com ESCALADO: a pessoa que passa a ser responsável.",
    )


class IncidentAssign(ApiInput):
    """Campos ausentes ficam como estão; enviados a `null` são retirados."""

    assignee_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None


class IncidentRelate(ApiInput):
    target_incident_id: uuid.UUID
    relation_type: RelationType
    rationale: str = Field(default="", max_length=2000)
    confidence: Confidence = Confidence.MEDIA


class CommentCreate(ApiInput):
    body: str = Field(min_length=1, max_length=20000)
    is_internal: bool = False


class TaskCreate(ApiInput):
    title: str = Field(min_length=3, max_length=250)
    description: str = Field(default="", max_length=10000)
    priority: Priority = Priority.P3
    assignee_id: uuid.UUID | None = None
    due_at: datetime | None = None
    depends_on_ids: list[uuid.UUID] = Field(default_factory=list)


class TaskUpdate(ApiInput):
    title: str | None = Field(default=None, min_length=3, max_length=250)
    description: str | None = Field(default=None, max_length=10000)
    status: TaskStatus | None = None
    priority: Priority | None = None
    assignee_id: uuid.UUID | None = None
    due_at: datetime | None = None
    outcome: str | None = Field(default=None, max_length=10000)


class ObservationCreate(ApiInput):
    ioc_id: uuid.UUID
    role: ObservationRole = ObservationRole.RELACIONADO
    observed_at: datetime | None = None
    context: str = Field(default="", max_length=2000)
    confidence: Confidence = Confidence.MEDIA
    asset_id: uuid.UUID | None = None


class TechniqueAssign(ApiInput):
    technique_id: str = Field(
        max_length=20, description="Identificador ATT&CK, ex.: T1110 ou T1078.004."
    )
    confidence: Confidence = Confidence.MEDIA
    rationale: str = Field(default="", max_length=2000)


# -------------------------------------------------------------------- saída
class AssetSummary(ApiModel):
    id: uuid.UUID
    identifier: str
    name: str
    criticality: str
    hostname: str | None = None
    ip_address: str | None = None


class IocSummary(ApiModel):
    id: uuid.UUID
    ioc_type: str
    value: str
    reputation: str
    risk_score: int
    is_allowlisted: bool


class TechniqueSummary(ApiModel):
    technique_id: str
    name: str
    url: str | None = None
    is_subtechnique: bool
    tactic_shortnames: list[str] = Field(default_factory=list)


class IncidentTechniqueRead(ApiModel):
    id: uuid.UUID
    technique: TechniqueSummary
    #: `False` significa hipótese do motor; `True`, facto afirmado (§11).
    is_asserted: bool
    confidence: str
    rationale: str
    evidence_refs: dict = Field(default_factory=dict)
    created_at: datetime


class CommentRead(ApiModel):
    id: uuid.UUID
    body: str
    is_internal: bool
    is_system: bool
    author: UserSummary | None = None
    created_at: datetime
    edited_at: datetime | None = None


class TaskRead(ApiModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    title: str
    description: str
    status: str
    priority: str
    ordering: int
    assignee: UserSummary | None = None
    due_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: str | None = None
    created_at: datetime


class EvidenceRead(ApiModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    name: str
    description: str
    evidence_type: str
    original_filename: str
    content_type: str
    size_bytes: int
    sha256: str
    md5: str | None = None
    integrity_verified_at: datetime | None = None
    integrity_ok: bool | None = None
    source: str
    collected_at: datetime | None = None
    uploaded_by: UserSummary | None = None
    created_at: datetime


class ObservationRead(ApiModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    ioc: IocSummary
    alert_id: uuid.UUID | None = None
    asset: AssetSummary | None = None
    role: str
    observed_at: datetime
    context: str
    confidence: str
    is_automatic: bool


class IncidentRelationRead(ApiModel):
    id: uuid.UUID
    relation_type: str
    rationale: str
    created_by_engine: bool
    confidence: str
    created_at: datetime
    #: Incidente do outro lado da aresta, na perspectiva de quem consulta.
    incident_id: uuid.UUID
    incident_reference: str
    incident_title: str
    incident_status: str
    direction: str = Field(description="'saida' ou 'entrada'.")


class IncidentListItem(ApiModel):
    """Versão compacta para listagens densas."""

    id: uuid.UUID
    reference: str
    title: str
    category: str
    severity: str
    priority: str
    status: str
    origin: str
    source_kind: str
    risk_score: int
    assignee: UserSummary | None = None
    detected_at: datetime
    due_at: datetime | None = None
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    is_demo_data: bool
    tags: list[str] = Field(default_factory=list)


class IncidentMetrics(ApiModel):
    """Métricas de resposta calculadas a partir dos marcos temporais."""

    tempo_ate_reconhecimento_segundos: int | None = None
    tempo_ate_contencao_segundos: int | None = None
    tempo_ate_resolucao_segundos: int | None = None
    dentro_do_prazo: bool | None = None
    alertas_associados: int = 0
    observacoes: int = 0
    evidencias: int = 0
    tarefas_totais: int = 0
    tarefas_concluidas: int = 0
    accoes_executadas: int = 0


class EquipaResumo(ApiModel):
    id: uuid.UUID
    name: str
    is_active: bool


class IncidentRead(IncidentListItem):
    """Detalhe completo do incidente."""

    description: str
    subtype: str | None = None
    confidence: str
    source_detail: str | None = None
    team_id: uuid.UUID | None = None
    #: A equipa com nome: com só o identificador, a interface não tinha como
    #: mostrar a que grupo o incidente está entregue.
    team: EquipaResumo | None = None
    reporter: UserSummary | None = None
    campaign_id: uuid.UUID | None = None

    acknowledged_at: datetime | None = None
    contained_at: datetime | None = None
    eradicated_at: datetime | None = None
    closed_at: datetime | None = None

    resolution_summary: str | None = None
    lessons_learned: str | None = None
    false_positive_reason: str | None = None

    affected_users: list[str] = Field(default_factory=list)
    risk_factors: dict = Field(default_factory=dict)
    assets: list[AssetSummary] = Field(default_factory=list)
    techniques: list[IncidentTechniqueRead] = Field(default_factory=list)

    #: Transições permitidas a partir do estado actual. Permite ao frontend
    #: apresentar apenas o que é de facto possível, sem duplicar as regras.
    transicoes_permitidas: list[str] = Field(default_factory=list)
    metricas: IncidentMetrics | None = None


class IncidentTimelineEntry(ApiModel):
    """Entrada da linha temporal unificada do incidente.

    Agrega auditoria, comentários, alertas, acções e evidências numa só
    sequência — é o que permite reconstruir o incidente (§31).
    """

    instante: datetime
    tipo: str = Field(description="auditoria | comentario | alerta | accao | evidencia | tarefa")
    titulo: str
    detalhe: str = ""
    autor: str | None = None
    referencia: str | None = None
    recurso_id: uuid.UUID | None = None
    dados: dict = Field(default_factory=dict)
