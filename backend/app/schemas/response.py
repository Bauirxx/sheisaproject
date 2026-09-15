"""Esquemas de playbooks, acções, aprovações e recomendações."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.core.enums import (
    ActionKind,
    ActionRiskLevel,
    IncidentCategory,
    PlaybookStepType,
    Severity,
)
from app.schemas.common import ApiInput, ApiModel, UserSummary


# -------------------------------------------------------------------- acções
class ActionPropose(ApiInput):
    incident_id: uuid.UUID
    action_kind: ActionKind
    title: str = Field(min_length=3, max_length=250)
    rationale: str = Field(
        min_length=5, max_length=4000,
        description="Obrigatória: uma acção sem justificação não é aprovável.",
    )
    target: dict = Field(
        default_factory=dict,
        description='Alvo normalizado, ex.: {"ip": "203.0.113.9"}.',
    )
    parameters: dict = Field(default_factory=dict)
    risk_level: ActionRiskLevel | None = Field(
        default=None,
        description=(
            "Pode elevar o risco por omissão do tipo de acção, nunca baixá-lo."
        ),
    )


class ApprovalDecide(ApiInput):
    approved: bool
    justification: str | None = Field(
        default=None, max_length=4000,
        description="Obrigatória para acções de risco crítico.",
    )


class ActionRevert(ApiInput):
    rationale: str = Field(min_length=5, max_length=4000)


class ApprovalRead(ApiModel):
    id: uuid.UUID
    decision: str
    required_permission: str
    requested_at: datetime
    decided_at: datetime | None = None
    decided_by: UserSummary | None = None
    justification: str | None = None
    expires_at: datetime | None = None


class ActionRead(ApiModel):
    id: uuid.UUID
    reference: str
    incident_id: uuid.UUID
    action_kind: str
    risk_level: str
    status: str
    title: str
    rationale: str
    target: dict = Field(default_factory=dict)
    parameters: dict = Field(default_factory=dict)
    integration_id: uuid.UUID | None = None
    proposed_by_engine: bool
    recommendation_id: uuid.UUID | None = None
    playbook_execution_id: uuid.UUID | None = None
    executed_at: datetime | None = None
    #: Resposta efectiva do sistema alvo. Vazio significa que nada correu.
    result: dict = Field(default_factory=dict)
    error: str | None = None
    is_reversible: bool
    reverted_at: datetime | None = None
    approvals: list[ApprovalRead] = Field(default_factory=list)
    created_at: datetime
    #: Indica se existe alguma integração activa capaz de a executar (§4).
    executavel: bool = True
    motivo_nao_executavel: str | None = None


# ----------------------------------------------------------------- playbooks
class PlaybookStepWrite(ApiInput):
    ordering: int = Field(ge=1, le=100)
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=4000)
    step_type: PlaybookStepType
    parameters: dict = Field(default_factory=dict)
    action_kind: ActionKind | None = None
    risk_level: ActionRiskLevel = ActionRiskLevel.BAIXO
    requires_approval: bool = False
    abort_on_failure: bool = True
    timeout_seconds: int = Field(default=120, ge=5, le=3600)
    is_enabled: bool = True


class PlaybookWrite(ApiInput):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=8000)
    is_enabled: bool = True
    trigger_category: IncidentCategory | None = None
    trigger_min_severity: Severity = Severity.BAIXA
    trigger_conditions: dict = Field(default_factory=dict)
    auto_execute: bool = Field(
        default=False,
        description=(
            "Execução automática ao satisfazer as condições. Por omissão "
            "desligada: automação silenciosa é um risco, não uma comodidade."
        ),
    )
    success_criteria: str = Field(default="", max_length=4000)
    rollback_criteria: str = Field(default="", max_length=4000)
    closing_status: str | None = None
    steps: list[PlaybookStepWrite] = Field(default_factory=list)


class PlaybookStepRead(ApiModel):
    id: uuid.UUID
    ordering: int
    name: str
    description: str
    step_type: str
    parameters: dict = Field(default_factory=dict)
    action_kind: str | None = None
    risk_level: str
    requires_approval: bool
    abort_on_failure: bool
    timeout_seconds: int
    is_enabled: bool


class PlaybookRead(ApiModel):
    id: uuid.UUID
    name: str
    description: str
    version: int
    is_enabled: bool
    trigger_category: str | None = None
    trigger_min_severity: str
    trigger_conditions: dict = Field(default_factory=dict)
    auto_execute: bool
    success_criteria: str
    rollback_criteria: str
    closing_status: str | None = None
    execution_count: int
    success_count: int
    last_executed_at: datetime | None = None
    steps: list[PlaybookStepRead] = Field(default_factory=list)
    created_at: datetime


class PlaybookSuggestion(ApiModel):
    playbook: PlaybookRead
    #: Porque é que este playbook está a ser proposto para este incidente.
    motivo: str


class PlaybookStepExecutionRead(ApiModel):
    id: uuid.UUID
    ordering: int
    step_name: str
    step_type: str
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output: dict = Field(default_factory=dict)
    error: str | None = None
    action_id: uuid.UUID | None = None


class PlaybookExecutionRead(ApiModel):
    id: uuid.UUID
    reference: str
    playbook_id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    playbook_version: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    triggered_automatically: bool
    context: dict = Field(default_factory=dict)
    result_summary: str
    error: str | None = None
    step_executions: list[PlaybookStepExecutionRead] = Field(default_factory=list)
    created_at: datetime


class PlaybookRun(ApiInput):
    incident_id: uuid.UUID


# ------------------------------------------------------------ recomendações
class RecommendationRead(ApiModel):
    id: uuid.UUID
    kind: str
    status: str
    target_type: str
    target_id: uuid.UUID
    title: str
    summary: str
    #: Porque é que o motor chegou a esta conclusão.
    explanation: str
    confidence: int
    #: Contributo de cada critério para a confiança.
    factors: dict = Field(default_factory=dict)
    #: Registos concretos consultados.
    evidence_refs: dict = Field(default_factory=dict)
    proposed_change: dict = Field(default_factory=dict)
    engine: str
    engine_version: str
    decided_at: datetime | None = None
    decided_by: UserSummary | None = None
    decision_note: str | None = None
    applied: bool
    created_at: datetime


class RecommendationDecide(ApiInput):
    accept: bool
    note: str | None = Field(default=None, max_length=2000)
    aplicar_alteracao: bool = Field(
        default=True,
        description=(
            "Se aceitar, aplica a alteração proposta ao alvo. Desligue para "
            "registar a concordância sem alterar nada."
        ),
    )
