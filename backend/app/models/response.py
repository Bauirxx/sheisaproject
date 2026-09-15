"""Automação controlada: playbooks, acções e aprovações (§13, §14).

A cadeia `IA → RECOMENDAÇÃO → ANALISTA → APROVAÇÃO → EXECUÇÃO` do §13 é
modelada com entidades reais e não como um campo booleano. `Action` é uma
entidade de primeira classe com ciclo de vida próprio: uma acção proposta que
nunca foi aprovada continua registada, com quem a propôs e porque não avançou.
É esta persistência que torna a decisão auditável.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    ActionKind,
    ActionRiskLevel,
    ActionStatus,
    ApprovalDecision,
    IncidentCategory,
    PlaybookExecutionStatus,
    PlaybookStepType,
    Severity,
    TaskStatus,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk


class Playbook(Base, TimestampMixin):
    """Procedimento de resposta reutilizável."""

    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    # --- condições de activação (§14) ---
    #: Categoria a que se aplica. Nulo => qualquer categoria.
    trigger_category: Mapped[IncidentCategory | None] = mapped_column(
        enum_column(IncidentCategory), nullable=True, index=True
    )
    #: Severidade mínima do incidente para o playbook ser sugerido.
    trigger_min_severity: Mapped[Severity] = mapped_column(
        enum_column(Severity), nullable=False, default=Severity.BAIXA
    )
    #: Condições adicionais avaliadas contra o incidente e as suas observações.
    #: Ex.: {"requires_ioc_types": ["IP"], "asset_criticality_min": "ALTA"}
    trigger_conditions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Execução automática ao satisfazer as condições, ou apenas sugestão.
    #: O valor por omissão é `False` deliberadamente: automação silenciosa numa
    #: plataforma de segurança é um risco, não uma funcionalidade.
    auto_execute: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Critérios que definem sucesso e condições de reversão (§14).
    success_criteria: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rollback_criteria: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Transição de estado a aplicar ao incidente quando o playbook termina bem.
    closing_status: Mapped[str | None] = mapped_column(String(40), nullable=True)

    execution_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    steps: Mapped[list["PlaybookStep"]] = relationship(
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="PlaybookStep.ordering",
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Playbook {self.name} v{self.version}>"


class PlaybookStep(Base, TimestampMixin):
    """Passo declarativo de um playbook."""

    __tablename__ = "playbook_steps"
    __table_args__ = (
        UniqueConstraint("playbook_id", "ordering", name="uq_playbook_steps_order"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    playbook_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False
    )
    ordering: Mapped[int] = mapped_column(Integer, nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    step_type: Mapped[PlaybookStepType] = mapped_column(
        enum_column(PlaybookStepType), nullable=False
    )
    #: Parâmetros do passo, interpretados pelo executor correspondente.
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Para passos EXECUTAR_ACCAO: que acção e com que risco.
    action_kind: Mapped[ActionKind | None] = mapped_column(
        enum_column(ActionKind), nullable=True
    )
    risk_level: Mapped[ActionRiskLevel] = mapped_column(
        enum_column(ActionRiskLevel), nullable=False, default=ActionRiskLevel.BAIXO
    )
    #: Sobrepõe-se ao regime derivado do risco quando é preciso exigir mais.
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Se `True`, uma falha neste passo interrompe a execução do playbook.
    abort_on_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    playbook: Mapped[Playbook] = relationship(back_populates="steps", lazy="noload")


class PlaybookExecution(Base, TimestampMixin):
    """Uma execução concreta de um playbook sobre um incidente."""

    __tablename__ = "playbook_executions"
    __table_args__ = (
        Index("ix_playbook_executions_incident", "incident_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    reference: Mapped[str] = mapped_column(String(24), nullable=False, unique=True, index=True)

    playbook_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="RESTRICT"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    status: Mapped[PlaybookExecutionStatus] = mapped_column(
        enum_column(PlaybookExecutionStatus), nullable=False,
        default=PlaybookExecutionStatus.PENDENTE, index=True,
    )
    #: Versão do playbook no momento da execução. Um playbook alterado depois
    #: não reescreve o que foi de facto executado.
    playbook_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    triggered_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: True quando disparado pelo motor e não por um utilizador.
    triggered_automatically: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    #: Contexto de entrada (IOCs, activos) e resultado consolidado.
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    result_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    playbook: Mapped[Playbook] = relationship(lazy="selectin")
    step_executions: Mapped[list["PlaybookStepExecution"]] = relationship(
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="PlaybookStepExecution.ordering",
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<PlaybookExecution {self.reference} {self.status}>"


class PlaybookStepExecution(Base, TimestampMixin):
    """Resultado de um passo dentro de uma execução."""

    __tablename__ = "playbook_step_executions"

    id: Mapped[uuid.UUID] = uuid_pk()
    execution_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbook_executions.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    step_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbook_steps.id", ondelete="SET NULL"), nullable=True
    )
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Nome e tipo copiados no momento da execução: se o passo for editado ou
    #: removido depois, o registo do que correu mantém-se legível.
    step_name: Mapped[str] = mapped_column(String(200), nullable=False)
    step_type: Mapped[PlaybookStepType] = mapped_column(
        enum_column(PlaybookStepType), nullable=False
    )

    status: Mapped[TaskStatus] = mapped_column(
        enum_column(TaskStatus), nullable=False, default=TaskStatus.PENDENTE
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    output: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Acção gerada por este passo, se aplicável.
    action_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("actions.id", ondelete="SET NULL"), nullable=True
    )

    execution: Mapped[PlaybookExecution] = relationship(
        back_populates="step_executions", lazy="noload"
    )


class Action(Base, TimestampMixin):
    """Acção de resposta: proposta, aprovada, executada e registada.

    O nível de risco determina o regime de aprovação (§13):

    * `BAIXO`    — executa sem aprovação, mas fica registada.
    * `MODERADO` — exige `actions:approve`.
    * `CRITICO`  — exige `actions:approve_critical` e justificação escrita.
    """

    __tablename__ = "actions"
    __table_args__ = (
        Index("ix_actions_status_risk", "status", "risk_level"),
        Index("ix_actions_incident", "incident_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    reference: Mapped[str] = mapped_column(String(24), nullable=False, unique=True, index=True)

    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    action_kind: Mapped[ActionKind] = mapped_column(
        enum_column(ActionKind), nullable=False, index=True
    )
    risk_level: Mapped[ActionRiskLevel] = mapped_column(
        enum_column(ActionRiskLevel), nullable=False, default=ActionRiskLevel.MODERADO
    )
    status: Mapped[ActionStatus] = mapped_column(
        enum_column(ActionStatus), nullable=False, default=ActionStatus.PROPOSTA, index=True
    )

    title: Mapped[str] = mapped_column(String(250), nullable=False)
    #: Porque foi proposta. Obrigatório: uma acção sem justificação não é
    #: aprovável.
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Alvo da acção, em forma normalizada (ex.: {"ip": "203.0.113.9"}).
    target: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    #: Integração através da qual a acção será executada. Sem integração activa
    #: a acção não é executável e o sistema di-lo explicitamente (§4).
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL"), nullable=True
    )

    proposed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: True quando proposta pelo motor de inteligência ou por um playbook.
    proposed_by_engine: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recommendation_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("recommendations.id", ondelete="SET NULL"), nullable=True
    )
    playbook_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbook_executions.id", ondelete="SET NULL"),
        nullable=True,
    )

    # --- execução ---
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: Resposta efectiva do sistema alvo. Vazio significa que nada correu —
    #: nunca é preenchido com um sucesso presumido.
    result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- reversão ---
    is_reversible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reverted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Acção que reverteu esta (ex.: DESBLOQUEAR_IP reverte BLOQUEAR_IP).
    reverted_by_action_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("actions.id", ondelete="SET NULL"), nullable=True
    )

    approvals: Mapped[list["ActionApproval"]] = relationship(
        back_populates="action", cascade="all, delete-orphan", lazy="selectin"
    )
    #: Quem propôs. Exposto na API porque a separação de funções (§13) compara
    #: o proponente com o decisor: sem este dado, a interface não consegue
    #: explicar a quem está a ver a fila porque é que não pode aprovar uma
    #: acção — só o descobriria ao levar 403.
    proposed_by: Mapped["User | None"] = relationship(
        foreign_keys=[proposed_by_id], lazy="selectin"
    )

    @property
    def requires_approval(self) -> bool:
        return self.risk_level in (ActionRiskLevel.MODERADO, ActionRiskLevel.CRITICO)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Action {self.reference} {self.action_kind} {self.status}>"


class ActionApproval(Base, TimestampMixin):
    """Decisão humana sobre uma acção (§13).

    Registada como entidade própria — e não como colunas na acção — porque a
    decisão tem autor, instante, justificação e permissão exigida. Uma rejeição
    é tão importante como uma aprovação e ambas têm de sobreviver no registo.
    """

    __tablename__ = "action_approvals"
    __table_args__ = (
        Index("ix_action_approvals_pending", "decision", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    action_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("actions.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    decision: Mapped[ApprovalDecision] = mapped_column(
        enum_column(ApprovalDecision), nullable=False,
        default=ApprovalDecision.PENDENTE, index=True,
    )
    #: Permissão que foi exigida para decidir. Guardada no momento do pedido,
    #: para que uma alteração posterior de política não reescreva a história.
    required_permission: Mapped[str] = mapped_column(String(64), nullable=False)

    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Prazo após o qual o pedido caduca sem decisão.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    action: Mapped[Action] = relationship(back_populates="approvals", lazy="noload")
    decided_by: Mapped["User | None"] = relationship(lazy="selectin")
