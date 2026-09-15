"""Incidente e as suas relações (§7, §20).

Nota sobre histórico: não existe uma tabela `incident_history` dedicada. O
registo de auditoria (§16) é a fonte única de "quem fez o quê e quando", com
valor anterior e novo — duplicá-lo criaria duas versões da verdade que podem
divergir. O incidente guarda apenas os **marcos temporais** (detecção,
reconhecimento, contenção, resolução, encerramento), porque esses são
necessários para calcular métricas de resposta com uma única leitura em vez de
reconstruir a linha temporal a partir da auditoria a cada consulta do painel.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    Confidence,
    IncidentCategory,
    IncidentOrigin,
    IncidentStatus,
    Priority,
    RelationType,
    Severity,
    SourceKind,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk

#: Activos afectados por um incidente. Junção pura.
incident_assets = Table(
    "incident_assets",
    Base.metadata,
    Column(
        "incident_id",
        PGUUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "asset_id",
        PGUUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_assignee_status", "assignee_id", "status"),
        Index("ix_incidents_open_priority", "status", "priority", "detected_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Identificador legível (INC-000125), gerado por sequência da base de dados.
    reference: Mapped[str] = mapped_column(String(24), nullable=False, unique=True, index=True)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # --- classificação ---
    category: Mapped[IncidentCategory] = mapped_column(
        enum_column(IncidentCategory), nullable=False,
        default=IncidentCategory.OUTRO, index=True,
    )
    #: Subtipo livre dentro da categoria (ex.: "ransomware", "forca-bruta-ssh").
    subtype: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity), nullable=False, default=Severity.MEDIA, index=True
    )
    priority: Mapped[Priority] = mapped_column(
        enum_column(Priority), nullable=False, default=Priority.P3, index=True
    )
    status: Mapped[IncidentStatus] = mapped_column(
        enum_column(IncidentStatus), nullable=False, default=IncidentStatus.NOVO, index=True
    )
    #: Confiança de que se trata de facto de um incidente real.
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence), nullable=False, default=Confidence.MEDIA
    )

    # --- proveniência ---
    origin: Mapped[IncidentOrigin] = mapped_column(
        enum_column(IncidentOrigin), nullable=False,
        default=IncidentOrigin.REGISTO_MANUAL, index=True,
    )
    source_kind: Mapped[SourceKind] = mapped_column(
        enum_column(SourceKind), nullable=False, default=SourceKind.MANUAL, index=True
    )
    source_detail: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # --- responsabilidade ---
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), nullable=True
    )
    reporter_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )

    # --- marcos temporais: base real das métricas de resposta (§17) ---
    #: Quando a actividade ocorreu/foi detectada pela ferramenta de origem.
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    #: Primeira interacção humana. Define o tempo médio de reconhecimento (MTTA).
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    eradicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Define o tempo médio de resolução (MTTR).
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Prazo derivado da severidade no momento da criação.
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- desfecho ---
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Registo do §36 ("APRENDER"): o que este incidente ensinou.
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Preenchido quando o estado passa a FALSO_POSITIVO. Alimenta o detector
    #: de falsos positivos, que aprende com decisões reais e não com suposições.
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Utilizadores afectados, quando aplicável (§7). Lista de identificadores
    #: de conta; não são utilizadores da plataforma, mas sujeitos do incidente.
    affected_users: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    #: Pontuação de risco 0-100, com a decomposição por factor que a justifica.
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    risk_factors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    is_demo_data: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    # --- relações ---
    assignee: Mapped["User | None"] = relationship(
        foreign_keys=[assignee_id], lazy="selectin"
    )
    reporter: Mapped["User | None"] = relationship(
        foreign_keys=[reporter_id], lazy="selectin"
    )
    team: Mapped["Team | None"] = relationship(lazy="selectin")
    campaign: Mapped["Campaign | None"] = relationship(
        back_populates="incidents", lazy="selectin"
    )
    assets: Mapped[list["Asset"]] = relationship(
        secondary=incident_assets, lazy="selectin"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="incident", lazy="noload",
        foreign_keys="Alert.incident_id",
    )
    comments: Mapped[list["Comment"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    tasks: Mapped[list["Task"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    techniques: Mapped[list["IncidentTechnique"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )

    @property
    def is_open(self) -> bool:
        from app.core.enums import INCIDENT_ACTIVE_STATUSES

        return self.status in INCIDENT_ACTIVE_STATUSES

    @property
    def time_to_acknowledge_seconds(self) -> int | None:
        if self.acknowledged_at is None:
            return None
        return int((self.acknowledged_at - self.detected_at).total_seconds())

    @property
    def time_to_resolve_seconds(self) -> int | None:
        if self.resolved_at is None:
            return None
        return int((self.resolved_at - self.detected_at).total_seconds())

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Incident {self.reference} {self.status}>"


class IncidentRelation(Base, TimestampMixin):
    """Aresta tipada e direccionada entre dois incidentes (§20).

    Ao contrário do merge do RTIR — irreversível e destrutivo — relacionar
    preserva ambos os incidentes e o motivo da ligação. Um duplicado continua a
    existir, consultável, com o seu histórico intacto.
    """

    __tablename__ = "incident_relations"
    __table_args__ = (
        UniqueConstraint(
            "source_incident_id", "target_incident_id", "relation_type",
            name="uq_incident_relations_edge",
        ),
        Index("ix_incident_relations_target", "target_incident_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    source_incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    target_incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    relation_type: Mapped[RelationType] = mapped_column(
        enum_column(RelationType), nullable=False
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Distingue uma ligação afirmada por um analista de uma proposta pelo motor.
    created_by_engine: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence), nullable=False, default=Confidence.MEDIA
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    source_incident: Mapped[Incident] = relationship(
        foreign_keys=[source_incident_id], lazy="selectin"
    )
    target_incident: Mapped[Incident] = relationship(
        foreign_keys=[target_incident_id], lazy="selectin"
    )


class IncidentTechnique(Base, TimestampMixin):
    """Associação incidente <-> técnica MITRE ATT&CK (§11).

    Guarda explicitamente se a associação foi **afirmada** (por um analista, ou
    reportada pela própria fonte de detecção) ou **inferida** pelo motor. O §11
    é claro: nunca assumir que uma técnica ocorreu. Uma inferência transporta
    sempre a sua justificação e o seu grau de confiança.
    """

    __tablename__ = "incident_techniques"
    __table_args__ = (
        UniqueConstraint("incident_id", "technique_id", name="uq_incident_techniques"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    technique_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), nullable=False
    )

    #: False => hipótese do motor. True => facto afirmado por humano ou fonte.
    is_asserted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence), nullable=False, default=Confidence.BAIXA
    )
    #: Porquê. Obrigatório para inferências: sem justificação, a associação não
    #: é defensável perante um auditor.
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Que dados sustentam a inferência (ids de alertas, grupos de regras, ...).
    evidence_refs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped[Incident] = relationship(back_populates="techniques", lazy="noload")
    technique: Mapped["MitreTechnique"] = relationship(lazy="selectin")
