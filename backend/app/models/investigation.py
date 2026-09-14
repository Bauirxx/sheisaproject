"""Artefactos da investigação: observações, comentários, tarefas e evidências.

`Observation` é a peça central do grafo investigativo (§20, §21). É o
*avistamento*: este indicador, neste incidente, neste papel, neste instante,
suportado por este alerta. As arestas do grafo derivam daqui — não de campos
soltos espalhados pelo incidente.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
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
    EvidenceType,
    ObservationRole,
    Priority,
    TaskStatus,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk

#: Dependências entre tarefas (§19). Auto-referência muitos-para-muitos: uma
#: tarefa pode depender de várias e bloquear várias.
task_dependencies = Table(
    "task_dependencies",
    Base.metadata,
    Column(
        "task_id",
        PGUUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "depends_on_id",
        PGUUID(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Observation(Base, TimestampMixin):
    """Avistamento de um artefacto no contexto de um incidente.

    Separar isto do IOC resolve uma ambiguidade real do TheHive: lá, um
    "observable" mistura "foi visto aqui" com "é malicioso". Aqui o IOC carrega
    a reputação (facto global) e a Observação carrega o contexto (facto local).
    """

    __tablename__ = "observations"
    __table_args__ = (
        # Um mesmo indicador pode ser observado em papéis diferentes no mesmo
        # incidente (origem numa fase, destino noutra), mas não repetido no
        # mesmo papel pelo mesmo alerta.
        UniqueConstraint(
            "incident_id", "ioc_id", "role", "alert_id", name="uq_observations_sighting"
        ),
        Index("ix_observations_ioc_time", "ioc_id", "observed_at"),
        Index("ix_observations_incident", "incident_id", "role"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    #: Alerta que originou o avistamento. Nulo se registado manualmente.
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    #: Activo onde o artefacto foi observado, quando determinável.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )

    role: Mapped[ObservationRole] = mapped_column(
        enum_column(ObservationRole), nullable=False, default=ObservationRole.RELACIONADO
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence), nullable=False, default=Confidence.MEDIA
    )
    #: Extraído automaticamente da normalização, ou afirmado por um analista.
    is_automatic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped["Incident"] = relationship(  # noqa: F821
        back_populates="observations", lazy="noload"
    )
    ioc: Mapped["Ioc"] = relationship(lazy="selectin")  # noqa: F821
    asset: Mapped["Asset | None"] = relationship(lazy="selectin")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Observation {self.role} ioc={self.ioc_id}>"


class Comment(Base, TimestampMixin):
    """Nota de investigação num incidente."""

    __tablename__ = "comments"
    __table_args__ = (
        Index("ix_comments_incident_created", "incident_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)

    #: Nota interna: não sai em relatórios destinados a terceiros.
    is_internal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Comentário gerado pelo sistema (execução de playbook, resultado de acção).
    #: Distinguir origem humana de origem automática é essencial num registo
    #: que se pretende probatório.
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    edited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    incident: Mapped["Incident"] = relationship(  # noqa: F821
        back_populates="comments", lazy="noload"
    )
    author: Mapped["User | None"] = relationship(lazy="selectin")  # noqa: F821


class Task(Base, TimestampMixin):
    """Tarefa de investigação ou resposta (§19)."""

    __tablename__ = "tasks"
    __table_args__ = (
        Index("ix_tasks_assignee_status", "assignee_id", "status"),
        Index("ix_tasks_incident_order", "incident_id", "ordering"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    title: Mapped[str] = mapped_column(String(250), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[TaskStatus] = mapped_column(
        enum_column(TaskStatus), nullable=False, default=TaskStatus.PENDENTE, index=True
    )
    priority: Mapped[Priority] = mapped_column(
        enum_column(Priority), nullable=False, default=Priority.P3
    )
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Resultado da tarefa. Uma tarefa concluída sem resultado registado não
    #: contribui para a reconstituição do incidente no relatório final.
    outcome: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Preenchido quando a tarefa foi criada por um passo de playbook.
    playbook_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbook_executions.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped["Incident"] = relationship(  # noqa: F821
        back_populates="tasks", lazy="noload"
    )
    assignee: Mapped["User | None"] = relationship(  # noqa: F821
        foreign_keys=[assignee_id], lazy="selectin"
    )
    depends_on: Mapped[list["Task"]] = relationship(
        secondary=task_dependencies,
        primaryjoin=lambda: Task.id == task_dependencies.c.task_id,
        secondaryjoin=lambda: Task.id == task_dependencies.c.depends_on_id,
        backref="blocks",
        lazy="selectin",
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Task {self.title[:30]} {self.status}>"


class Evidence(Base, TimestampMixin):
    """Evidência associada a um incidente (§15).

    Integridade: `sha256` é calculado sobre os bytes recebidos no momento do
    carregamento e nunca recalculado a partir do ficheiro em disco durante a
    verificação — é o valor de referência contra o qual o ficheiro é
    confrontado. Ficheiros idênticos partilham conteúdo em disco mas mantêm
    registos distintos, porque a mesma evidência em incidentes diferentes tem
    contextos diferentes.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_incident_created", "incident_id", "created_at"),
        Index("ix_evidence_sha256", "sha256"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_type: Mapped[EvidenceType] = mapped_column(
        enum_column(EvidenceType), nullable=False, default=EvidenceType.OUTRO, index=True
    )

    #: Nome tal como enviado pelo utilizador, apenas para apresentação. O
    #: caminho em disco nunca é derivado dele (prevenção de path traversal).
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Caminho relativo à raiz de armazenamento, gerado pelo servidor.
    storage_path: Mapped[str] = mapped_column(String(400), nullable=False)
    content_type: Mapped[str] = mapped_column(String(120), nullable=False, default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    #: Hash de integridade calculado na recepção.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)

    #: Resultado da última verificação de integridade e quando ocorreu.
    integrity_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    integrity_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    #: Origem da evidência: quem/o quê a produziu (§15).
    source: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra_metadata: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("tasks.id", ondelete="SET NULL"), nullable=True
    )

    incident: Mapped["Incident"] = relationship(  # noqa: F821
        back_populates="evidence", lazy="noload"
    )
    uploaded_by: Mapped["User | None"] = relationship(lazy="selectin")  # noqa: F821

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Evidence {self.name} sha256={self.sha256[:12]}>"
