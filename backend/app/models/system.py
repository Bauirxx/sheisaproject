"""Auditoria, integrações, notificações e relatórios (§16, §26, §31)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AuditOutcome,
    IntegrationDirection,
    IntegrationStatus,
    NotificationKind,
    ReportKind,
    Severity,
    SourceKind,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk


class AuditLog(Base):
    """Registo de auditoria (§16).

    Notas de concepção:

    * **Só inserção.** Não há caminho na aplicação que actualize ou apague uma
      linha desta tabela. Um registo de auditoria editável não tem valor.
    * **Sem `TimestampMixin`.** Um `updated_at` seria uma contradição.
    * **Identidade desnormalizada.** Guardamos `actor_email` além do `actor_id`
      porque o utilizador pode ser eliminado; o registo tem de continuar a
      dizer quem agiu, e uma chave estrangeira anulada não o diria.
    * **Valores anterior e novo.** Só o par permite responder à pergunta do §16
      ("MÉDIA -> ALTA"); guardar apenas o estado final perderia metade da
      informação.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_resource", "resource_type", "resource_id", "created_at"),
        Index("ix_audit_logs_actor_time", "actor_id", "created_at"),
        Index("ix_audit_logs_action_time", "action", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # --- quem ---
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str] = mapped_column(String(254), nullable=False, default="sistema")
    actor_role: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: Preenchido quando a acção foi executada por uma chave de API (ingestão).
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True
    )
    #: True quando não houve actor humano (motor, playbook, tarefa agendada).
    is_system_actor: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # --- fez o quê, sobre o quê ---
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    #: Referência legível do recurso (INC-000125), para que a auditoria seja
    #: consultável mesmo depois de o recurso desaparecer.
    resource_reference: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)

    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # --- valor anterior e novo ---
    old_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    #: Nomes dos campos alterados, para filtrar sem inspeccionar o JSON.
    changed_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # --- origem e resultado ---
    #: "aplicacao_web" | "api" | "ingestao" | "motor" | "playbook" | "cli"
    origin: Mapped[str] = mapped_column(String(30), nullable=False, default="aplicacao_web")
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    outcome: Mapped[AuditOutcome] = mapped_column(
        enum_column(AuditOutcome), nullable=False, default=AuditOutcome.SUCESSO, index=True
    )
    #: Presente quando `outcome` é NEGADO ou FALHA.
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AuditLog {self.action} {self.resource_type} {self.outcome}>"


class Integration(Base, TimestampMixin):
    """Ligação a um sistema externo (§26).

    `status` nunca é `ACTIVA` por declaração: só depois de um teste de ligação
    bem-sucedido, cujo resultado e instante ficam registados. Isto é a
    materialização do §4 — uma integração não verificada apresenta-se como não
    verificada.
    """

    __tablename__ = "integrations"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    kind: Mapped[SourceKind] = mapped_column(enum_column(SourceKind), nullable=False, index=True)
    direction: Mapped[IntegrationDirection] = mapped_column(
        enum_column(IntegrationDirection), nullable=False, default=IntegrationDirection.ENTRADA
    )
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    status: Mapped[IntegrationStatus] = mapped_column(
        enum_column(IntegrationStatus), nullable=False,
        default=IntegrationStatus.NAO_CONFIGURADA, index=True,
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Configuração não sensível (URL base, opções). Segredos NUNCA aqui.
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Nomes das variáveis de ambiente que contêm os segredos desta integração
    #: (§23: "gestão de segredos através de variáveis de ambiente"). Guardamos
    #: o *nome*, não o valor.
    secret_env_vars: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # --- verificação real ---
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_check_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- estatísticas de utilização reais ---
    events_received: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    actions_executed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actions_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Tipos de acção que esta integração consegue executar. Vazio => a
    #: integração só recebe dados.
    supported_actions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="integration", lazy="noload"
    )

    @property
    def is_operational(self) -> bool:
        return self.is_enabled and self.status == IntegrationStatus.ACTIVA

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Integration {self.name} {self.status}>"


class Notification(Base, TimestampMixin):
    """Aviso dirigido a um utilizador."""

    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_user_unread", "user_id", "read_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    kind: Mapped[NotificationKind] = mapped_column(
        enum_column(NotificationKind), nullable=False, index=True
    )
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity), nullable=False, default=Severity.INFO
    )

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Recurso a que a notificação diz respeito, para navegação directa.
    resource_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    resource_reference: Mapped[str | None] = mapped_column(String(24), nullable=True)

    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Report(Base, TimestampMixin):
    """Relatório gerado (§31).

    O conteúdo é persistido em JSON estruturado no momento da geração, e não
    recalculado em cada consulta. Um relatório é um instantâneo: se for
    regenerado dias depois com os dados alterados, deixa de descrever o que foi
    apresentado a quem o leu.
    """

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_kind_created", "kind", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    reference: Mapped[str] = mapped_column(String(24), nullable=False, unique=True, index=True)
    kind: Mapped[ReportKind] = mapped_column(enum_column(ReportKind), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(250), nullable=False)

    #: Parâmetros usados (intervalo, filtros). Tornam o relatório reproduzível.
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Conteúdo estruturado do relatório, tal como gerado.
    content: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    period_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Presente nos relatórios de incidente.
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: Contagem de registos que sustentam o relatório, para verificação rápida.
    record_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    generated_by: Mapped["User | None"] = relationship(lazy="selectin")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Report {self.reference} {self.kind}>"
