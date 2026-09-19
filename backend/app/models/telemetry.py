"""Eventos, alertas e regras de correlação (§8, §9).

A distinção entre `Event` e `Alert` é deliberada e é o que sustenta o §6:

* **Event** — um sinal recebido de uma fonte, normalizado mas imutável. Alto
  volume. Guarda sempre o payload original, para que a normalização possa ser
  corrigida e reprocessada sem perda de informação.
* **Alert** — uma asserção de detecção, resultante de um ou mais eventos após
  deduplicação. É a unidade que o analista tria.

Sem esta separação, "10 000 tentativas de autenticação falhadas" seriam 10 000
alertas. Com ela, são um alerta com `event_count = 10000`.
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
    AlertStatus,
    CorrelationOutcome,
    CorrelationStrategy,
    Severity,
    SourceKind,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk


class Event(Base, TimestampMixin):
    """Sinal bruto normalizado, tal como recebido de uma fonte.

    Os campos normalizados seguem o formato interno comum do §8. O
    `raw_payload` é a prova de origem: qualquer valor apresentado ao analista
    pode ser confrontado com o que a fonte enviou de facto.
    """

    __tablename__ = "events"
    __table_args__ = (
        # A fonte garante unicidade do seu próprio identificador; isto torna a
        # ingestão idempotente perante reenvios do integrator do Wazuh.
        UniqueConstraint("source_kind", "source_event_id", name="uq_events_source_eventid"),
        Index("ix_events_occurred_source", "occurred_at", "source_kind"),
        Index("ix_events_src_dst", "source_ip", "destination_ip"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()

    # --- proveniência ---
    source_kind: Mapped[SourceKind] = mapped_column(
        enum_column(SourceKind), nullable=False, index=True
    )
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: Identificador atribuído pela fonte (ex.: `id` do alerta Wazuh).
    source_event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL"), nullable=True
    )

    # --- formato interno comum (§8) ---
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity), nullable=False, default=Severity.INFO, index=True
    )
    #: Severidade original da fonte antes do mapeamento (ex.: nível Wazuh 0-15).
    source_severity: Mapped[str | None] = mapped_column(String(40), nullable=True)

    event_type: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)

    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    rule_id: Mapped[str | None] = mapped_column(String(60), nullable=True, index=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Grupos/categorias declarados pela fonte (ex.: `rule.groups` do Wazuh).
    rule_groups: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    #: Técnicas MITRE declaradas pela própria fonte. Distinguem-se das inferidas
    #: pelo motor: estas são factos reportados, aquelas são hipóteses (§11).
    reported_techniques: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    #: Payload original, integral.
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Campos normalizados adicionais que não têm coluna própria.
    normalized_extra: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )

    alert: Mapped["Alert | None"] = relationship(back_populates="events", lazy="noload")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Event {self.source_kind}:{self.source_event_id}>"


class Alert(Base, TimestampMixin):
    """Asserção de detecção sujeita a triagem."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_severity", "status", "severity"),
        # Índice de pesquisa textual (`pg_trgm`, criado na migração 0002).
        # Declarado aqui porque o autogenerate compara o esquema com o metadata:
        # um índice que existe na base mas não nos modelos é lido como "a mais" e
        # a migração seguinte apagava-o em silêncio.
        Index(
            "ix_alerts_title_trgm", "title",
            postgresql_using="gin", postgresql_ops={"title": "gin_trgm_ops"},
        ),
        Index("ix_alerts_dedup_open", "dedup_key", "status"),
        Index("ix_alerts_triage_queue", "status", "triage_score", "last_event_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    reference: Mapped[str] = mapped_column(String(24), nullable=False, unique=True, index=True)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    source_kind: Mapped[SourceKind] = mapped_column(
        enum_column(SourceKind), nullable=False, index=True
    )
    source_name: Mapped[str] = mapped_column(String(120), nullable=False)

    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity), nullable=False, default=Severity.MEDIA, index=True
    )
    status: Mapped[AlertStatus] = mapped_column(
        enum_column(AlertStatus), nullable=False, default=AlertStatus.NOVO, index=True
    )

    #: Chave de deduplicação: derivada de (fonte, regra, host, IPs). Eventos
    #: equivalentes dentro da janela agregam-se neste alerta em vez de criarem
    #: alertas novos.
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_event_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    # --- resultado do motor de triagem (§12). Sempre explicável. ---
    #: Pontuação 0-100 calculada de forma determinística.
    triage_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    #: Contribuição de cada factor para a pontuação, para que o analista possa
    #: ver *porquê*. Ex.: {"severidade_fonte": 30, "criticidade_activo": 20, ...}
    triage_factors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Probabilidade estimada de falso positivo (0-100), derivada do histórico
    #: real de decisões sobre alertas da mesma regra.
    false_positive_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    triage_rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- resultado da correlação (§9) ---
    correlation_outcome: Mapped[CorrelationOutcome] = mapped_column(
        enum_column(CorrelationOutcome), nullable=False, default=CorrelationOutcome.SEM_CORRELACAO
    )
    correlation_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("correlation_rules.id", ondelete="SET NULL"), nullable=True
    )
    correlation_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- ligações ---
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    #: Preenchido quando o alerta foi marcado como duplicado de outro.
    duplicate_of_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )

    # --- triagem humana ---
    triaged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triage_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Marcação explícita de dados de demonstração (§34). Nunca silenciosa: a
    #: interface assinala visivelmente qualquer registo com esta marca.
    is_demo_data: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    rule_id: Mapped[str | None] = mapped_column(String(60), nullable=True, index=True)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    events: Mapped[list[Event]] = relationship(
        back_populates="alert", lazy="noload", foreign_keys=[Event.alert_id]
    )
    incident: Mapped["Incident | None"] = relationship(
        back_populates="alerts", lazy="noload", foreign_keys=[incident_id]
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.reference} {self.status}>"


class CorrelationRule(Base, TimestampMixin):
    """Regra configurável do motor de correlação.

    As regras vivem na base de dados, não no código: um SOC afina a correlação
    continuamente, e exigir um deploy para isso tornaria o motor inútil na
    prática. O §36 ("APRENDER") depende desta maleabilidade.
    """

    __tablename__ = "correlation_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    #: Ordem de avaliação. A primeira regra que corresponder decide o destino.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100, index=True)

    strategy: Mapped[CorrelationStrategy] = mapped_column(
        enum_column(CorrelationStrategy), nullable=False
    )
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    #: Nº mínimo de alertas distintos para a regra disparar.
    min_alerts: Mapped[int] = mapped_column(Integer, nullable=False, default=2)

    #: Campos cuja igualdade define "a mesma actividade" para a estratégia
    #: ENTIDADE_PARTILHADA. Ex.: ["source_ip"], ["host", "username"].
    match_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    #: Filtros que restringem os alertas candidatos.
    #: Ex.: {"severity_min": "MEDIA", "rule_groups_any": ["authentication_failed"]}
    conditions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    #: Para SEQUENCIA_TEMPORAL: ordem esperada de grupos de regras.
    sequence: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    #: Severidade/categoria a atribuir ao incidente resultante. Nulo mantém a
    #: severidade máxima observada entre os alertas correlacionados.
    resulting_severity: Mapped[Severity | None] = mapped_column(
        enum_column(Severity), nullable=True
    )
    resulting_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    incident_title_template: Mapped[str] = mapped_column(
        String(300), nullable=False, default="Actividade correlacionada"
    )
    #: Playbook a sugerir quando esta regra dispara.
    suggested_playbook_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True
    )

    #: Estatísticas reais de utilização, base do §36 ("APRENDER").
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_matched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Quantas vezes um incidente criado por esta regra acabou como falso
    #: positivo. Permite identificar regras ruidosas com dados, não por intuição.
    false_positive_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<CorrelationRule {self.name}>"
