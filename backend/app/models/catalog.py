"""Entidades de catálogo: activos, indicadores, MITRE ATT&CK e campanhas.

São entidades *globais* — existem independentemente de qualquer incidente. Um IP
malicioso é um facto sobre o mundo; que tenha sido visto num incidente concreto
é um facto diferente, registado como Observação (ver `models/investigation.py`).
Esta separação é o que permite calcular primeira/última observação a partir de
avistamentos reais em vez de campos preenchidos à mão (§10).
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
    AssetCriticality,
    AssetType,
    Confidence,
    IocReputation,
    IocType,
    Severity,
)
from app.models.base import JSONB, PGUUID, Base, TimestampMixin, enum_column, uuid_pk


class Asset(Base, TimestampMixin):
    """Activo da organização que pode ser afectado por um incidente."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("identifier", name="uq_assets_identifier"),
        Index("ix_assets_ip_hostname", "ip_address", "hostname"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Identificador estável na organização (etiqueta de inventário, FQDN, ...).
    identifier: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    asset_type: Mapped[AssetType] = mapped_column(
        enum_column(AssetType), nullable=False, default=AssetType.OUTRO
    )
    criticality: Mapped[AssetCriticality] = mapped_column(
        enum_column(AssetCriticality), nullable=False, default=AssetCriticality.MEDIA, index=True
    )

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(120), nullable=True)

    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    location: Mapped[str | None] = mapped_column(String(120), nullable=True)
    business_service: Mapped[str | None] = mapped_column(String(160), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Identificador do agente Wazuh, quando o activo é monitorizado. É o que
    #: permite ligar um alerta recebido ao activo real sem adivinhar.
    wazuh_agent_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Asset {self.identifier}>"


class Ioc(Base, TimestampMixin):
    """Indicador de compromisso: entidade global, única por (tipo, valor).

    `first_seen`/`last_seen`/`sighting_count` são mantidos pelo serviço de
    observações a partir de avistamentos efectivos — nunca introduzidos
    manualmente.
    """

    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_iocs_type_value"),
        Index("ix_iocs_reputation_type", "reputation", "ioc_type"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    ioc_type: Mapped[IocType] = mapped_column(enum_column(IocType), nullable=False, index=True)
    #: Valor normalizado (minúsculas para domínios/hashes, forma canónica de IP).
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    reputation: Mapped[IocReputation] = mapped_column(
        enum_column(IocReputation), nullable=False, default=IocReputation.DESCONHECIDA, index=True
    )
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence), nullable=False, default=Confidence.BAIXA
    )
    #: Pontuação 0-100 calculada pelo motor de inteligência, não introduzida.
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    source: Mapped[str] = mapped_column(String(120), nullable=False, default="interno")
    context: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    sighting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Marcado como benigno de forma deliberada: suprime alertas futuros e
    #: alimenta o detector de falsos positivos.
    is_allowlisted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    allowlist_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    #: Enriquecimento externo. Vazio enquanto nenhuma fonte estiver configurada;
    #: nunca preenchido com valores fictícios (§34).
    enrichment: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Ioc {self.ioc_type}:{self.value}>"


class MitreTactic(Base, TimestampMixin):
    """Táctica ATT&CK. Carregada do bundle STIX oficial da MITRE (§11)."""

    __tablename__ = "mitre_tactics"

    id: Mapped[uuid.UUID] = uuid_pk()
    tactic_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)
    shortname: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Ordem canónica na cadeia de ataque, usada para desenhar a kill chain.
    ordering: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    techniques: Mapped[list["MitreTechnique"]] = relationship(
        back_populates="tactic", lazy="noload"
    )


class MitreTechnique(Base, TimestampMixin):
    """Técnica ou subtécnica ATT&CK.

    Uma técnica pode pertencer a várias tácticas; guardamos a lista completa em
    `tactic_shortnames` e uma táctica primária como chave estrangeira para
    consultas e agrupamentos rápidos.
    """

    __tablename__ = "mitre_techniques"
    __table_args__ = (
        Index("ix_mitre_techniques_parent", "parent_technique_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str | None] = mapped_column(String(255), nullable=True)

    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Ex.: "T1078" para a subtécnica "T1078.004".
    parent_technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)

    tactic_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("mitre_tactics.id", ondelete="SET NULL"), nullable=True
    )
    tactic_shortnames: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    platforms: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    data_sources: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    detection: Mapped[str] = mapped_column(Text, nullable=False, default="")

    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    attack_version: Mapped[str | None] = mapped_column(String(20), nullable=True)

    tactic: Mapped[MitreTactic | None] = relationship(
        back_populates="techniques", lazy="selectin"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<MitreTechnique {self.technique_id}>"


class Campaign(Base, TimestampMixin):
    """Agrupamento de incidentes que se crê pertencerem à mesma actividade (§20).

    Existe para dar resposta à pergunta que o RTIR e o TheHive não respondem:
    "estes cinco incidentes são a mesma operação?". É criada por um analista ou
    proposta pelo motor de correlação.
    """

    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = uuid_pk()
    reference: Mapped[str] = mapped_column(String(24), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    severity: Mapped[Severity] = mapped_column(
        enum_column(Severity), nullable=False, default=Severity.MEDIA
    )
    confidence: Mapped[Confidence] = mapped_column(
        enum_column(Confidence), nullable=False, default=Confidence.BAIXA
    )
    suspected_actor: Mapped[str | None] = mapped_column(String(160), nullable=True)

    first_activity_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_activity_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    #: Preenchido quando a campanha foi proposta pelo motor de correlação, com a
    #: justificação da proposta.
    created_by_engine: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    engine_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    incidents: Mapped[list["Incident"]] = relationship(
        back_populates="campaign", lazy="noload"
    )
