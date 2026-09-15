"""Esquemas de activos, indicadores, MITRE e campanhas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.core.enums import (
    AssetCriticality,
    AssetType,
    Confidence,
    IocReputation,
    IocType,
    Severity,
)
from app.schemas.common import ApiInput, ApiModel


# ------------------------------------------------------------------ activos
class AssetWrite(ApiInput):
    identifier: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=160)
    asset_type: AssetType = AssetType.OUTRO
    criticality: AssetCriticality = AssetCriticality.MEDIA
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=45)
    mac_address: str | None = Field(default=None, max_length=17)
    operating_system: str | None = Field(default=None, max_length=120)
    owner: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    business_service: str | None = Field(default=None, max_length=160)
    description: str = Field(default="", max_length=4000)
    wazuh_agent_id: str | None = Field(
        default=None, max_length=32,
        description="Identificador do agente Wazuh, se monitorizado.",
    )
    tags: list[str] = Field(default_factory=list)
    is_active: bool = True


class AssetUpdate(ApiInput):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    asset_type: AssetType | None = None
    criticality: AssetCriticality | None = None
    hostname: str | None = Field(default=None, max_length=255)
    ip_address: str | None = Field(default=None, max_length=45)
    mac_address: str | None = Field(default=None, max_length=17)
    operating_system: str | None = Field(default=None, max_length=120)
    owner: str | None = Field(default=None, max_length=120)
    location: str | None = Field(default=None, max_length=120)
    business_service: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=4000)
    wazuh_agent_id: str | None = Field(default=None, max_length=32)
    tags: list[str] | None = None
    is_active: bool | None = None


class AssetRead(ApiModel):
    id: uuid.UUID
    identifier: str
    name: str
    asset_type: str
    criticality: str
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    owner: str | None = None
    location: str | None = None
    business_service: str | None = None
    description: str
    wazuh_agent_id: str | None = None
    is_active: bool
    tags: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    incidentes_activos: int = 0
    incidentes_totais: int = 0
    alertas_recentes: int = 0


# --------------------------------------------------------------- indicadores
class IocWrite(ApiInput):
    ioc_type: IocType
    value: str = Field(min_length=1, max_length=512)
    reputation: IocReputation = IocReputation.DESCONHECIDA
    confidence: Confidence = Confidence.BAIXA
    source: str = Field(default="manual", max_length=120)
    context: str = Field(default="", max_length=4000)
    tags: list[str] = Field(default_factory=list)


class IocUpdate(ApiInput):
    reputation: IocReputation | None = None
    confidence: Confidence | None = None
    context: str | None = Field(default=None, max_length=4000)
    tags: list[str] | None = None


class IocAllowlist(ApiInput):
    """Marcação explícita de um indicador como benigno."""

    is_allowlisted: bool
    reason: str = Field(
        min_length=5, max_length=2000,
        description=(
            "Obrigatório: permitir um indicador suprime alertas futuros, pelo "
            "que o motivo tem de ficar registado."
        ),
    )


class IocRead(ApiModel):
    id: uuid.UUID
    ioc_type: str
    value: str
    reputation: str
    confidence: str
    risk_score: int
    source: str
    context: str
    tags: list[str] = Field(default_factory=list)
    #: Derivados de avistamentos reais, nunca introduzidos manualmente (§10).
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sighting_count: int
    is_allowlisted: bool
    allowlist_reason: str | None = None
    enrichment: dict = Field(default_factory=dict)
    enriched_at: datetime | None = None
    created_at: datetime


class IocDetail(IocRead):
    incidentes_relacionados: list[dict] = Field(default_factory=list)
    observacoes_totais: int = 0


# ---------------------------------------------------------------- MITRE
class MitreTacticRead(ApiModel):
    id: uuid.UUID
    tactic_id: str
    shortname: str
    name: str
    description: str
    url: str | None = None
    ordering: int


class MitreTechniqueRead(ApiModel):
    id: uuid.UUID
    technique_id: str
    name: str
    description: str
    url: str | None = None
    is_subtechnique: bool
    parent_technique_id: str | None = None
    tactic_shortnames: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    detection: str
    attack_version: str | None = None


class MitreCoverageEntry(ApiModel):
    """Cobertura observada de uma técnica nos incidentes registados."""

    technique_id: str
    name: str
    tactic: str | None = None
    #: Quantos incidentes a afirmaram e quantos a têm apenas como hipótese.
    incidentes_afirmados: int = 0
    incidentes_hipotese: int = 0


# -------------------------------------------------------------- campanhas
class CampaignWrite(ApiInput):
    name: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=8000)
    severity: Severity = Severity.MEDIA
    confidence: Confidence = Confidence.BAIXA
    suspected_actor: str | None = Field(default=None, max_length=160)
    incident_ids: list[uuid.UUID] = Field(default_factory=list)


class CampaignRead(ApiModel):
    id: uuid.UUID
    reference: str
    name: str
    description: str
    severity: str
    confidence: str
    suspected_actor: str | None = None
    first_activity_at: datetime | None = None
    last_activity_at: datetime | None = None
    is_active: bool
    created_by_engine: bool
    engine_rationale: str | None = None
    created_at: datetime
    incidentes: int = 0
