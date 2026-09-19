"""Activos, indicadores e MITRE — /api/assets, /api/iocs, /api/mitre."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, or_, select

from app.core import audit
from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import (
    INCIDENT_ACTIVE_STATUSES,
    AssetCriticality,
    AssetType,
    IocReputation,
    IocType,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.partial_update import reject_nulls_for_required
from app.core.permissions import Permission
from app.models.catalog import Asset, Ioc, MitreTactic, MitreTechnique
from app.models.incident import Incident, IncidentTechnique, incident_assets
from app.models.investigation import Observation
from app.models.telemetry import Alert
from app.schemas.catalog import (
    AssetDetail,
    AssetRead,
    AssetUpdate,
    AssetWrite,
    IocAllowlist,
    IocDetail,
    IocRead,
    IocUpdate,
    IocWrite,
    MitreCoverageEntry,
    MitreTacticRead,
    MitreTechniqueRead,
)

asset_router = APIRouter(prefix="/assets", tags=["Activos"])
ioc_router = APIRouter(prefix="/iocs", tags=["Indicadores de compromisso"])
mitre_router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


# ------------------------------------------------------------------ activos
@asset_router.get("", response_model=Page[AssetRead], summary="Listar activos")
async def list_assets(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ASSETS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query()] = None,
    tipo: Annotated[list[AssetType] | None, Query()] = None,
    criticidade: Annotated[list[AssetCriticality] | None, Query()] = None,
    apenas_activos: Annotated[bool, Query()] = True,
) -> Page[AssetRead]:
    stmt = select(Asset)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Asset.identifier.ilike(pattern),
                Asset.name.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.ip_address.ilike(pattern),
            )
        )
    if tipo:
        stmt = stmt.where(Asset.asset_type.in_(tipo))
    if criticidade:
        stmt = stmt.where(Asset.criticality.in_(criticidade))
    if apenas_activos:
        stmt = stmt.where(Asset.is_active.is_(True))

    stmt = apply_sort(
        stmt, Asset, params.sort,
        allowed={"identifier", "name", "criticality", "asset_type", "created_at"},
        default="identifier",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([AssetRead.model_validate(a) for a in items], total, params)


@asset_router.post(
    "", response_model=AssetRead, status_code=status.HTTP_201_CREATED,
    summary="Registar activo",
)
async def create_asset(
    payload: AssetWrite,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ASSETS_MANAGE))],
) -> AssetRead:
    existing = await session.execute(
        select(Asset).where(Asset.identifier == payload.identifier)
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Já existe um activo com o identificador '{payload.identifier}'.")

    asset = Asset(**payload.model_dump())
    session.add(asset)
    await session.flush()

    await audit.record(
        session, ctx,
        action="CRIAR_ACTIVO", resource_type="activo", resource_id=asset.id,
        description=f"Activo '{asset.identifier}' registado ({asset.criticality.value}).",
        new_value=payload.model_dump(mode="json"),
    )
    return AssetRead.model_validate(asset)


@asset_router.get("/{asset_id}", response_model=AssetDetail, summary="Detalhe do activo")
async def get_asset(
    asset_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.ASSETS_READ))],
) -> AssetDetail:
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Activo", asset_id)

    counts = await session.execute(
        select(
            func.count(Incident.id),
            func.count(Incident.id).filter(
                Incident.status.in_(list(INCIDENT_ACTIVE_STATUSES))
            ),
        )
        .select_from(incident_assets)
        .join(Incident, Incident.id == incident_assets.c.incident_id)
        .where(incident_assets.c.asset_id == asset_id)
    )
    total, active = counts.one()
    alerts = await session.execute(
        select(func.count()).select_from(Alert).where(Alert.asset_id == asset_id)
    )

    detail = AssetDetail.model_validate(asset)
    detail.incidentes_totais = int(total or 0)
    detail.incidentes_activos = int(active or 0)
    detail.alertas_recentes = int(alerts.scalar_one() or 0)
    return detail


@asset_router.patch("/{asset_id}", response_model=AssetRead, summary="Editar activo")
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.ASSETS_MANAGE))],
) -> AssetRead:
    asset = await session.get(Asset, asset_id)
    if asset is None:
        raise NotFoundError("Activo", asset_id)

    changes = payload.model_dump(exclude_unset=True)
    reject_nulls_for_required(asset, changes)
    for field, value in changes.items():
        setattr(asset, field, value)

    await audit.record_change(
        session, ctx, asset,
        action="EDITAR_ACTIVO", resource_type="activo",
        description=f"Activo '{asset.identifier}' editado.",
    )
    return AssetRead.model_validate(asset)


# --------------------------------------------------------------- indicadores
@ioc_router.get("", response_model=Page[IocRead], summary="Listar indicadores")
async def list_iocs(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.IOCS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query(description="Pesquisa pelo valor.")] = None,
    tipo: Annotated[list[IocType] | None, Query()] = None,
    reputacao: Annotated[list[IocReputation] | None, Query()] = None,
    incluir_permitidos: Annotated[bool, Query()] = False,
    avistamentos_minimos: Annotated[int | None, Query(ge=1)] = None,
) -> Page[IocRead]:
    stmt = select(Ioc)
    if q:
        stmt = stmt.where(Ioc.value.ilike(f"%{q.strip()}%"))
    if tipo:
        stmt = stmt.where(Ioc.ioc_type.in_(tipo))
    if reputacao:
        stmt = stmt.where(Ioc.reputation.in_(reputacao))
    if not incluir_permitidos:
        stmt = stmt.where(Ioc.is_allowlisted.is_(False))
    if avistamentos_minimos:
        stmt = stmt.where(Ioc.sighting_count >= avistamentos_minimos)

    stmt = apply_sort(
        stmt, Ioc, params.sort,
        allowed={"last_seen", "first_seen", "sighting_count", "risk_score",
                 "value", "created_at", "reputation"},
        default="-last_seen",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([IocRead.model_validate(i) for i in items], total, params)


@ioc_router.post(
    "", response_model=IocRead, status_code=status.HTTP_201_CREATED,
    summary="Registar indicador",
)
async def create_ioc(
    payload: IocWrite,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.IOCS_MANAGE))],
) -> IocRead:
    from app.services.ingestion_service import ioc_value_problem, normalise_ioc_value

    if problem := ioc_value_problem(payload.ioc_type, payload.value):
        raise ValidationError(
            f"Valor inválido para {payload.ioc_type.value}: {problem}.",
            code="VALOR_INVALIDO",
        )
    value = normalise_ioc_value(payload.ioc_type, payload.value)
    existing = await session.execute(
        select(Ioc).where(Ioc.ioc_type == payload.ioc_type, Ioc.value == value)
    )
    if (found := existing.scalar_one_or_none()) is not None:
        raise ConflictError(
            f"O indicador {payload.ioc_type.value} '{value}' já existe.",
            details={"ioc_id": str(found.id)},
        )

    ioc = Ioc(**{**payload.model_dump(), "value": value})
    session.add(ioc)
    await session.flush()

    await audit.record(
        session, ctx,
        action="CRIAR_IOC", resource_type="indicador", resource_id=ioc.id,
        description=f"Indicador {ioc.ioc_type.value} '{ioc.value}' registado.",
        new_value=payload.model_dump(mode="json"),
    )
    return IocRead.model_validate(ioc)


@ioc_router.get("/{ioc_id}", response_model=IocDetail, summary="Detalhe do indicador")
async def get_ioc(
    ioc_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.IOCS_READ))],
) -> IocDetail:
    ioc = await session.get(Ioc, ioc_id)
    if ioc is None:
        raise NotFoundError("Indicador", ioc_id)

    related = await session.execute(
        select(Incident, func.count(Observation.id))
        .join(Observation, Observation.incident_id == Incident.id)
        .where(Observation.ioc_id == ioc_id)
        .group_by(Incident.id)
        .order_by(Incident.detected_at.desc())
        .limit(50)
    )
    rows = related.all()

    detail = IocDetail.model_validate(ioc)
    detail.incidentes_relacionados = [
        {
            "id": str(incident.id),
            "referencia": incident.reference,
            "titulo": incident.title,
            "severidade": incident.severity.value,
            "estado": incident.status.value,
            "detectado_em": incident.detected_at.isoformat(),
            "observacoes": int(count),
        }
        for incident, count in rows
    ]
    detail.observacoes_totais = sum(int(c) for _, c in rows)
    return detail


@ioc_router.patch("/{ioc_id}", response_model=IocRead, summary="Editar indicador")
async def update_ioc(
    ioc_id: uuid.UUID,
    payload: IocUpdate,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.IOCS_MANAGE))],
) -> IocRead:
    ioc = await session.get(Ioc, ioc_id)
    if ioc is None:
        raise NotFoundError("Indicador", ioc_id)

    changes = payload.model_dump(exclude_unset=True)
    reject_nulls_for_required(ioc, changes)
    for field, value in changes.items():
        setattr(ioc, field, value)

    await audit.record_change(
        session, ctx, ioc,
        action="EDITAR_IOC", resource_type="indicador",
        description=f"Indicador '{ioc.value}' actualizado.",
    )
    return IocRead.model_validate(ioc)


@ioc_router.post(
    "/{ioc_id}/allowlist",
    response_model=IocRead,
    summary="Marcar indicador como benigno",
    description=(
        "Permitir um indicador suprime alertas futuros que o contenham, pelo "
        "que o motivo é obrigatório e fica registado na auditoria."
    ),
)
async def set_allowlist(
    ioc_id: uuid.UUID,
    payload: IocAllowlist,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.IOCS_MANAGE))],
) -> IocRead:
    ioc = await session.get(Ioc, ioc_id)
    if ioc is None:
        raise NotFoundError("Indicador", ioc_id)

    previous = ioc.is_allowlisted
    ioc.is_allowlisted = payload.is_allowlisted
    ioc.allowlist_reason = payload.reason
    if payload.is_allowlisted:
        ioc.reputation = IocReputation.BENIGNA

    await audit.record(
        session, ctx,
        action="ALTERAR_LISTA_PERMITIDOS", resource_type="indicador", resource_id=ioc.id,
        description=(
            f"Indicador '{ioc.value}' "
            f"{'adicionado à' if payload.is_allowlisted else 'removido da'} "
            f"lista de permitidos. Motivo: {payload.reason}"
        ),
        old_value={"permitido": previous},
        new_value={"permitido": payload.is_allowlisted, "motivo": payload.reason},
        changed_fields=["is_allowlisted"],
    )
    return IocRead.model_validate(ioc)


# ------------------------------------------------------------------- MITRE
@mitre_router.get(
    "/tactics", response_model=list[MitreTacticRead], summary="Tácticas ATT&CK",
    description="Ordenadas pela sequência canónica da cadeia de ataque.",
)
async def list_tactics(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.MITRE_READ))],
) -> list[MitreTacticRead]:
    result = await session.execute(select(MitreTactic).order_by(MitreTactic.ordering))
    return [MitreTacticRead.model_validate(t) for t in result.scalars()]


@mitre_router.get(
    "/techniques", response_model=Page[MitreTechniqueRead], summary="Técnicas ATT&CK"
)
async def list_techniques(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.MITRE_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    q: Annotated[str | None, Query(description="Pesquisa por identificador ou nome.")] = None,
    tactica: Annotated[str | None, Query(description="Nome curto da táctica.")] = None,
    incluir_subtecnicas: Annotated[bool, Query()] = True,
) -> Page[MitreTechniqueRead]:
    stmt = select(MitreTechnique).where(MitreTechnique.is_deprecated.is_(False))
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(MitreTechnique.technique_id.ilike(pattern), MitreTechnique.name.ilike(pattern))
        )
    if tactica:
        stmt = stmt.where(MitreTechnique.tactic_shortnames.contains([tactica]))
    if not incluir_subtecnicas:
        stmt = stmt.where(MitreTechnique.is_subtechnique.is_(False))

    stmt = apply_sort(
        stmt, MitreTechnique, params.sort,
        allowed={"technique_id", "name", "created_at"}, default="technique_id",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([MitreTechniqueRead.model_validate(t) for t in items], total, params)


@mitre_router.get(
    "/coverage",
    response_model=list[MitreCoverageEntry],
    summary="Cobertura observada de técnicas",
    description=(
        "Técnicas efectivamente observadas nos incidentes registados, "
        "separando as afirmadas das que são apenas hipótese do motor."
    ),
)
async def technique_coverage(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.MITRE_READ))],
) -> list[MitreCoverageEntry]:
    result = await session.execute(
        select(
            MitreTechnique.technique_id,
            MitreTechnique.name,
            MitreTactic.name,
            func.count(IncidentTechnique.id).filter(IncidentTechnique.is_asserted.is_(True)),
            func.count(IncidentTechnique.id).filter(IncidentTechnique.is_asserted.is_(False)),
        )
        .join(IncidentTechnique, IncidentTechnique.technique_id == MitreTechnique.id)
        .outerjoin(MitreTactic, MitreTactic.id == MitreTechnique.tactic_id)
        .group_by(MitreTechnique.technique_id, MitreTechnique.name, MitreTactic.name)
        .order_by(func.count(IncidentTechnique.id).desc())
    )
    return [
        MitreCoverageEntry(
            technique_id=tid, name=name, tactic=tactic,
            incidentes_afirmados=int(asserted), incidentes_hipotese=int(inferred),
        )
        for tid, name, tactic, asserted, inferred in result.all()
    ]


@mitre_router.get(
    "/techniques/{technique_id}",
    response_model=MitreTechniqueRead,
    summary="Detalhe de uma técnica",
)
async def get_technique(
    technique_id: str,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.MITRE_READ))],
) -> MitreTechniqueRead:
    from app.services.mitre_service import find_technique

    technique = await find_technique(session, technique_id)
    if technique is None:
        raise NotFoundError("Técnica MITRE", technique_id)
    return MitreTechniqueRead.model_validate(technique)
