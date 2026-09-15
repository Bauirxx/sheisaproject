"""Relatórios — /api/reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from pydantic import Field
from sqlalchemy import select

from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import ReportKind
from app.core.errors import NotFoundError, ValidationError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.models.system import Report
from app.schemas.common import ApiInput, ApiModel
from app.services import incident_service, report_service

router = APIRouter(prefix="/reports", tags=["Relatórios"])


class ReportRead(ApiModel):
    id: uuid.UUID
    reference: str
    kind: str
    title: str
    parameters: dict = Field(default_factory=dict)
    period_start: datetime | None = None
    period_end: datetime | None = None
    incident_id: uuid.UUID | None = None
    record_count: int
    created_at: datetime


class ReportDetail(ReportRead):
    #: Conteúdo tal como gerado. Um relatório é um instantâneo, não uma vista.
    content: dict = Field(default_factory=dict)


class IncidentReportRequest(ApiInput):
    incident_id: uuid.UUID


class PeriodReportRequest(ApiInput):
    start: datetime
    end: datetime
    title: str | None = None


@router.get("", response_model=Page[ReportRead], summary="Listar relatórios gerados")
async def list_reports(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    tipo: Annotated[list[ReportKind] | None, Query()] = None,
    incident_id: Annotated[uuid.UUID | None, Query()] = None,
) -> Page[ReportRead]:
    stmt = select(Report)
    if tipo:
        stmt = stmt.where(Report.kind.in_(tipo))
    if incident_id:
        stmt = stmt.where(Report.incident_id == incident_id)

    stmt = apply_sort(
        stmt, Report, params.sort,
        allowed={"created_at", "kind", "reference", "title"}, default="-created_at",
    )
    items, total = await paginate(session, stmt, params)
    return Page.build([ReportRead.model_validate(r) for r in items], total, params)


@router.get("/{report_id}", response_model=ReportDetail, summary="Conteúdo do relatório")
async def get_report(
    report_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_READ))],
) -> ReportDetail:
    report = await session.get(Report, report_id)
    if report is None:
        raise NotFoundError("Relatório", report_id)
    return ReportDetail.model_validate(report)


@router.post(
    "/incident",
    response_model=ReportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Gerar relatório de incidente",
    description=(
        "Reconstitui o incidente respondendo às oito perguntas do relatório: o "
        "que aconteceu, quando, como foi detectado, quem investigou, que "
        "evidências existem, que decisões foram tomadas, que acções foram "
        "executadas e qual foi o resultado."
    ),
)
async def generate_incident_report(
    payload: IncidentReportRequest,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_GENERATE))],
) -> ReportDetail:
    incident = await incident_service.get_incident(
        session, payload.incident_id, with_details=True
    )
    content = await report_service.build_incident_report(session, incident)
    report = await report_service.persist_report(
        session, ctx,
        kind=ReportKind.INCIDENTE,
        title=f"Relatório do incidente {incident.reference}",
        content=content,
        parameters={"incident_id": str(incident.id), "referencia": incident.reference},
        incident_id=incident.id,
        record_count=1,
    )
    return ReportDetail.model_validate(report)


@router.post(
    "/period",
    response_model=ReportDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Gerar relatório de período",
)
async def generate_period_report(
    payload: PeriodReportRequest,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_GENERATE))],
) -> ReportDetail:
    if payload.end <= payload.start:
        raise ValidationError("A data final tem de ser posterior à inicial.")
    if (payload.end - payload.start) > timedelta(days=366):
        raise ValidationError("O período não pode exceder 366 dias.")

    content = await report_service.build_period_report(
        session, start=payload.start, end=payload.end
    )
    report = await report_service.persist_report(
        session, ctx,
        kind=ReportKind.PERIODO,
        title=payload.title
        or (
            f"Actividade de {payload.start.date().isoformat()} a "
            f"{payload.end.date().isoformat()}"
        ),
        content=content,
        parameters={"inicio": payload.start.isoformat(), "fim": payload.end.isoformat()},
        period_start=payload.start,
        period_end=payload.end,
        record_count=content["totais"]["incidentes"],
    )
    return ReportDetail.model_validate(report)


@router.get(
    "/{report_id}/pdf",
    summary="Exportar relatório em PDF",
    description=(
        "Exportação opcional: requer o pacote `reportlab` "
        "(`pip install -r requirements-reports.txt`). Sem ele, a API responde "
        "503 em vez de devolver um ficheiro inválido."
    ),
)
async def export_pdf(
    report_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_READ))],
):
    from app.core.errors import FeatureNotAvailableError

    report = await session.get(Report, report_id)
    if report is None:
        raise NotFoundError("Relatório", report_id)

    try:
        from app.reporting.pdf import render_report_pdf
    except ImportError as exc:
        raise FeatureNotAvailableError(
            "A exportação em PDF requer o pacote 'reportlab', que não está "
            "instalado nesta instalação. O relatório continua disponível em "
            "JSON.",
            code="PDF_INDISPONIVEL",
        ) from exc

    from fastapi.responses import Response

    pdf_bytes = render_report_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{report.reference}.pdf"'
        },
    )
