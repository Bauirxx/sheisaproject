"""Comunicações de incidente — /api/public e /api/reports-inbox (§5 · §37).

Dois encaminhadores de propósito, porque têm regras de acesso opostas e
misturá-los seria pedir um acidente.

`public_router` **não exige autenticação**. É a única escrita da plataforma
nessas condições, e é tratada como tal: limite de taxa próprio e mais
restritivo que o geral, tamanhos limitados em todos os campos, e nada do que o
comunicante envia é aceite como avaliação da plataforma. O que devolve é o
mínimo — o estado da comunicação e mais nada (§37: *o utilizador externo nunca
deve aceder a dados internos*).

`inbox_router` é a fila do analista, com permissões como o resto da plataforma.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import (
    REPORT_OPEN_STATUSES,
    IncidentCategory,
    ReportChannel,
    ReportStatus,
    Severity,
)
from app.core.errors import IntegrationNotAvailableError, ValidationError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.models.identity import User
from app.models.reporting import IncidentReport
from app.schemas.reporting import (
    ReportAccept,
    ReportDuplicate,
    ReportLinkIncident,
    ReportListItem,
    ReportPublicStatus,
    ReportRead,
    ReportReject,
    ReportSubmit,
    ReportSubmitted,
)
from app.services import email_service, report_inbox_service

public_router = APIRouter(prefix="/public", tags=["Portal externo"])
inbox_router = APIRouter(prefix="/reports-inbox", tags=["Comunicações recebidas"])


def _ip_do_pedido(request: Request) -> str | None:
    """Endereço de onde a submissão partiu.

    Serve para investigar abuso do formulário público. Não é usado para
    autorizar nada: atrás de um proxy pode ser o do proxy, e confiar nele para
    decisões de acesso seria confiar num cabeçalho que o cliente controla.
    """
    return request.client.host if request.client else None


# =============================================================== portal externo
@public_router.post(
    "/reports",
    response_model=ReportSubmitted,
    status_code=status.HTTP_201_CREATED,
    summary="Comunicar um incidente (sem conta na plataforma)",
    description=(
        "Aberto a qualquer pessoa, sem autenticação. Devolve uma referência e um "
        "código de acompanhamento — **o código é mostrado uma única vez**, porque "
        "a base de dados guarda apenas o seu resumo.\n\n"
        "A classificação indicada por quem comunica é registada como afirmação "
        "de terceiros e não como avaliação da plataforma; os indicadores ficam "
        "em texto e não entram no catálogo sem verificação de um analista."
    ),
)
async def submit_report(
    payload: ReportSubmit,
    request: Request,
    session: SessionDep,
    ctx: AuditDep,
) -> ReportSubmitted:
    relato, codigo = await report_inbox_service.submit(
        session,
        ctx,
        reporter_name=payload.reporter_name,
        reporter_email=payload.reporter_email,
        reporter_organisation=payload.reporter_organisation,
        reporter_phone=payload.reporter_phone,
        subject=payload.subject,
        description=payload.description,
        claimed_category=payload.claimed_category,
        claimed_severity=payload.claimed_severity,
        reported_indicators=payload.reported_indicators,
        channel=ReportChannel.PORTAL,
        submitted_from_ip=_ip_do_pedido(request),
    )
    return ReportSubmitted(
        referencia=relato.reference,
        codigo_de_acompanhamento=codigo,
        aviso=(
            "Guarde a referência e o código: é com os dois que pode consultar o "
            "estado desta comunicação. O código não pode voltar a ser mostrado."
        ),
    )


@public_router.get(
    "/reports/{reference}",
    response_model=ReportPublicStatus,
    summary="Consultar o estado de uma comunicação",
    description=(
        "Exige a referência **e** o código de acompanhamento. Devolve apenas o "
        "estado: nunca o incidente a que foi ligada, quem a avaliou ou as notas "
        "internas. Uma referência inexistente e um código errado dão a mesma "
        "resposta, para que as referências — que são sequenciais — não possam ser "
        "enumeradas."
    ),
)
async def track_report(
    reference: str,
    session: SessionDep,
    codigo: Annotated[str, Query(min_length=8, max_length=128, description="Código de acompanhamento.")],
) -> ReportPublicStatus:
    relato = await report_inbox_service.track(
        session, reference=reference, codigo=codigo
    )
    return ReportPublicStatus.model_validate(
        report_inbox_service.estado_publico(relato)
    )


# ============================================================ fila do analista
def _com_incidentes(stmt):
    return stmt.options(
        selectinload(IncidentReport.incidents),
        selectinload(IncidentReport.triaged_by),
        selectinload(IncidentReport.duplicate_of),
    )


def _para_leitura(relato: IncidentReport) -> ReportRead:
    """Monta o detalhe, resolvendo o que o esquema não sabe ler do modelo."""
    dados = ReportRead.model_validate(relato).model_dump()
    dados["duplicate_of_reference"] = (
        relato.duplicate_of.reference if relato.duplicate_of else None
    )
    dados["triaged_by_email"] = (
        relato.triaged_by.email if relato.triaged_by else None
    )
    return ReportRead.model_validate(dados)


@inbox_router.get(
    "/canal-de-email",
    summary="Estado do canal de correio electrónico",
    description=(
        "Diz o que está configurado, e **não** contacta o servidor: apresentar o "
        "canal como activo sem o provar é exactamente o que o §4 proíbe. Use "
        "`POST /canal-de-email/testar` para o provar."
    ),
)
async def estado_do_canal_de_email(
    _: Annotated[object, Depends(require(Permission.REPORTS_INBOX_READ))],
) -> dict:
    return email_service.estado_do_canal()


@inbox_router.post(
    "/canal-de-email/testar",
    summary="Testar o envio de correio",
    description=(
        "Envia uma mensagem real para o endereço indicado e devolve o "
        "`Message-ID` que o servidor atribuiu. Um `true` não provaria nada; o "
        "identificador permite encontrar a mensagem no servidor."
    ),
)
async def testar_canal_de_email(
    destino: Annotated[str, Query(min_length=3, max_length=254)],
    _: Annotated[object, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> dict:
    try:
        identificador = await asyncio.to_thread(email_service.testar_envio, destino)
    except email_service.EmailNaoConfigurado as exc:
        raise ValidationError(str(exc), code="CANAL_NAO_CONFIGURADO") from exc
    except Exception as exc:
        # 503 e não 500: o serviço externo falhou, não a plataforma. E a
        # explicação vai no corpo — "erro interno" não diz a ninguém o que
        # corrigir na configuração do servidor de correio.
        raise IntegrationNotAvailableError(
            "Correio electrónico",
            f"o servidor recusou ou não respondeu: {exc}",
        ) from exc
    return {"enviada": True, "para": destino, "message_id": identificador}


@inbox_router.post(
    "/recolher-email",
    summary="Recolher comunicações da caixa de segurança",
    description=(
        "Lê a caixa configurada e cria uma comunicação por mensagem nova. "
        "Devolve o que aconteceu item a item: um número não diria se as "
        "restantes foram duplicados ou falhas. "
        "Duplicados são detectados pelo `Message-ID` — o POP3 não guarda estado "
        "de lida, e uma reentrega criaria uma comunicação nova."
    ),
)
async def recolher_email(
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> dict:
    try:
        return await report_inbox_service.recolher_do_email(session, ctx)
    except email_service.EmailNaoConfigurado as exc:
        raise ValidationError(str(exc), code="CANAL_NAO_CONFIGURADO") from exc
    except Exception as exc:
        raise IntegrationNotAvailableError(
            "Correio electrónico",
            f"a caixa de correio não respondeu: {exc}",
        ) from exc


@inbox_router.get(
    "",
    response_model=Page[ReportListItem],
    summary="Fila de comunicações recebidas",
    description=(
        "Por omissão mostra só o que está por decidir — a lista serve para "
        "trabalhar. `estado` explícito inclui o histórico."
    ),
)
async def list_reports(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_INBOX_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    estado: Annotated[list[ReportStatus] | None, Query()] = None,
    canal: Annotated[list[ReportChannel] | None, Query()] = None,
    q: Annotated[str | None, Query(description="Pesquisa no assunto, referência ou comunicante.")] = None,
    severidade_afirmada: Annotated[list[Severity] | None, Query()] = None,
    categoria_afirmada: Annotated[list[IncidentCategory] | None, Query()] = None,
    desde: Annotated[datetime | None, Query()] = None,
    ate: Annotated[datetime | None, Query()] = None,
) -> Page[ReportListItem]:
    stmt = _com_incidentes(select(IncidentReport))

    if estado:
        stmt = stmt.where(IncidentReport.status.in_(estado))
    else:
        stmt = stmt.where(IncidentReport.status.in_(REPORT_OPEN_STATUSES))
    if canal:
        stmt = stmt.where(IncidentReport.channel.in_(canal))
    if severidade_afirmada:
        stmt = stmt.where(IncidentReport.claimed_severity.in_(severidade_afirmada))
    if categoria_afirmada:
        stmt = stmt.where(IncidentReport.claimed_category.in_(categoria_afirmada))
    if desde:
        stmt = stmt.where(IncidentReport.received_at >= desde)
    if ate:
        stmt = stmt.where(IncidentReport.received_at <= ate)
    if q:
        padrao = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                IncidentReport.reference.ilike(padrao),
                IncidentReport.subject.ilike(padrao),
                IncidentReport.reporter_name.ilike(padrao),
                IncidentReport.reporter_email.ilike(padrao),
                IncidentReport.reporter_organisation.ilike(padrao),
            )
        )

    stmt = apply_sort(
        stmt,
        IncidentReport,
        params.sort,
        allowed={"received_at", "status", "channel", "triaged_at"},
        default="-received_at",
    )
    itens, total = await paginate(session, stmt, params)
    return Page.build(
        [ReportListItem.model_validate(r) for r in itens], total, params
    )


@inbox_router.get(
    "/{report_id}",
    response_model=ReportRead,
    summary="Detalhe de uma comunicação",
)
async def get_report(
    report_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.REPORTS_INBOX_READ))],
) -> ReportRead:
    relato = await report_inbox_service.get_report(session, report_id)
    return _para_leitura(relato)


@inbox_router.post(
    "/{report_id}/triage",
    response_model=ReportRead,
    summary="Assumir a avaliação de uma comunicação",
    description=(
        "Marca-a em avaliação, para que dois analistas não a tratem em paralelo."
    ),
)
async def start_triage(
    report_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[User, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> ReportRead:
    relato = await report_inbox_service.get_report(session, report_id)
    await report_inbox_service.comecar_triagem(
        session, ctx, relato=relato, analista=user
    )
    return _para_leitura(relato)


@inbox_router.post(
    "/{report_id}/accept",
    response_model=ReportRead,
    summary="Aceitar, ligando a um incidente",
    description=(
        "Exige um incidente: ligar a um existente (`incident_id`) ou criar um "
        "novo (`criar_incidente`). Não há terceira via — aceite sem incidente "
        "seria um estado que mente."
    ),
)
async def accept_report(
    report_id: uuid.UUID,
    payload: ReportAccept,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[User, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> ReportRead:
    relato = await report_inbox_service.get_report(session, report_id)
    await report_inbox_service.aceitar(
        session,
        ctx,
        relato=relato,
        analista=user,
        nota=payload.nota,
        incident_id=payload.incident_id,
        criar_incidente=payload.criar_incidente,
        categoria=payload.categoria,
        severidade=payload.severidade,
    )
    return _para_leitura(relato)


@inbox_router.post(
    "/{report_id}/reject",
    response_model=ReportRead,
    summary="Recusar, com justificação obrigatória",
)
async def reject_report(
    report_id: uuid.UUID,
    payload: ReportReject,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[User, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> ReportRead:
    relato = await report_inbox_service.get_report(session, report_id)
    await report_inbox_service.recusar(
        session, ctx, relato=relato, analista=user, nota=payload.nota
    )
    return _para_leitura(relato)


@inbox_router.post(
    "/{report_id}/duplicate",
    response_model=ReportRead,
    summary="Marcar como duplicada de outra",
    description=(
        "Não apaga nem funde: a comunicação continua a existir e quem a fez "
        "continua a poder acompanhá-la."
    ),
)
async def duplicate_report(
    report_id: uuid.UUID,
    payload: ReportDuplicate,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[User, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> ReportRead:
    relato = await report_inbox_service.get_report(session, report_id)
    await report_inbox_service.marcar_duplicada(
        session,
        ctx,
        relato=relato,
        analista=user,
        original_id=payload.original_id,
        nota=payload.nota,
    )
    return _para_leitura(relato)


@inbox_router.post(
    "/{report_id}/incidents",
    response_model=ReportRead,
    summary="Ligar a comunicação a outro incidente",
    description=(
        "A relação é muitos-para-muitos: uma comunicação sobre um incidente que "
        "atinge vários sistemas pode pertencer a mais do que um."
    ),
)
async def link_incident(
    report_id: uuid.UUID,
    payload: ReportLinkIncident,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[User, Depends(require(Permission.REPORTS_INBOX_TRIAGE))],
) -> ReportRead:
    relato = await report_inbox_service.get_report(session, report_id)
    await report_inbox_service.ligar_incidente(
        session, ctx, relato=relato, incident_id=payload.incident_id
    )
    return _para_leitura(relato)
