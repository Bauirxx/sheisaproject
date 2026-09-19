"""Recomendações do motor de inteligência — /api/recommendations (§12)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.deps import AuditDep, SessionDep, require
from app.core.enums import RecommendationKind, RecommendationStatus
from app.core.errors import ConflictError
from app.core.pagination import Page, PageParams, apply_sort, page_params, paginate
from app.core.permissions import Permission
from app.intelligence import recommendations as engine
from app.models.incident import Incident
from app.models.intelligence import Recommendation
from app.models.telemetry import Alert
from app.schemas.response import (
    RecommendationDecide,
    RecommendationDecision,
    RecommendationRead,
    RecommendationSyncResult,
)
from app.services import recommendation_service

router = APIRouter(prefix="/recommendations", tags=["Recomendações"])


@router.get(
    "",
    response_model=Page[RecommendationRead],
    summary="Listar recomendações",
    description=(
        "Fila de recomendações do motor determinístico. Cada entrada traz a "
        "decomposição por factor, a confiança calculada a partir dessa "
        "decomposição e os registos que a sustentam — não há pontuações sem "
        "explicação."
    ),
)
async def list_recommendations(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_READ))],
    params: Annotated[PageParams, Depends(page_params)],
    estado: Annotated[RecommendationStatus | None, Query(description="Filtrar por estado.")] = None,
    tipo: Annotated[RecommendationKind | None, Query(description="Filtrar por tipo.")] = None,
    # Os dois valores possíveis, e não texto livre: com texto livre,
    # `alvo=incidente` devolvia uma fila vazia e parecia não haver nada a decidir.
    alvo: Annotated[
        Literal["alert", "incident"] | None,
        Query(description="Tipo de alvo: 'alert' ou 'incident'."),
    ] = None,
    alvo_id: Annotated[uuid.UUID | None, Query(description="Identificador do alvo.")] = None,
    confianca_minima: Annotated[int | None, Query(ge=0, le=100)] = None,
) -> Page[RecommendationRead]:
    stmt = select(Recommendation)

    # Por omissão só interessa o que está por decidir: a lista serve para
    # trabalhar, não para consultar histórico.
    pedido = estado if estado is not None else RecommendationStatus.PENDENTE
    stmt = stmt.where(Recommendation.status == pedido)

    if pedido is RecommendationStatus.PENDENTE:
        # Estar por decidir exclui o que já venceu. `status` é uma
        # denormalização: a coluna só passa a EXPIRADA quando alguém recalcula,
        # pelo que o facto autoritativo é `expires_at`. Confiar na coluna
        # deixaria a fila a oferecer propostas caducadas até ao varrimento
        # seguinte — e a filtrar aqui, `?estado=PENDENTE` explícito tem de dar o
        # mesmo que a omissão, senão passar o filtro à mão contornava a regra.
        #
        # O instante é calculado em Python de propósito. O `now()` do PostgreSQL
        # é o do início da transacção, e usá-lo faria a fronteira depender de
        # quando o pedido começou em vez de quando a pergunta é feita.
        stmt = stmt.where(
            or_(
                Recommendation.expires_at.is_(None),
                Recommendation.expires_at > datetime.now(UTC),
            )
        )
    if tipo is not None:
        stmt = stmt.where(Recommendation.kind == tipo)
    if alvo is not None:
        stmt = stmt.where(Recommendation.target_type == alvo)
    if alvo_id is not None:
        stmt = stmt.where(Recommendation.target_id == alvo_id)
    if confianca_minima is not None:
        stmt = stmt.where(Recommendation.confidence >= confianca_minima)

    stmt = apply_sort(
        stmt,
        Recommendation,
        params.sort,
        allowed={"created_at", "confidence", "kind", "status"},
        default="-confidence",
    )
    itens, total = await paginate(session, stmt, params)
    return Page.build([RecommendationRead.model_validate(r) for r in itens], total, params)


@router.get(
    "/{recommendation_id}",
    response_model=RecommendationRead,
    summary="Detalhe de uma recomendação",
)
async def get_recommendation(
    recommendation_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_READ))],
) -> RecommendationRead:
    rec = await recommendation_service.get_recommendation(session, recommendation_id)
    return RecommendationRead.model_validate(rec)


@router.post(
    "/{recommendation_id}/decide",
    response_model=RecommendationDecision,
    summary="Aceitar ou rejeitar uma recomendação",
    description=(
        "Aceitar aplica a alteração proposta, se existir e se quem decide "
        "tiver a permissão que essa operação exigiria feita à mão — aceitar "
        "uma recomendação nunca é atalho para o que o perfil não permite. A "
        "resposta diz sempre o que aconteceu de facto ao alvo."
    ),
)
async def decide_recommendation(
    recommendation_id: uuid.UUID,
    payload: RecommendationDecide,
    session: SessionDep,
    ctx: AuditDep,
    user: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_DECIDE))],
) -> RecommendationDecision:
    rec = await recommendation_service.get_recommendation(session, recommendation_id)
    rec, efeito = await recommendation_service.decidir(
        session,
        ctx,
        rec=rec,
        decisor=user,
        aceitar=payload.accept,
        nota=payload.note,
        aplicar_alteracao=payload.aplicar_alteracao,
    )
    return RecommendationDecision(
        recomendacao=RecommendationRead.model_validate(rec), efeito=efeito
    )


@router.post(
    "/generate",
    response_model=RecommendationSyncResult,
    summary="Recalcular as recomendações do trabalho em aberto",
    description=(
        "Corre o motor sobre os alertas por triar e os incidentes não "
        "encerrados. É idempotente: recomendações pendentes são actualizadas, "
        "as que deixaram de se justificar são retiradas, e uma proposta já "
        "recusada não volta a ser levantada."
    ),
)
async def generate(
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_DECIDE))],
    limite: Annotated[int, Query(ge=1, le=500, description="Registos por tipo.")] = 200,
) -> RecommendationSyncResult:
    try:
        resumo = await recommendation_service.sincronizar_em_aberto(session, limite=limite)
    except IntegrityError as exc:
        # O índice único parcial da migração 0004 impede duas gerações
        # concorrentes de criarem a mesma recomendação pendente. Traduzido
        # para 409 em vez de deixar sair um 500 sem explicação.
        await session.rollback()
        raise ConflictError(
            "Já está a decorrer outra geração de recomendações. Tente novamente.",
            code="GERACAO_CONCORRENTE",
        ) from exc

    await audit.record(
        session,
        ctx,
        action="GERAR_RECOMENDACOES",
        resource_type="recomendacao",
        description=(
            f"Motor {resumo['motor']} v{resumo['versao']}: "
            f"{resumo['recomendacoes_de_alertas']} sobre alertas, "
            f"{resumo['recomendacoes_de_incidentes']} sobre incidentes, "
            f"{resumo['retiradas_ou_expiradas']} retirada(s) ou expirada(s)."
        ),
        new_value=resumo,
    )
    return RecommendationSyncResult(**resumo)


@router.post(
    "/alerts/{alert_id}/generate",
    response_model=list[RecommendationRead],
    summary="Recalcular as recomendações de um alerta",
)
async def generate_for_alert(
    alert_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_DECIDE))],
) -> list[RecommendationRead]:
    from app.core.errors import NotFoundError

    alerta = await session.get(Alert, alert_id)
    if alerta is None:
        raise NotFoundError("Alerta", alert_id)
    vigentes, retiradas = await recommendation_service.sincronizar_alerta(session, alerta)
    await _auditar_recalculo(session, ctx, "alerta", alerta.id, alerta.reference,
                             len(vigentes), retiradas)
    return [RecommendationRead.model_validate(r) for r in vigentes]


@router.post(
    "/incidents/{incident_id}/generate",
    response_model=list[RecommendationRead],
    summary="Recalcular as recomendações de um incidente",
)
async def generate_for_incident(
    incident_id: uuid.UUID,
    session: SessionDep,
    ctx: AuditDep,
    _: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_DECIDE))],
) -> list[RecommendationRead]:
    from app.core.errors import NotFoundError

    incidente = await session.get(Incident, incident_id)
    if incidente is None:
        raise NotFoundError("Incidente", incident_id)
    vigentes, retiradas = await recommendation_service.sincronizar_incidente(
        session, incidente
    )
    await _auditar_recalculo(session, ctx, "incidente", incidente.id, incidente.reference,
                             len(vigentes), retiradas)
    return [RecommendationRead.model_validate(r) for r in vigentes]


async def _auditar_recalculo(
    session: AsyncSession, ctx: AuditContext, resource_type: str,
    resource_id: uuid.UUID, reference: str,
    vigentes: int, retiradas: int,
) -> None:
    """Regista o recálculo de um só alvo, como já se registava o global.

    Um recálculo cria e retira recomendações, e uma recomendação retirada
    desaparece da fila de quem decide — isso não pode acontecer sem rasto.
    """
    await audit.record(
        session, ctx,
        action="GERAR_RECOMENDACOES", resource_type=resource_type,
        resource_id=resource_id, resource_reference=reference,
        description=(
            f"Recomendações de {reference} recalculadas: {vigentes} vigente(s), "
            f"{retiradas} retirada(s) ou expirada(s)."
        ),
        new_value={"vigentes": vigentes, "retiradas_ou_expiradas": retiradas},
    )


@router.get(
    "/meta/tipos",
    response_model=dict,
    summary="Tipos de recomendação e limiares do motor",
    description=(
        "Os valores que governam o motor, expostos para que a interface possa "
        "explicá-los ao analista em vez de os repetir por sua conta."
    ),
)
async def meta(
    _: Annotated[object, Depends(require(Permission.RECOMMENDATIONS_READ))],
) -> dict:
    return {
        "motor": engine.ENGINE_NAME,
        "versao": engine.ENGINE_VERSION,
        "tipos": recommendation_service.kinds_disponiveis(),
        "estados": [e.value for e in RecommendationStatus],
        "limiares": {
            "confianca_minima_para_levantar": engine.MIN_CONFIDENCE_TO_RAISE,
            "confianca_maxima_de_inferencia": engine.MAX_CONFIDENCE_INFERENCIA,
            "taxa_de_falso_positivo": engine.FP_RATE_THRESHOLD,
            "pontuacao_minima_para_promover": engine.PROMOTE_SCORE_THRESHOLD,
            "validade_por_omissao_em_dias": engine.DEFAULT_TTL_DAYS,
        },
    }
