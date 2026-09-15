"""Painel, centro de operações e grafo — /api/dashboard, /api/soc, /api/graph."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.deps import SessionDep, require
from app.core.permissions import Permission
from app.services import analytics_service, incident_service

dashboard_router = APIRouter(prefix="/dashboard", tags=["Painel"])
soc_router = APIRouter(prefix="/soc", tags=["Centro de Operações"])
graph_router = APIRouter(prefix="/graph", tags=["Grafo investigativo"])


@dashboard_router.get(
    "",
    summary="Indicadores do painel",
    description=(
        "Todos os valores são contados na base de dados no momento do pedido. "
        "Não existem números pré-calculados nem em cache."
    ),
)
async def overview(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.DASHBOARD_READ))],
    dias: Annotated[int, Query(ge=1, le=365, description="Janela de análise.")] = 30,
) -> dict:
    return await analytics_service.dashboard_overview(session, days=dias)


@dashboard_router.get(
    "/distribution",
    summary="Distribuições por severidade, categoria, estado e fonte",
)
async def distribution(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.DASHBOARD_READ))],
    dias: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict:
    return await analytics_service.distribution(session, days=dias)


@dashboard_router.get(
    "/response-metrics",
    summary="Tempos médios de reconhecimento e resolução",
    description=(
        "Calculados a partir dos marcos temporais reais. Incidentes sem o "
        "marco correspondente ficam de fora da média, em vez de contarem como "
        "zero e a baixarem artificialmente."
    ),
)
async def response_metrics(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.DASHBOARD_READ))],
    dias: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict:
    return await analytics_service.response_metrics(session, days=dias)


@dashboard_router.get("/trend", summary="Tendência diária de incidentes e alertas")
async def trend(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.DASHBOARD_READ))],
    dias: Annotated[int, Query(ge=1, le=180)] = 30,
) -> list[dict]:
    return await analytics_service.trend(session, days=dias)


@dashboard_router.get("/workload", summary="Carga por analista")
async def workload(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.DASHBOARD_READ))],
) -> list[dict]:
    return await analytics_service.analyst_workload(session)


@soc_router.get(
    "",
    summary="Vista do centro de operações",
    description=(
        "Reúne numa só resposta os incidentes activos, os alertas por triar, "
        "as aprovações pendentes, os playbooks em execução, os indicadores mais "
        "frequentes, os activos afectados e as tarefas em aberto."
    ),
)
async def soc_overview(
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.DASHBOARD_READ))],
    limite: Annotated[int, Query(ge=1, le=50)] = 10,
) -> dict:
    return await analytics_service.soc_center(session, limit=limite)


@graph_router.get(
    "/incident/{incident_id}",
    summary="Grafo investigativo de um incidente",
    description=(
        "Nós: incidentes, indicadores, activos e alertas. As arestas "
        "transportam o papel do artefacto (origem, destino, alvo), o que "
        "permite distinguir o lado do atacante do lado da vítima. "
        "Com profundidade 2 juntam-se os incidentes que partilham indicadores "
        "— é assim que uma campanha se torna visível sem perder o contexto."
    ),
)
async def incident_graph(
    incident_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.INCIDENTS_READ))],
    profundidade: Annotated[int, Query(ge=1, le=3)] = 1,
) -> dict:
    await incident_service.get_incident(session, incident_id)
    return await analytics_service.investigation_graph(
        session, incident_id=incident_id, depth=profundidade
    )


@graph_router.get(
    "/ioc/{ioc_id}",
    summary="Grafo centrado num indicador",
    description=(
        "Mostra em que incidentes o indicador foi observado e com que outros "
        "indicadores coocorre."
    ),
)
async def ioc_graph(
    ioc_id: uuid.UUID,
    session: SessionDep,
    _: Annotated[object, Depends(require(Permission.IOCS_READ))],
) -> dict:
    return await analytics_service.ioc_graph(session, ioc_id=ioc_id)
