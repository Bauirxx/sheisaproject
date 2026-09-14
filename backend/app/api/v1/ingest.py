"""Endpoints de ingestão — /api/ingest.

Autenticados por chave de API (`X-API-Key`) e não por sessão de utilizador: o
emissor é uma máquina, não uma pessoa. Cada chave está ligada a uma integração,
o que torna a origem de qualquer evento atribuível e revogável isoladamente.

O corpo aceita um objecto ou uma lista de objectos, porque o `integrator` do
Wazuh envia um alerta de cada vez enquanto uma recolha de `eve.json` do
Suricata envia lotes.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Header, Request, status
from pydantic import BaseModel, Field

from app.core.deps import SessionDep, authenticate_api_key, get_audit_context
from app.core.enums import SourceKind
from app.core.errors import ValidationError
from app.services import ingestion_service, integration_service

router = APIRouter(prefix="/ingest", tags=["Ingestão"])

#: Limite de elementos por lote. Protege contra um corpo que esgote a memória
#: do processo; lotes maiores devem ser divididos pelo emissor.
MAX_BATCH = 500


class IngestionResponse(BaseModel):
    recebidos: int = Field(description="Número de sinais recebidos no pedido.")
    processados: int = Field(description="Número de sinais efectivamente processados.")
    resultados: list[dict[str, Any]]


async def _handle(
    request: Request,
    session: SessionDep,
    api_key_value: str | None,
    payload: Any,
    source_kind: SourceKind | None,
) -> IngestionResponse:
    api_key = await authenticate_api_key(request, session, api_key_value)
    ctx = get_audit_context(request)

    # A fonte declarada pela chave prevalece sobre a inferida do payload: é a
    # chave que estabelece confiança sobre a origem.
    integration = None
    if api_key.integration_id is not None:
        integration = await integration_service.get_integration(
            session, api_key.integration_id
        )
        if source_kind is None:
            source_kind = integration.kind

    if isinstance(payload, dict):
        payloads = [payload]
    elif isinstance(payload, list):
        payloads = payload
    else:
        raise ValidationError("O corpo deve ser um objecto JSON ou uma lista de objectos.")

    if not payloads:
        raise ValidationError("Nenhum sinal recebido.")
    if len(payloads) > MAX_BATCH:
        raise ValidationError(
            f"Lote demasiado grande ({len(payloads)}). Máximo: {MAX_BATCH}.",
            details={"maximo": MAX_BATCH},
        )
    if not all(isinstance(item, dict) for item in payloads):
        raise ValidationError("Todos os elementos do lote devem ser objectos JSON.")

    results = await ingestion_service.ingest_batch(
        session,
        ctx,
        payloads,
        source_name=api_key.name,
        source_kind=source_kind,
        integration_id=api_key.integration_id,
    )

    for _ in results:
        await integration_service.record_ingestion(session, api_key.integration_id)

    return IngestionResponse(
        recebidos=len(payloads),
        processados=len(results),
        resultados=[r.to_dict() for r in results],
    )


@router.post(
    "/wazuh",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receber alertas do Wazuh",
    description=(
        "Destino do script `custom-sheisa` do daemon *integrator* do Wazuh. "
        "Aceita o alerta JSON tal como o Wazuh o produz, com `rule`, `agent` e "
        "`data`. Reenvios do mesmo alerta são reconhecidos e ignorados."
    ),
)
async def ingest_wazuh(
    request: Request,
    session: SessionDep,
    payload: Annotated[Any, Body()],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> IngestionResponse:
    return await _handle(request, session, x_api_key, payload, SourceKind.WAZUH)


@router.post(
    "/suricata",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receber eventos EVE JSON do Suricata",
    description=(
        "Aceita registos `eve.json`. Apenas os de `event_type: alert` produzem "
        "alertas; os restantes são normalizados de forma genérica."
    ),
)
async def ingest_suricata(
    request: Request,
    session: SessionDep,
    payload: Annotated[Any, Body()],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> IngestionResponse:
    return await _handle(request, session, x_api_key, payload, SourceKind.SURICATA)


@router.post(
    "/events",
    response_model=IngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receber eventos de qualquer fonte",
    description=(
        "Endpoint genérico. A fonte é determinada pela chave de API utilizada; "
        "se a chave não a declarar, é inferida da forma do payload. Aceita os "
        "nomes de campo mais comuns (`src_ip`, `srcip`, `source_ip`, ...)."
    ),
)
async def ingest_generic(
    request: Request,
    session: SessionDep,
    payload: Annotated[Any, Body()],
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> IngestionResponse:
    return await _handle(request, session, x_api_key, payload, None)
