"""Ponto de entrada da API SHEISA."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.database import dispose_engine
from app.core.errors import SheisaError
from app.core.middleware import (
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
    TempoDeRespostaMiddleware,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
)
logger = logging.getLogger("sheisa")


async def _verificar_as_permissoes_da_base() -> None:
    """Avisa, ao arrancar, se a base não tem permissões que as rotas exigem.

    As rotas verificam as permissões guardadas na base de dados; uma que só
    exista no código faz a rota responder 403 a todos os perfis, sem que nada no
    código esteja errado. Aconteceu a correr, em 2026-09-28, à caixa de
    comunicações — e a única pista era o 403, que é indistinguível de "este
    perfil não tem essa permissão".

    A verificação não pode impedir a API de arrancar: se a base não responder, o
    arranque diz que não conseguiu verificar em vez de afirmar que está bem.
    """
    from sqlalchemy.exc import SQLAlchemyError

    from app.core.database import get_sessionmaker
    from app.services import bootstrap

    try:
        async with get_sessionmaker()() as sessao:
            await bootstrap.avisar_de_permissoes_em_falta(sessao)
    except (SQLAlchemyError, OSError):
        # A base não responder é o caso previsto: dizer que não se verificou, e
        # deixar a API arrancar. Qualquer outra excepção passa, porque aí o
        # problema não é este e calá-lo esconderia-o.
        logger.warning(
            "Nao foi possivel verificar as permissoes na base de dados.", exc_info=True
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "SHEISA a arrancar (ambiente=%s, base de dados=%s)",
        settings.environment,
        settings.effective_database_url.rsplit("@", 1)[-1],
    )
    settings.evidence_storage_path.mkdir(parents=True, exist_ok=True)
    await _verificar_as_permissoes_da_base()
    yield
    await dispose_engine()
    logger.info("SHEISA encerrada.")


DESCRIPTION = """
Plataforma de gestão e resposta a incidentes cibernéticos.

A API segue o percurso operacional **evento → alerta → observação → incidente →
acção → resultado**. Todos os dados devolvidos provêm da base de dados ou de
integrações efectivamente configuradas: nenhum endpoint devolve valores
simulados.

**Autenticação.** A maioria dos endpoints exige um token de acesso
(`Authorization: Bearer <token>`), obtido em `POST /api/auth/login`. A ingestão
de eventos usa antes uma chave de API no cabeçalho `X-API-Key`.

**Autorização.** Cada endpoint declara as permissões exigidas. A verificação é
feita no servidor contra o perfil actual do utilizador; esconder funcionalidades
no frontend não substitui esta verificação.
"""

app = FastAPI(
    title=settings.app_title,
    version="1.0.0",
    description=DESCRIPTION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    contact={"name": "SHEISA"},
)

#: Só é `True` quando a aplicação está atrás de um proxy inverso de confiança.
app.state.trust_proxy_headers = False

# A ordem importa, e o último acrescentado é o mais exterior. O identificador de
# pedido é atribuído primeiro, para ficar disponível a tudo o que vem depois. A
# limitação de taxa fica por dentro dos cabeçalhos de segurança: estava por fora,
# e o 429 que ela devolve saía sem nenhum deles.
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
# A medição fica por dentro do identificador de pedido, para poder citá-lo ao
# registar um pedido lento, e por fora de tudo o resto, para que o tempo inclua
# a limitação de taxa e a serialização da resposta.
app.add_middleware(TempoDeRespostaMiddleware)
app.add_middleware(RequestIdMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-Id"],
    # Sem estar exposto, um cabeçalho de resposta é invisível ao JavaScript do
    # navegador, mesmo chegando na resposta: medir e não conseguir ler a medição
    # seria o mesmo que não medir.
    expose_headers=["X-Request-Id", "X-Tempo-Resposta-ms"],
    max_age=600,
)


# --------------------------------------------------------- tratamento de erros
@app.exception_handler(SheisaError)
async def _handle_sheisa_error(request: Request, exc: SheisaError) -> JSONResponse:
    headers = {}
    if retry_after := getattr(exc, "retry_after", None):
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        status_code=exc.status_code, content=exc.to_payload(), headers=headers
    )


@app.exception_handler(RequestValidationError)
async def _handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Traduz os erros de validação do Pydantic para o formato da aplicação."""
    campos = [
        {
            "campo": ".".join(str(p) for p in err["loc"][1:]) or str(err["loc"][0]),
            "problema": err["msg"],
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "erro": {
                "codigo": "VALIDACAO",
                "mensagem": "Os dados enviados são inválidos.",
                "detalhes": {"campos": campos},
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def _handle_http_exception(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "erro": {
                "codigo": f"HTTP_{exc.status_code}",
                "mensagem": str(exc.detail),
            }
        },
    )


@app.exception_handler(Exception)
async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    """Erro não previsto.

    A mensagem devolvida é genérica de propósito: uma excepção pode conter
    fragmentos de consultas ou caminhos do sistema. O detalhe fica no log do
    servidor, ligado ao pedido pelo `X-Request-Id`.
    """
    request_id = getattr(request.state, "request_id", "?")
    logger.exception("Erro não tratado (request_id=%s)", request_id)
    return JSONResponse(
        status_code=500,
        content={
            "erro": {
                "codigo": "ERRO_INTERNO",
                "mensagem": "Ocorreu um erro interno. Contacte o administrador.",
                "detalhes": {"request_id": request_id},
            }
        },
    )


# ----------------------------------------------------------------- diagnóstico
@app.get("/api/health", tags=["Diagnóstico"], summary="Estado da aplicação")
async def health() -> dict:
    """Verificação de vida do processo. Não toca na base de dados."""
    return {"estado": "operacional", "versao": app.version, "ambiente": settings.environment}


@app.get("/api/health/ready", tags=["Diagnóstico"], summary="Prontidão (com base de dados)")
async def readiness() -> JSONResponse:
    """Confirma que a base de dados responde.

    Distinta de `/api/health`: um processo vivo com base de dados inacessível
    não está pronto a servir, e reportar o contrário esconderia a avaria.
    """
    from sqlalchemy import text

    from app.core.database import get_sessionmaker

    try:
        factory = get_sessionmaker()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        return JSONResponse({"estado": "pronto", "base_dados": "acessivel"})
    except Exception as exc:  # noqa: BLE001 - queremos reportar qualquer falha
        logger.error("Verificação de prontidão falhou: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"estado": "indisponivel", "base_dados": "inacessivel"},
        )


# ---------------------------------------------------------------------- rotas
from app.api.v1 import admin as admin_routes  # noqa: E402
from app.api.v1 import alerts as alert_routes  # noqa: E402
from app.api.v1 import analytics as analytics_routes  # noqa: E402
from app.api.v1 import auth as auth_routes  # noqa: E402
from app.api.v1 import catalog as catalog_routes  # noqa: E402
from app.api.v1 import incidents as incident_routes  # noqa: E402
from app.api.v1 import ingest as ingest_routes  # noqa: E402
from app.api.v1 import investigation as investigation_routes  # noqa: E402
from app.api.v1 import recommendations as recommendation_routes  # noqa: E402
from app.api.v1 import reporting as reporting_routes  # noqa: E402
from app.api.v1 import reports as report_routes  # noqa: E402
from app.api.v1 import response as response_routes  # noqa: E402

for _router in (
    auth_routes.router,
    ingest_routes.router,
    alert_routes.router,
    alert_routes.events_router,
    incident_routes.router,
    investigation_routes.evidence_router,
    investigation_routes.task_router,
    catalog_routes.asset_router,
    catalog_routes.ioc_router,
    catalog_routes.mitre_router,
    response_routes.action_router,
    response_routes.approval_router,
    response_routes.playbook_router,
    analytics_routes.dashboard_router,
    analytics_routes.soc_router,
    analytics_routes.graph_router,
    recommendation_routes.router,
    report_routes.router,
    admin_routes.user_router,
    admin_routes.role_router,
    admin_routes.team_router,
    admin_routes.audit_router,
    admin_routes.integration_router,
    admin_routes.notification_router,
    # O portal externo vai por último para deixar claro, ao ler a lista, que é
    # o único encaminhador sem autenticação.
    reporting_routes.inbox_router,
    reporting_routes.public_router,
):
    app.include_router(_router, prefix=settings.api_prefix)
