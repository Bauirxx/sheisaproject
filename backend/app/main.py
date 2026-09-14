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
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
)
logger = logging.getLogger("sheisa")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "SHEISA a arrancar (ambiente=%s, base de dados=%s)",
        settings.environment,
        settings.effective_database_url.rsplit("@", 1)[-1],
    )
    settings.evidence_storage_path.mkdir(parents=True, exist_ok=True)
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

# A ordem importa: o identificador de pedido tem de ser atribuído primeiro para
# ficar disponível a tudo o que vem depois, incluindo as respostas de erro.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestIdMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-Id"],
    expose_headers=["X-Request-Id"],
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
from app.api.v1 import auth as auth_routes  # noqa: E402
from app.api.v1 import ingest as ingest_routes  # noqa: E402

app.include_router(auth_routes.router, prefix=settings.api_prefix)
app.include_router(ingest_routes.router, prefix=settings.api_prefix)
