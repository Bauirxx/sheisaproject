"""Middlewares transversais (§23).

Inclui identificação de pedidos, limitação de taxa e cabeçalhos de segurança.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Atribui um identificador único a cada pedido.

    O identificador entra no registo de auditoria e é devolvido no cabeçalho
    `X-Request-Id`, permitindo ligar o que o utilizador viu ao que ficou
    registado no servidor — indispensável quando se investiga um incidente na
    própria plataforma.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        incoming = request.headers.get("x-request-id")
        # Um identificador vindo do cliente só é aceite se for um UUID válido,
        # para que não possa injectar conteúdo arbitrário na auditoria.
        try:
            request_id = str(uuid.UUID(incoming)) if incoming else str(uuid.uuid4())
        except ValueError:
            request_id = str(uuid.uuid4())

        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Cabeçalhos de segurança nas respostas da API."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Cache-Control", "no-store, no-cache, must-revalidate, private"
        )
        # A API só devolve JSON e ficheiros de evidência; uma CSP restritiva
        # impede que um payload malicioso guardado em texto seja interpretado
        # como conteúdo activo caso alguém abra uma resposta directamente.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class _SlidingWindow:
    """Janela deslizante em memória.

    Limitação assumida: o estado é por processo. Com vários trabalhadores
    uvicorn o limite efectivo multiplica-se pelo número de processos. Para uma
    implantação distribuída este armazenamento deve passar para Redis — a
    interface (`hit`) foi mantida estreita precisamente para tornar essa troca
    trivial. Documentado em vez de silenciado (§34).
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        """Regista um acesso. Devolve (permitido, segundos até poder repetir)."""
        now = time.monotonic()
        cutoff = now - window_seconds
        bucket = self._hits[key]

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = max(1, int(bucket[0] + window_seconds - now) + 1)
            return False, retry_after

        bucket.append(now)
        return True, 0

    def reset(self) -> None:
        self._hits.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Limitação de taxa por identidade e classe de rota.

    Os limites são diferenciados por classe porque as necessidades são
    opostas: a autenticação tem de ser restritiva (travar força bruta) e a
    ingestão tem de ser permissiva (um SOC recebe milhares de alertas).
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self._window = _SlidingWindow()

    def _classify(self, path: str) -> tuple[str, int]:
        if "/auth/login" in path or "/auth/refresh" in path:
            return "auth", settings.rate_limit_auth_per_minute
        if "/ingest" in path:
            return "ingest", settings.rate_limit_ingest_per_minute
        return "default", settings.rate_limit_default_per_minute

    def _identity(self, request: Request, klass: str) -> str:
        # Na ingestão, a chave de API identifica a fonte melhor do que o IP:
        # várias fontes podem partilhar o mesmo IP de saída. **Só na ingestão**,
        # que é onde a chave é validada. Noutras rotas o cabeçalho é texto livre
        # do cliente: usado como identidade no login, bastava mudá-lo em cada
        # tentativa para ter um balde novo e anular o limite contra força bruta.
        auth = request.headers.get("x-api-key")
        if klass == "ingest" and auth:
            return f"apikey:{auth[:8]}"
        client = request.client.host if request.client else "desconhecido"
        return f"ip:{client}"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not settings.rate_limit_enabled:
            return await call_next(request)

        klass, limit = self._classify(request.url.path)
        key = f"{klass}:{self._identity(request, klass)}"
        allowed, retry_after = self._window.hit(key, limit)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "erro": {
                        "codigo": "DEMASIADOS_PEDIDOS",
                        "mensagem": (
                            "Demasiados pedidos. Tente novamente dentro de instantes."
                        ),
                        "detalhes": {"repetir_apos_segundos": retry_after},
                    }
                },
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
