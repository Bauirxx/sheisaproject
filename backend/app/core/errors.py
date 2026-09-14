"""Erros da aplicação e respectivo tratamento (§27).

Todas as respostas de erro partilham o mesmo formato, para que o frontend tenha
um único caminho de tratamento:

    {"erro": {"codigo": "TRANSICAO_INVALIDA", "mensagem": "...", "detalhes": {...}}}

O `codigo` é estável e destina-se a ser interpretado por código; a `mensagem` é
em português e destina-se a ser lida por pessoas.
"""

from __future__ import annotations

from typing import Any

from fastapi import status


class SheisaError(Exception):
    """Erro base da aplicação."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    code: str = "ERRO"
    message: str = "Ocorreu um erro."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        status_code: int | None = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.details = details or {}
        if status_code is not None:
            self.status_code = status_code
        super().__init__(self.message)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"codigo": self.code, "mensagem": self.message}
        if self.details:
            payload["detalhes"] = self.details
        return {"erro": payload}


# ------------------------------------------------------------ autenticação
class AuthenticationError(SheisaError):
    status_code = status.HTTP_401_UNAUTHORIZED
    code = "NAO_AUTENTICADO"
    message = "Credenciais inválidas ou sessão expirada."


class InvalidCredentialsError(AuthenticationError):
    code = "CREDENCIAIS_INVALIDAS"
    message = "Endereço de correio electrónico ou palavra-passe incorrectos."


class AccountLockedError(AuthenticationError):
    code = "CONTA_BLOQUEADA"
    message = "Conta temporariamente bloqueada por tentativas de acesso falhadas."


class AccountInactiveError(AuthenticationError):
    code = "CONTA_INACTIVA"
    message = "Esta conta está desactivada."


class SessionExpiredError(AuthenticationError):
    code = "SESSAO_EXPIRADA"
    message = "A sessão expirou. Inicie sessão novamente."


# ------------------------------------------------------------- autorização
class AuthorizationError(SheisaError):
    status_code = status.HTTP_403_FORBIDDEN
    code = "SEM_PERMISSAO"
    message = "Não tem permissão para executar esta operação."

    def __init__(self, required: str | None = None, **kwargs: Any) -> None:
        details = kwargs.pop("details", {}) or {}
        if required:
            details["permissao_necessaria"] = required
        super().__init__(details=details, **kwargs)


# ----------------------------------------------------------------- domínio
class NotFoundError(SheisaError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "NAO_ENCONTRADO"
    message = "Recurso não encontrado."

    def __init__(self, resource: str = "Recurso", identifier: Any = None, **kwargs: Any) -> None:
        msg = f"{resource} não encontrado."
        details = kwargs.pop("details", {}) or {}
        if identifier is not None:
            details["identificador"] = str(identifier)
        super().__init__(msg, details=details, **kwargs)


class ConflictError(SheisaError):
    status_code = status.HTTP_409_CONFLICT
    code = "CONFLITO"
    message = "A operação entra em conflito com o estado actual do recurso."


class ValidationError(SheisaError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    code = "VALIDACAO"
    message = "Os dados fornecidos são inválidos."


class InvalidTransitionError(ConflictError):
    """Transição de estado não permitida pelo ciclo de vida configurado."""

    code = "TRANSICAO_INVALIDA"

    def __init__(self, current: str, requested: str, allowed: list[str]) -> None:
        super().__init__(
            f"Não é possível passar de {current} para {requested}.",
            details={
                "estado_actual": current,
                "estado_pedido": requested,
                "transicoes_permitidas": sorted(allowed),
            },
        )


class ApprovalRequiredError(SheisaError):
    """A acção exige aprovação humana antes de ser executada (§13)."""

    status_code = status.HTTP_409_CONFLICT
    code = "APROVACAO_NECESSARIA"
    message = "Esta acção requer aprovação antes de ser executada."


class IntegrationNotAvailableError(SheisaError):
    """A integração necessária não está configurada ou verificada.

    Deliberadamente um erro e não um sucesso simulado: o §4 proíbe apresentar
    uma integração inactiva como se estivesse a funcionar.
    """

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "INTEGRACAO_INDISPONIVEL"
    message = "A integração necessária não está configurada ou activa."

    def __init__(self, name: str, reason: str | None = None) -> None:
        super().__init__(
            f"A integração '{name}' não está disponível.",
            details={"integracao": name, "motivo": reason or "não configurada"},
        )


class FeatureNotAvailableError(SheisaError):
    """Funcionalidade cujo suporte opcional não está instalado."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    code = "FUNCIONALIDADE_INDISPONIVEL"
    message = "Esta funcionalidade não está disponível nesta instalação."


class RateLimitError(SheisaError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "DEMASIADOS_PEDIDOS"
    message = "Demasiados pedidos. Tente novamente dentro de instantes."

    def __init__(self, retry_after: int) -> None:
        super().__init__(details={"repetir_apos_segundos": retry_after})
        self.retry_after = retry_after


class PayloadTooLargeError(SheisaError):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    code = "FICHEIRO_DEMASIADO_GRANDE"
    message = "O ficheiro excede o tamanho máximo permitido."
