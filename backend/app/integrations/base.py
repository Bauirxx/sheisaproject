"""Contrato dos conectores para sistemas externos (§24, §26).

Um conector sabe duas coisas: como confirmar que consegue falar com o serviço
(`test_connection`) e, quando aplicável, como executar acções de resposta
(`execute_action`).

Regra que este módulo impõe: **nenhum conector devolve sucesso sem ter recebido
resposta do serviço.** Não existe um modo "simulado" que devolva `True`. Se o
serviço não estiver alcançável, a chamada levanta excepção e a acção fica
registada como falhada — é isso que o §4 exige.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

import httpx

from app.core.enums import ActionKind, SourceKind
from app.core.errors import IntegrationNotAvailableError
from app.models.system import Integration

#: Tempo limite das chamadas a serviços externos. Uma acção de resposta que
#: demore mais do que isto deve falhar de forma visível em vez de bloquear o
#: analista sem explicação.
DEFAULT_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


class ActionResult:
    """Resultado de uma acção executada através de um conector."""

    def __init__(
        self,
        *,
        success: bool,
        detail: str,
        raw_response: dict[str, Any] | None = None,
        reversible: bool = False,
    ) -> None:
        self.success = success
        self.detail = detail
        self.raw_response = raw_response or {}
        self.reversible = reversible

    def as_dict(self) -> dict[str, Any]:
        return {
            "sucesso": self.success,
            "detalhe": self.detail,
            "resposta": self.raw_response,
            "reversivel": self.reversible,
        }


class Connector(Protocol):
    """Contrato mínimo de um conector."""

    kind: SourceKind
    supported_actions: tuple[ActionKind, ...]

    async def test_connection(self, integration: Integration) -> str:
        """Confirma a ligação. Devolve descrição do que foi verificado.

        Levanta excepção se não conseguir contactar o serviço.
        """
        ...

    async def execute_action(
        self, integration: Integration, action_kind: ActionKind, target: dict, parameters: dict
    ) -> ActionResult:
        """Executa uma acção de resposta."""
        ...


class BaseConnector:
    """Funcionalidade comum aos conectores HTTP."""

    kind: SourceKind
    supported_actions: tuple[ActionKind, ...] = ()

    #: Se o conector suporta importar sinais (pull). Os de envio (o integrador
    #: do Wazuh, o Suricata, a API genérica) não: os dados chegam por POST, não
    #: se vão buscar. Só QRadar e NetScout o activam.
    supports_pull: bool = False

    async def fetch_events(
        self, integration: Integration, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Importa sinais do serviço, já no formato interno comum.

        Só os conectores de pull o implementam; os restantes recusam de forma
        honesta em vez de devolver uma lista vazia que pareceria "nada a importar".
        """
        raise IntegrationNotAvailableError(
            integration.name,
            "este conector não suporta importação: os dados chegam por envio",
        )

    def required_env(self, integration: Integration) -> dict[str, str]:
        """Lê os segredos das variáveis de ambiente declaradas.

        Levanta `IntegrationNotAvailableError` se alguma faltar — falhar aqui é
        preferível a enviar um pedido sem credenciais e interpretar o 401
        resultante como indisponibilidade do serviço.
        """
        values: dict[str, str] = {}
        missing: list[str] = []
        for name in integration.secret_env_vars:
            value = os.environ.get(name)
            if not value:
                missing.append(name)
            else:
                values[name] = value
        if missing:
            raise IntegrationNotAvailableError(
                integration.name,
                f"variáveis de ambiente em falta: {', '.join(missing)}",
            )
        return values

    def base_url(self, integration: Integration, env_key: str) -> str:
        url = (
            integration.config.get("base_url")
            or os.environ.get(env_key)
            or ""
        ).rstrip("/")
        if not url:
            raise IntegrationNotAvailableError(
                integration.name, f"URL base não configurado ({env_key})"
            )
        return url

    def _client(self, *, verify: bool = True, **kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, verify=verify, **kwargs)

    async def execute_action(
        self,
        integration: Integration,
        action_kind: ActionKind,
        target: dict,
        parameters: dict,
    ) -> ActionResult:
        raise IntegrationNotAvailableError(
            integration.name,
            f"o conector não implementa a acção {action_kind.value}",
        )
