"""Conectores QRadar e NetScout.

Ambos foram implementados contra a documentação pública das respectivas APIs.
**Não foi possível verificá-los contra instâncias reais** — o ambiente não dispõe
de nenhuma, e nem o QRadar nem o NetScout se distribuem como contentor. São, isso
sim, verificáveis contra o simulador da API de cada fornecedor (`lab/siem-sim`),
que responde nos mesmos caminhos e formatos: assim o código abaixo — pedido,
autenticação, normalização — é exercitado a sério, faltando só confrontá-lo com o
produto comercial. Em consequência:

* o catálogo diz, em cada um, "verificável contra o simulador; não verificada
  contra uma instância real";
* `test_connection` contacta o serviço a sério e falha se não o alcançar. Não
  existe caminho que devolva sucesso sem resposta do servidor.

Isto é o §4 aplicado a uma situação incómoda: a alternativa fácil seria fingir
que funcionam, ou apresentar o simulador como o produto real. A alternativa
honesta é implementá-los correctamente, testá-los onde é possível, e dizer com
precisão o que não foi confirmado.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from app.core.enums import ActionKind, Severity, SourceKind
from app.core.errors import IntegrationNotAvailableError
from app.integrations.base import BaseConnector
from app.models.system import Integration


class QRadarConnector(BaseConnector):
    """IBM QRadar via API REST (`/api/siem/offenses`).

    Autenticação por cabeçalho `SEC` com um token de autorização de serviço.
    """

    kind = SourceKind.QRADAR
    supported_actions: tuple[ActionKind, ...] = ()
    supports_pull = True

    #: Versão da API declarada no cabeçalho `Version`. O QRadar exige-a e
    #: rejeita pedidos sem ela em instalações recentes.
    API_VERSION = "20.0"

    def _headers(self, integration: Integration) -> dict[str, str]:
        token = os.environ.get("SHEISA_QRADAR_API_TOKEN")
        if not token:
            raise IntegrationNotAvailableError(
                integration.name, "SHEISA_QRADAR_API_TOKEN não está definida"
            )
        return {
            "SEC": token,
            "Version": self.API_VERSION,
            "Accept": "application/json",
        }

    async def test_connection(self, integration: Integration) -> str:
        url = self.base_url(integration, "SHEISA_QRADAR_API_URL")
        verify = not bool(integration.config.get("permitir_certificado_auto_assinado"))

        async with self._client(verify=verify) as client:
            response = await client.get(
                f"{url}/api/system/about",
                headers=self._headers(integration),
            )
            response.raise_for_status()
            about = response.json()

        return (
            "Ligação estabelecida com o QRadar "
            f"{about.get('release_name', 'versão desconhecida')} "
            f"(build {about.get('build_version', '?')})."
        )

    async def fetch_events(
        self, integration: Integration, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        return await self.fetch_offenses(integration, limit=limit)

    async def fetch_offenses(
        self, integration: Integration, *, since: datetime | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Importa offenses abertas, já convertidas para o formato interno."""
        url = self.base_url(integration, "SHEISA_QRADAR_API_URL")
        verify = not bool(integration.config.get("permitir_certificado_auto_assinado"))

        filters = ["status=OPEN"]
        if since is not None:
            filters.append(f"last_updated_time>{int(since.timestamp() * 1000)}")

        async with self._client(verify=verify) as client:
            response = await client.get(
                f"{url}/api/siem/offenses",
                headers={**self._headers(integration), "Range": f"items=0-{limit - 1}"},
                params={"filter": " and ".join(filters)},
            )
            response.raise_for_status()
            offenses = response.json()

        return [self._offense_to_event(o) for o in offenses]

    @staticmethod
    def _offense_to_event(offense: dict[str, Any]) -> dict[str, Any]:
        """Converte uma offense do QRadar para o formato interno comum.

        O QRadar usa magnitude de 1 a 10; mapeamo-la para a nossa escala de
        severidade em cinco níveis.
        """
        magnitude = offense.get("magnitude", 0) or 0
        if magnitude >= 9:
            severity = Severity.CRITICA
        elif magnitude >= 7:
            severity = Severity.ALTA
        elif magnitude >= 4:
            severity = Severity.MEDIA
        elif magnitude >= 2:
            severity = Severity.BAIXA
        else:
            severity = Severity.INFO

        start_ms = offense.get("start_time")
        occurred = (
            datetime.fromtimestamp(start_ms / 1000, tz=UTC).isoformat()
            if start_ms
            else datetime.now(UTC).isoformat()
        )

        sources = offense.get("source_address_ids") or []
        return {
            "id": f"qradar-{offense.get('id')}",
            "timestamp": occurred,
            "severity": severity.value,
            "event_type": offense.get("offense_type_name") or "offense",
            "description": offense.get("description", "").strip(),
            "rule_id": str(offense.get("id")),
            "rule_name": offense.get("offense_source"),
            "host": offense.get("domain_name"),
            "groups": offense.get("categories", []),
            "qradar_magnitude": magnitude,
            "qradar_event_count": offense.get("event_count"),
            "qradar_source_address_ids": sources,
        }


class NetScoutConnector(BaseConnector):
    """NetScout (Arbor Sightline) via API REST `/api/sp/v7/alerts`."""

    kind = SourceKind.NETSCOUT
    supported_actions: tuple[ActionKind, ...] = ()
    supports_pull = True

    def _headers(self, integration: Integration) -> dict[str, str]:
        token = os.environ.get("SHEISA_NETSCOUT_API_TOKEN")
        if not token:
            raise IntegrationNotAvailableError(
                integration.name, "SHEISA_NETSCOUT_API_TOKEN não está definida"
            )
        return {"X-Arbux-APIToken": token, "Accept": "application/json"}

    async def test_connection(self, integration: Integration) -> str:
        url = self.base_url(integration, "SHEISA_NETSCOUT_API_URL")
        verify = not bool(integration.config.get("permitir_certificado_auto_assinado"))

        async with self._client(verify=verify) as client:
            response = await client.get(
                f"{url}/api/sp/v7/alerts",
                headers=self._headers(integration),
                params={"perPage": 1},
            )
            response.raise_for_status()
            payload = response.json()

        total = (payload.get("meta") or {}).get("available", "?")
        return f"Ligação estabelecida com o NetScout; {total} alerta(s) acessível(is)."

    async def fetch_events(
        self, integration: Integration, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        return await self.fetch_alerts(integration, limit=limit)

    async def fetch_alerts(
        self, integration: Integration, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        url = self.base_url(integration, "SHEISA_NETSCOUT_API_URL")
        verify = not bool(integration.config.get("permitir_certificado_auto_assinado"))

        async with self._client(verify=verify) as client:
            response = await client.get(
                f"{url}/api/sp/v7/alerts",
                headers=self._headers(integration),
                params={"perPage": limit},
            )
            response.raise_for_status()
            payload = response.json()

        return [self._alert_to_event(a) for a in payload.get("data", [])]

    @staticmethod
    def _alert_to_event(alert: dict[str, Any]) -> dict[str, Any]:
        attributes = alert.get("attributes", {}) or {}
        importance = attributes.get("importance", 0) or 0
        severity = {0: Severity.BAIXA, 1: Severity.MEDIA, 2: Severity.ALTA}.get(
            importance, Severity.MEDIA
        )
        subobject = attributes.get("subobject", {}) or {}
        return {
            "id": f"netscout-{alert.get('id')}",
            "timestamp": attributes.get("start_time") or datetime.now(UTC).isoformat(),
            "severity": severity.value,
            "event_type": attributes.get("alert_type") or "trafego",
            "description": (
                f"{attributes.get('alert_class', 'alerta')} — "
                f"{subobject.get('misuse_types') or attributes.get('alert_type', '')}"
            ).strip(" —"),
            "rule_id": str(alert.get("id")),
            "rule_name": attributes.get("alert_class"),
            "destination_ip": subobject.get("host_address"),
            "netscout_impact_bps": subobject.get("impact_bps"),
            "netscout_impact_pps": subobject.get("impact_pps"),
            "netscout_ongoing": attributes.get("ongoing"),
        }
