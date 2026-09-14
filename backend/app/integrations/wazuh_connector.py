"""Conector para o Wazuh (§26).

Usa a API REST real do gestor Wazuh:

* `POST /security/user/authenticate` — obtém um JWT (autenticação básica);
* `GET  /agents`                    — lista de agentes, usada como teste de ligação;
* `GET  /manager/info`              — versão do gestor;
* `PUT  /active-response`           — dispara uma resposta activa num agente.

A ingestão de alertas **não** passa por aqui: o caminho normal é o daemon
`integrator` do Wazuh empurrar cada alerta para o nosso endpoint
`POST /api/ingest/wazuh` através do script `custom-sheisa`. Isso é preferível a
sondar a API periodicamente — os alertas chegam no momento em que ocorrem e não
se perde nada entre sondagens. Esta API serve para verificação e resposta.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from app.core.enums import ActionKind, SourceKind
from app.core.errors import IntegrationNotAvailableError
from app.integrations.base import ActionResult, BaseConnector
from app.models.system import Integration


class WazuhConnector(BaseConnector):
    kind = SourceKind.WAZUH
    supported_actions = (
        ActionKind.EXECUTAR_VARRIMENTO,
        ActionKind.RECOLHER_ARTEFACTOS,
        ActionKind.ISOLAR_ACTIVO,
    )

    def _credentials(self, integration: Integration) -> tuple[str, str, str, bool]:
        url = self.base_url(integration, "SHEISA_WAZUH_API_URL")
        user = os.environ.get("SHEISA_WAZUH_API_USER")
        password = os.environ.get("SHEISA_WAZUH_API_PASSWORD")
        if not user or not password:
            raise IntegrationNotAvailableError(
                integration.name,
                "SHEISA_WAZUH_API_USER e SHEISA_WAZUH_API_PASSWORD são obrigatórias",
            )
        # O Wazuh usa por omissão um certificado auto-assinado. Permitimos
        # desactivar a verificação **explicitamente** por configuração, nunca
        # por omissão silenciosa.
        verify = not bool(integration.config.get("permitir_certificado_auto_assinado"))
        return url, user, password, verify

    async def _authenticate(
        self, client: httpx.AsyncClient, url: str, user: str, password: str
    ) -> str:
        response = await client.post(
            f"{url}/security/user/authenticate",
            auth=(user, password),
        )
        response.raise_for_status()
        token = (response.json().get("data") or {}).get("token")
        if not token:
            raise RuntimeError("A API do Wazuh não devolveu um token de sessão.")
        return token

    async def test_connection(self, integration: Integration) -> str:
        url, user, password, verify = self._credentials(integration)

        async with self._client(verify=verify) as client:
            token = await self._authenticate(client, url, user, password)
            headers = {"Authorization": f"Bearer {token}"}

            info = await client.get(f"{url}/manager/info", headers=headers)
            info.raise_for_status()
            manager = (info.json().get("data") or {}).get("affected_items") or [{}]
            version = manager[0].get("version", "desconhecida")

            agents = await client.get(
                f"{url}/agents", headers=headers, params={"limit": 1}
            )
            agents.raise_for_status()
            total = (agents.json().get("data") or {}).get("total_affected_items", 0)

        return (
            f"Ligação estabelecida com o gestor Wazuh {version}; "
            f"{total} agente(s) registado(s)."
        )

    async def fetch_agents(self, integration: Integration) -> list[dict[str, Any]]:
        """Lista os agentes, para sincronizar o inventário de activos."""
        url, user, password, verify = self._credentials(integration)
        async with self._client(verify=verify) as client:
            token = await self._authenticate(client, url, user, password)
            response = await client.get(
                f"{url}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 500},
            )
            response.raise_for_status()
            return (response.json().get("data") or {}).get("affected_items", [])

    async def execute_action(
        self,
        integration: Integration,
        action_kind: ActionKind,
        target: dict,
        parameters: dict,
    ) -> ActionResult:
        if action_kind not in self.supported_actions:
            return await super().execute_action(
                integration, action_kind, target, parameters
            )

        agent_id = target.get("agent_id") or target.get("wazuh_agent_id")
        if not agent_id:
            raise IntegrationNotAvailableError(
                integration.name,
                "a acção requer o identificador do agente Wazuh no alvo",
            )

        # `active-response` é o mecanismo real do Wazuh para actuar num agente.
        command = {
            ActionKind.EXECUTAR_VARRIMENTO: "restart-wazuh0",
            ActionKind.RECOLHER_ARTEFACTOS: parameters.get("command", "wazuh-logcollector"),
            ActionKind.ISOLAR_ACTIVO: parameters.get("command", "firewall-drop0"),
        }[action_kind]

        url, user, password, verify = self._credentials(integration)
        async with self._client(verify=verify) as client:
            token = await self._authenticate(client, url, user, password)
            response = await client.put(
                f"{url}/active-response",
                headers={"Authorization": f"Bearer {token}"},
                params={"agents_list": str(agent_id)},
                json={"command": command, "arguments": parameters.get("arguments", [])},
            )
            response.raise_for_status()
            payload = response.json()

        affected = (payload.get("data") or {}).get("affected_items", [])
        success = bool(affected)
        return ActionResult(
            success=success,
            detail=(
                f"Resposta activa '{command}' enviada ao agente {agent_id}."
                if success
                else f"O Wazuh não aplicou a resposta activa ao agente {agent_id}."
            ),
            raw_response=payload,
            reversible=(action_kind == ActionKind.ISOLAR_ACTIVO),
        )
