"""Registo de conectores disponíveis.

Acrescentar um sistema externo é acrescentar uma entrada aqui. Nada no núcleo
da plataforma precisa de mudar — é o desacoplamento exigido pelo §24.
"""

from __future__ import annotations

from app.core.enums import ActionKind, SourceKind
from app.integrations.base import Connector
from app.integrations.siem_connectors import NetScoutConnector, QRadarConnector
from app.integrations.wazuh_connector import WazuhConnector

_CONNECTORS: dict[SourceKind, Connector] = {
    SourceKind.WAZUH: WazuhConnector(),
    SourceKind.QRADAR: QRadarConnector(),
    SourceKind.NETSCOUT: NetScoutConnector(),
    # Suricata e a API genérica só recebem dados (o Suricata empurra eve.json
    # para o endpoint de ingestão), pelo que não têm cliente de saída.
}


def get_connector(kind: SourceKind) -> Connector | None:
    return _CONNECTORS.get(kind)


def connectors_supporting(action_kind: ActionKind) -> list[Connector]:
    """Conectores capazes de executar uma dada acção."""
    return [
        connector
        for connector in _CONNECTORS.values()
        if action_kind in getattr(connector, "supported_actions", ())
    ]


def action_is_executable(action_kind: ActionKind) -> bool:
    """Indica se existe algum conector capaz de executar a acção.

    Usado para impedir que a interface ofereça acções que nada consegue
    realizar — oferecer um botão que não pode funcionar é precisamente o que o
    §4 proíbe.
    """
    return bool(connectors_supporting(action_kind))
