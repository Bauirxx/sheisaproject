"""Formato interno comum e contrato dos normalizadores (§8).

Todas as fontes convergem para `NormalizedEvent`. O objectivo é que o resto da
plataforma — correlação, pontuação, grafo — nunca precise de saber se um sinal
veio do Wazuh, do Suricata ou de uma chamada manual.

Regra que atravessa este módulo: **o que a fonte não disse, não se inventa.**
Um campo ausente fica `None`. Preencher um IP de destino com um valor plausível
porque "normalmente existe" corromperia a correlação e a investigação.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from app.core.enums import IocType, ObservationRole, Severity, SourceKind


@dataclass(slots=True)
class ExtractedIndicator:
    """Artefacto extraído de um evento, com o papel que nele desempenha."""

    ioc_type: IocType
    value: str
    role: ObservationRole
    context: str = ""


@dataclass(slots=True)
class NormalizedEvent:
    """Sinal de segurança em formato interno comum."""

    # --- proveniência (obrigatória) ---
    source_kind: SourceKind
    source_name: str
    source_event_id: str
    occurred_at: datetime

    # --- classificação ---
    severity: Severity = Severity.INFO
    source_severity: str | None = None
    event_type: str = ""
    description: str = ""

    # --- rede ---
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None

    # --- contexto de sistema ---
    host: str | None = None
    username: str | None = None
    process: str | None = None
    file_hash: str | None = None

    # --- regra de detecção ---
    rule_id: str | None = None
    rule_name: str | None = None
    rule_groups: list[str] = field(default_factory=list)
    #: Técnicas MITRE declaradas pela fonte. São factos reportados, não
    #: hipóteses do nosso motor - a distinção é preservada até ao incidente.
    reported_techniques: list[str] = field(default_factory=list)

    # --- identificação do activo ---
    agent_id: str | None = None
    agent_name: str | None = None

    # --- dados brutos ---
    raw_payload: dict[str, Any] = field(default_factory=dict)
    normalized_extra: dict[str, Any] = field(default_factory=dict)

    # --- artefactos ---
    indicators: list[ExtractedIndicator] = field(default_factory=list)

    #: Título proposto para o alerta que este evento venha a originar.
    alert_title: str = ""

    def dedup_key(self) -> str:
        """Chave de agregação de eventos equivalentes.

        Escolha deliberada dos componentes: fonte, regra, activo e par de IPs.
        Excluímos o instante e o identificador do evento — se os incluíssemos,
        cada ocorrência seria única e a deduplicação nunca agruparia nada, que
        é precisamente o problema de "um alerta por evento" que queremos evitar.
        """
        parts = [
            self.source_kind.value,
            self.rule_id or self.event_type or "sem-regra",
            self.host or self.agent_id or "sem-activo",
            self.source_ip or "",
            self.destination_ip or "",
            self.username or "",
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            # Um instante sem fuso vindo de uma fonte externa é ambíguo.
            # Assumimos UTC e registamo-lo, em vez de o deixar passar em
            # silêncio e produzir correlações temporais erradas.
            self.occurred_at = self.occurred_at.replace(tzinfo=UTC)
            self.normalized_extra.setdefault(
                "aviso_normalizacao", "instante sem fuso horário; assumido UTC"
            )
        if not self.alert_title:
            self.alert_title = self.rule_name or self.description[:200] or self.event_type


class Normalizer(Protocol):
    """Contrato de um normalizador de fonte."""

    source_kind: SourceKind

    def can_handle(self, payload: dict[str, Any]) -> bool:
        """Indica se o payload tem a forma esperada por esta fonte."""
        ...

    def normalize(self, payload: dict[str, Any], source_name: str) -> NormalizedEvent:
        """Converte o payload para o formato interno."""
        ...


# ------------------------------------------------------------------ auxiliares
def parse_timestamp(value: Any) -> datetime | None:
    """Interpreta os formatos de instante mais comuns nas fontes de segurança."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float):
        # Heurística para distinguir segundos de milissegundos desde a época.
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # ISO-8601, incluindo o sufixo Z que o `fromisoformat` não aceita
        # directamente em Python 3.11 quando acompanhado de microssegundos.
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            pass
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
        ):
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                continue
    return None


def coerce_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def classify_hash(value: str) -> IocType | None:
    """Determina o tipo de hash pelo comprimento."""
    length = len(value.strip())
    return {32: IocType.HASH_MD5, 40: IocType.HASH_SHA1, 64: IocType.HASH_SHA256}.get(length)


#: Gamas consideradas *internas*: um endereço destes é contexto da própria
#: organização, não um indicador de ameaça externa.
INTERNAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",        # RFC 1918
        "172.16.0.0/12",     # RFC 1918
        "192.168.0.0/16",    # RFC 1918
        "100.64.0.0/10",     # CGNAT, RFC 6598
        "169.254.0.0/16",    # link-local
        "127.0.0.0/8",       # loopback
        "::1/128",
        "fc00::/7",          # unique local, RFC 4193
        "fe80::/10",         # link-local IPv6
    )
)


def is_external_ip(value: str | None) -> bool:
    """Indica se o endereço representa uma contraparte externa à organização.

    Não usamos `ipaddress.is_private` nem `is_reserved` porque ambos abrangem
    as gamas de documentação da RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24). Essas gamas *representam* endereços públicos — são o que
    aparece em exercícios, laboratórios e na literatura. Tratá-las como
    internas faria com que o IP do atacante fosse descartado em silêncio e
    nunca chegasse a ser um indicador, que é exactamente o erro que este
    comentário existe para evitar.

    A verificação é feita contra uma lista explícita de gamas internas, o que
    torna o critério legível e auditável em vez de dependente da classificação
    da biblioteca.
    """
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if address.is_multicast or address.is_unspecified:
        return False
    return not any(address in network for network in INTERNAL_NETWORKS)

