"""Normalizador de eventos EVE JSON do Suricata.

O Suricata emite um fluxo de objectos JSON (`eve.json`) com `event_type`
distinguindo `alert`, `dns`, `http`, `tls`, `flow`, etc. Só ingerimos o que tem
significado de detecção: os de tipo `alert`. Ingerir `flow` ou `dns` em bruto
encheria a plataforma de telemetria sem asserção de ameaça — é trabalho de um
SIEM, não de uma plataforma de resposta a incidentes.

Severidade: no Suricata **1 é a mais alta** (a escala é invertida em relação à
intuição). Traduzir isto ao contrário faria com que os alertas mais graves
aparecessem como os menos graves.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.enums import IocType, ObservationRole, Severity, SourceKind
from app.ingestion.base import (
    ExtractedIndicator,
    NormalizedEvent,
    coerce_port,
    is_external_ip,
    parse_timestamp,
)

#: `alert.severity` do Suricata: 1 = alta, 2 = média, 3 = baixa, 4 = informativa.
SURICATA_SEVERITY: dict[int, Severity] = {
    1: Severity.ALTA,
    2: Severity.MEDIA,
    3: Severity.BAIXA,
    4: Severity.INFO,
}

#: Categorias de assinatura que justificam elevar a severidade.
#: Um "Trojan" ou "Exploit" detectado é materialmente mais grave do que a
#: severidade genérica da assinatura sugere.
CRITICAL_CATEGORIES = (
    "trojan", "malware", "exploit", "command and control",
    "ransomware", "backdoor", "shellcode",
)


def map_suricata_severity(severity: Any, category: str = "") -> Severity:
    try:
        value = int(severity)
    except (TypeError, ValueError):
        return Severity.MEDIA

    base = SURICATA_SEVERITY.get(value, Severity.MEDIA)
    lowered = (category or "").lower()
    if any(marker in lowered for marker in CRITICAL_CATEGORIES):
        # Eleva um grau, sem ultrapassar CRITICA.
        order = [Severity.INFO, Severity.BAIXA, Severity.MEDIA, Severity.ALTA, Severity.CRITICA]
        return order[min(order.index(base) + 1, len(order) - 1)]
    return base


class SuricataNormalizer:
    source_kind = SourceKind.SURICATA

    def can_handle(self, payload: dict[str, Any]) -> bool:
        return payload.get("event_type") == "alert" and "alert" in payload

    def normalize(self, payload: dict[str, Any], source_name: str) -> NormalizedEvent:
        alert = payload.get("alert") or {}
        category = alert.get("category", "") or ""

        occurred_at = parse_timestamp(payload.get("timestamp")) or datetime.now(UTC)
        severity = map_suricata_severity(alert.get("severity"), category)

        signature_id = alert.get("signature_id")
        # `flow_id` mais assinatura identificam a ocorrência de forma estável
        # entre reenvios do mesmo ficheiro eve.json. Sem `flow_id` recorremos ao
        # instante, que é menos robusto mas continua a evitar colisões.
        flow_id = payload.get("flow_id")
        if flow_id is not None:
            source_event_id = f"{flow_id}-{signature_id}"
        else:
            source_event_id = f"{signature_id}-{occurred_at.timestamp()}"

        event = NormalizedEvent(
            source_kind=self.source_kind,
            source_name=source_name,
            source_event_id=source_event_id,
            occurred_at=occurred_at,
            severity=severity,
            source_severity=f"severity {alert.get('severity')}",
            event_type=category or "intrusion-detection",
            description=alert.get("signature", "") or "",
            source_ip=payload.get("src_ip"),
            destination_ip=payload.get("dest_ip"),
            source_port=coerce_port(payload.get("src_port")),
            destination_port=coerce_port(payload.get("dest_port")),
            protocol=payload.get("proto"),
            host=payload.get("host") or payload.get("hostname"),
            rule_id=str(signature_id) if signature_id is not None else None,
            rule_name=alert.get("signature"),
            rule_groups=[category] if category else [],
            raw_payload=payload,
            normalized_extra={
                "interface": payload.get("in_iface"),
                "flow_id": payload.get("flow_id"),
                "gid": alert.get("gid"),
                "rev": alert.get("rev"),
                "action": alert.get("action"),
                "app_proto": payload.get("app_proto"),
                "http": payload.get("http"),
                "dns": payload.get("dns"),
                "tls": payload.get("tls"),
            },
            alert_title=alert.get("signature") or "Alerta Suricata",
        )

        event.indicators = self._extract_indicators(event, payload)
        return event

    def _extract_indicators(
        self, event: NormalizedEvent, payload: dict[str, Any]
    ) -> list[ExtractedIndicator]:
        indicators: list[ExtractedIndicator] = []

        if is_external_ip(event.source_ip):
            indicators.append(
                ExtractedIndicator(
                    IocType.IP, event.source_ip, ObservationRole.ORIGEM,
                    "IP de origem do tráfego detectado",
                )
            )
        if is_external_ip(event.destination_ip):
            indicators.append(
                ExtractedIndicator(
                    IocType.IP, event.destination_ip, ObservationRole.DESTINO,
                    "IP de destino do tráfego detectado",
                )
            )

        http = payload.get("http") or {}
        hostname = http.get("hostname")
        if hostname:
            indicators.append(
                ExtractedIndicator(
                    IocType.DOMINIO, str(hostname).lower(), ObservationRole.DESTINO,
                    "Domínio pedido por HTTP",
                )
            )
        url = http.get("url")
        if hostname and url:
            indicators.append(
                ExtractedIndicator(
                    IocType.URL, f"http://{hostname}{url}", ObservationRole.DESTINO,
                    "URL pedido",
                )
            )
        user_agent = http.get("http_user_agent")
        if user_agent:
            indicators.append(
                ExtractedIndicator(
                    IocType.USER_AGENT, str(user_agent), ObservationRole.ARTEFACTO,
                    "User-Agent observado",
                )
            )

        dns = payload.get("dns") or {}
        rrname = dns.get("rrname")
        if rrname:
            indicators.append(
                ExtractedIndicator(
                    IocType.DOMINIO, str(rrname).lower().rstrip("."),
                    ObservationRole.DESTINO, "Domínio consultado por DNS",
                )
            )

        tls = payload.get("tls") or {}
        sni = tls.get("sni")
        if sni:
            indicators.append(
                ExtractedIndicator(
                    IocType.DOMINIO, str(sni).lower(), ObservationRole.DESTINO,
                    "SNI observado na negociação TLS",
                )
            )

        return indicators
