"""Normalizador genérico para fontes sem conector dedicado (§8).

Aceita o formato interno comum directamente, permitindo que qualquer ferramenta
capaz de fazer um POST alimente a plataforma sem precisar de código novo. É
também o caminho usado pelo registo manual de ocorrências.

Serve de plano de recurso: se um payload não for reconhecido por nenhum
normalizador específico, é aceite aqui com os campos que se conseguirem
identificar e uma marca explícita de que a normalização foi parcial. Rejeitar o
evento perderia um sinal de segurança; aceitá-lo fingindo normalização completa
seria pior — por isso o aviso fica no registo.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.enums import IocType, ObservationRole, Severity, SourceKind
from app.ingestion.base import (
    ExtractedIndicator,
    NormalizedEvent,
    classify_hash,
    coerce_port,
    is_external_ip,
    parse_timestamp,
)

#: Nomes alternativos aceites para cada campo do formato interno. As fontes
#: divergem na nomenclatura e exigir um único nome tornaria o endpoint inútil
#: para metade dos integradores.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "occurred_at": ("timestamp", "occurred_at", "time", "@timestamp", "event_time", "date"),
    "severity": ("severity", "level", "priority", "gravidade"),
    "event_type": ("event_type", "type", "category", "tipo"),
    "description": ("description", "message", "msg", "signature", "descricao"),
    "source_ip": ("source_ip", "src_ip", "srcip", "src", "ip_origem"),
    "destination_ip": ("destination_ip", "dest_ip", "dstip", "dst_ip", "ip_destino"),
    "source_port": ("source_port", "src_port", "srcport"),
    "destination_port": ("destination_port", "dest_port", "dstport", "dst_port"),
    "protocol": ("protocol", "proto", "protocolo"),
    "host": ("host", "hostname", "computer", "agent_name", "maquina"),
    "username": ("username", "user", "account", "utilizador", "srcuser", "dstuser"),
    "process": ("process", "process_name", "image", "processo"),
    "file_hash": ("file_hash", "hash", "sha256", "md5", "sha1"),
    "rule_id": ("rule_id", "signature_id", "ruleid", "sid", "regra_id"),
    "rule_name": ("rule_name", "rule", "signature", "regra"),
}

#: Aceita tanto os nomes internos como as escalas numéricas mais comuns.
SEVERITY_ALIASES: dict[str, Severity] = {
    "info": Severity.INFO, "informational": Severity.INFO, "informativa": Severity.INFO,
    "low": Severity.BAIXA, "baixa": Severity.BAIXA, "menor": Severity.BAIXA,
    "medium": Severity.MEDIA, "media": Severity.MEDIA, "média": Severity.MEDIA,
    "moderate": Severity.MEDIA,
    "high": Severity.ALTA, "alta": Severity.ALTA, "major": Severity.ALTA,
    "critical": Severity.CRITICA, "critica": Severity.CRITICA,
    "crítica": Severity.CRITICA, "severe": Severity.CRITICA,
}


def _pick(payload: dict[str, Any], field: str) -> Any:
    for alias in FIELD_ALIASES.get(field, ()):
        if alias in payload and payload[alias] not in (None, ""):
            return payload[alias]
    return None


def coerce_severity(value: Any) -> Severity:
    """Interpreta severidade em texto ou numérica.

    Para valores numéricos assume-se a escala 0-15 do Wazuh quando o número
    excede 5, e a escala 1-5 caso contrário. É uma heurística, e por isso o
    facto de ter sido aplicada é registado no evento.
    """
    if value is None:
        return Severity.MEDIA
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in SEVERITY_ALIASES:
            return SEVERITY_ALIASES[text]
        try:
            value = int(text)
        except ValueError:
            return Severity.MEDIA
    if isinstance(value, int | float):
        number = int(value)
        if number > 5:
            from app.ingestion.wazuh import map_wazuh_level

            return map_wazuh_level(number)
        return {
            0: Severity.INFO, 1: Severity.BAIXA, 2: Severity.MEDIA,
            3: Severity.ALTA, 4: Severity.CRITICA, 5: Severity.CRITICA,
        }.get(number, Severity.MEDIA)
    return Severity.MEDIA


class GenericNormalizer:
    source_kind = SourceKind.API_GENERICA

    def can_handle(self, payload: dict[str, Any]) -> bool:
        # Plano de recurso: aceita qualquer objecto.
        return isinstance(payload, dict)

    def normalize(
        self,
        payload: dict[str, Any],
        source_name: str,
        source_kind: SourceKind | None = None,
    ) -> NormalizedEvent:
        occurred_raw = _pick(payload, "occurred_at")
        occurred_at = parse_timestamp(occurred_raw) or datetime.now(UTC)

        avisos: list[str] = []
        if occurred_raw is None:
            avisos.append(
                "instante não fornecido pela fonte; usado o instante de recepção"
            )

        severity_raw = _pick(payload, "severity")
        severity = coerce_severity(severity_raw)
        if isinstance(severity_raw, int | float) and int(severity_raw) > 5:
            avisos.append("severidade numérica interpretada na escala 0-15")

        description = str(_pick(payload, "description") or "")
        if not description:
            avisos.append("evento sem descrição")

        groups = payload.get("rule_groups") or payload.get("groups") or []
        if isinstance(groups, str):
            groups = [groups]

        techniques = payload.get("mitre_techniques") or payload.get("techniques") or []
        if isinstance(techniques, str):
            techniques = [techniques]

        source_event_id = str(
            payload.get("id")
            or payload.get("event_id")
            or payload.get("uuid")
            or f"generico-{occurred_at.timestamp()}-{abs(hash(description)) % 10**8}"
        )

        extra = {
            k: v
            for k, v in payload.items()
            if k not in {a for aliases in FIELD_ALIASES.values() for a in aliases}
        }
        if avisos:
            extra["avisos_normalizacao"] = avisos

        event = NormalizedEvent(
            source_kind=source_kind or self.source_kind,
            source_name=source_name,
            source_event_id=source_event_id,
            occurred_at=occurred_at,
            severity=severity,
            source_severity=str(severity_raw) if severity_raw is not None else None,
            event_type=str(_pick(payload, "event_type") or "evento"),
            description=description,
            source_ip=_pick(payload, "source_ip"),
            destination_ip=_pick(payload, "destination_ip"),
            source_port=coerce_port(_pick(payload, "source_port")),
            destination_port=coerce_port(_pick(payload, "destination_port")),
            protocol=_pick(payload, "protocol"),
            host=_pick(payload, "host"),
            username=_pick(payload, "username"),
            process=_pick(payload, "process"),
            file_hash=_pick(payload, "file_hash"),
            rule_id=str(_pick(payload, "rule_id")) if _pick(payload, "rule_id") else None,
            rule_name=_pick(payload, "rule_name"),
            rule_groups=[str(g) for g in groups],
            reported_techniques=[str(t).upper().strip() for t in techniques if str(t).strip()],
            raw_payload=payload,
            normalized_extra=extra,
            alert_title=str(
                payload.get("title") or _pick(payload, "rule_name") or description or "Evento"
            )[:300],
        )

        event.indicators = self._extract_indicators(event)
        return event

    def _extract_indicators(self, event: NormalizedEvent) -> list[ExtractedIndicator]:
        indicators: list[ExtractedIndicator] = []

        if is_external_ip(event.source_ip):
            indicators.append(
                ExtractedIndicator(
                    IocType.IP, event.source_ip, ObservationRole.ORIGEM, "IP de origem"
                )
            )
        if is_external_ip(event.destination_ip):
            indicators.append(
                ExtractedIndicator(
                    IocType.IP, event.destination_ip, ObservationRole.DESTINO, "IP de destino"
                )
            )
        if event.username:
            indicators.append(
                ExtractedIndicator(
                    IocType.UTILIZADOR, event.username, ObservationRole.ACTOR, "Conta envolvida"
                )
            )
        if event.host:
            indicators.append(
                ExtractedIndicator(
                    IocType.HOSTNAME, event.host, ObservationRole.ALVO, "Sistema afectado"
                )
            )
        if event.file_hash:
            ioc_type = classify_hash(event.file_hash)
            if ioc_type:
                indicators.append(
                    ExtractedIndicator(
                        ioc_type, event.file_hash.lower(), ObservationRole.PAYLOAD,
                        "Hash de ficheiro",
                    )
                )
        return indicators
