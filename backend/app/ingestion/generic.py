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

import hashlib
import json
import uuid
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
    # `srcuser` e `dstuser` não entram aqui: dizem de que lado está a conta, e
    # juntá-las a um nome neutro perdia essa informação (ver `normalize`).
    "username": ("username", "user", "account", "utilizador"),
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


def _as_level(value: Any) -> int | None:
    """Nível numérico, venha como número ou como texto ("12")."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _severity_warning(value: Any) -> str | None:
    """O aviso que acompanha uma severidade interpretada ou assumida."""
    if value is None:
        return "severidade não fornecida; assumida MEDIA"
    level = _as_level(value)
    if level is not None:
        return "severidade numérica interpretada na escala 0-15" if level > 5 else None
    if isinstance(value, str) and value.strip().lower() in SEVERITY_ALIASES:
        return None
    return f"severidade '{value}' não reconhecida; assumida MEDIA"


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


def _fallback_event_id(
    payload: dict[str, Any], occurred_at: datetime, *, instante_da_fonte: bool
) -> str:
    """Identificador para um evento que não traz o seu.

    Há dois casos, e tratá-los da mesma maneira estragava um deles.

    **A fonte deu o instante.** O identificador tem de ser determinístico, para
    que o mesmo evento reenviado seja reconhecido como duplicado. Resume o
    payload inteiro, e não só o instante e a descrição: duas falhas de
    autenticação no mesmo segundo, de origens diferentes, tinham o mesmo
    identificador e a segunda era descartada. E usa um resumo estável — `hash()`
    é aleatorizado por processo, e o mesmo evento reenviado depois de reiniciar a
    API deixava de ser reconhecido.

    **A fonte não deu o instante.** Então não existe nada no payload que
    distinga um reenvio de uma ocorrência nova, e a escolha é deixar cada
    entrega contar: perder uma ocorrência real é pior do que contar um reenvio
    duas vezes. Isto dependia de o instante de recepção ser diferente a cada
    chamada, e **não é**: em Windows duas chamadas consecutivas a
    `datetime.now()` caem no mesmo tique do relógio do sistema (medido nesta
    máquina: 20 pares consecutivos em 20 deram valores idênticos), pelo que dois
    eventos entregues seguidos recebiam o mesmo identificador e o segundo
    desaparecia. Um token próprio por entrega diz o que se quer sem depender da
    resolução de relógio nenhum.
    """
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    if instante_da_fonte:
        semente = f"{occurred_at.isoformat()}|{canonical}"
    else:
        semente = f"{uuid.uuid4()}|{canonical}"
    digest = hashlib.sha256(semente.encode()).hexdigest()
    return f"generico-{digest[:40]}"


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
        parsed_at = parse_timestamp(occurred_raw)
        occurred_at = parsed_at or datetime.now(UTC)

        avisos: list[str] = []
        if occurred_raw is None:
            avisos.append(
                "instante não fornecido pela fonte; usado o instante de recepção"
            )
        elif parsed_at is None:
            avisos.append(
                f"instante '{occurred_raw}' não reconhecido; usado o instante de recepção"
            )

        severity_raw = _pick(payload, "severity")
        severity = coerce_severity(severity_raw)
        if aviso := _severity_warning(severity_raw):
            avisos.append(aviso)

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
            or _fallback_event_id(
                payload, occurred_at, instante_da_fonte=parsed_at is not None
            )
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
            username=(
                payload.get("dstuser") or payload.get("srcuser") or _pick(payload, "username")
            ),
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

        event.indicators = self._extract_indicators(event, payload)
        return event

    def _extract_indicators(
        self, event: NormalizedEvent, payload: dict[str, Any]
    ) -> list[ExtractedIndicator]:
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
        # A conta que actua é do lado do atacante; a visada, do lado da vítima.
        # Tratá-las igual faria a correlação ver "o mesmo actor" em dois ataques
        # contra a mesma conta — o defeito 4 do ESTADO, que o normalizador Wazuh
        # já tinha corrigido e este não.
        acting, targeted = payload.get("srcuser"), payload.get("dstuser")
        if acting:
            indicators.append(
                ExtractedIndicator(
                    IocType.UTILIZADOR, str(acting), ObservationRole.ACTOR,
                    "Conta que executou a acção",
                )
            )
        if targeted:
            indicators.append(
                ExtractedIndicator(
                    IocType.UTILIZADOR, str(targeted), ObservationRole.ALVO,
                    "Conta visada pela acção",
                )
            )
        if not acting and not targeted and event.username:
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
