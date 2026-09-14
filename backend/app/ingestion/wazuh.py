"""Normalizador de alertas do Wazuh (§26).

Contrato real do Wazuh, conforme a documentação do gestor:

* o daemon `integrator` invoca `/var/ossec/integrations/custom-*` com
  `argv[1]` = ficheiro do alerta, `argv[2]` = `api_key`, `argv[3]` = `hook_url`;
* o alerta JSON traz `rule.{id,level,description,groups,mitre}`,
  `agent.{id,name,ip}`, `data.{srcip,dstip,srcport,dstport,srcuser,dstuser}`,
  `full_log`, `decoder`, `location`, `manager`, `id`, `timestamp`.

**Níveis de severidade.** O Wazuh usa 0-15, não 1-5. O mapeamento abaixo segue
a classificação publicada pela Wazuh e está exposto como função para poder ser
verificado e testado — traduzir mal estes níveis faria com que um "severe
attack" (15) aparecesse como informação.
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

#: Correspondência entre o nível Wazuh (0-15) e a severidade interna.
#: Fonte: "Rules classification" da documentação Wazuh.
#:   0-3   eventos autorizados / notificações de baixa prioridade
#:   4-6   erros do sistema ou do utilizador, ataques de baixa relevância
#:   7-9   correspondências suspeitas, primeira ocorrência, origem inválida
#:   10-12 erros múltiplos, alteração de binários, eventos de alta importância
#:   13-15 erro invulgar, evento de segurança grave, ataque severo
WAZUH_LEVEL_TO_SEVERITY: dict[range, Severity] = {
    range(0, 4): Severity.INFO,
    range(4, 7): Severity.BAIXA,
    range(7, 10): Severity.MEDIA,
    range(10, 13): Severity.ALTA,
    range(13, 16): Severity.CRITICA,
}


def map_wazuh_level(level: Any) -> Severity:
    """Converte o nível Wazuh na severidade interna."""
    try:
        value = int(level)
    except (TypeError, ValueError):
        return Severity.INFO
    value = max(0, min(15, value))
    for span, severity in WAZUH_LEVEL_TO_SEVERITY.items():
        if value in span:
            return severity
    return Severity.INFO


def _extract_techniques(rule: dict[str, Any]) -> list[str]:
    """Técnicas ATT&CK declaradas pela regra Wazuh.

    O campo `rule.mitre.id` já traz identificadores no formato `T1078`. São
    tratados como reportados pela fonte, não como inferência nossa.
    """
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") or []
    if isinstance(ids, str):
        ids = [ids]
    return [str(i).strip().upper() for i in ids if str(i).strip()]


class WazuhNormalizer:
    source_kind = SourceKind.WAZUH

    def can_handle(self, payload: dict[str, Any]) -> bool:
        # A combinação rule+agent é característica do Wazuh; `rule.level` é o
        # discriminador mais fiável, por ser específico deste produto.
        rule = payload.get("rule")
        return isinstance(rule, dict) and "level" in rule and "agent" in payload

    def normalize(self, payload: dict[str, Any], source_name: str) -> NormalizedEvent:
        rule = payload.get("rule") or {}
        agent = payload.get("agent") or {}
        data = payload.get("data") or {}

        level = rule.get("level")
        severity = map_wazuh_level(level)

        occurred_at = parse_timestamp(payload.get("timestamp")) or datetime.now(UTC)

        source_ip = data.get("srcip") or data.get("src_ip")
        destination_ip = data.get("dstip") or data.get("dst_ip")
        # `srcuser` e a conta que actua; `dstuser` e a conta visada. Confundi-las
        # faria a correlacao tratar a vitima como se fosse o atacante.
        acting_user = data.get("srcuser")
        targeted_user = data.get("dstuser")
        username = targeted_user or acting_user or data.get("user")

        groups = rule.get("groups") or []
        if isinstance(groups, str):
            groups = [groups]

        # O identificador do alerta Wazuh garante idempotência na ingestão: se o
        # integrator reenviar o mesmo alerta, reconhecemo-lo.
        source_event_id = str(
            payload.get("id") or f"{rule.get('id','?')}-{occurred_at.timestamp()}"
        )

        event = NormalizedEvent(
            source_kind=self.source_kind,
            source_name=source_name,
            source_event_id=source_event_id,
            occurred_at=occurred_at,
            severity=severity,
            source_severity=f"nivel {level}" if level is not None else None,
            event_type=(groups[0] if groups else "wazuh"),
            description=rule.get("description", "") or "",
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=coerce_port(data.get("srcport")),
            destination_port=coerce_port(data.get("dstport")),
            protocol=data.get("protocol"),
            host=agent.get("name") or payload.get("manager", {}).get("name"),
            username=username,
            process=data.get("process") or (data.get("win", {}) or {})
                .get("eventdata", {}).get("image"),
            rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
            rule_name=rule.get("description"),
            rule_groups=[str(g) for g in groups],
            reported_techniques=_extract_techniques(rule),
            agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
            agent_name=agent.get("name"),
            raw_payload=payload,
            normalized_extra={
                "location": payload.get("location"),
                "decoder": (payload.get("decoder") or {}).get("name"),
                "full_log": (payload.get("full_log") or "")[:4000],
                "manager": (payload.get("manager") or {}).get("name"),
                "rule_firedtimes": rule.get("firedtimes"),
            },
            alert_title=rule.get("description") or "Alerta Wazuh",
        )

        event.indicators = self._extract_indicators(event, agent, data)
        return event

    def _extract_indicators(
        self, event: NormalizedEvent, agent: dict[str, Any], data: dict[str, Any]
    ) -> list[ExtractedIndicator]:
        indicators: list[ExtractedIndicator] = []

        # Só IPs encaminháveis se tornam indicadores: um endereço privado é
        # contexto interno e polui a base de IOCs se tratado como ameaça.
        if is_external_ip(event.source_ip):
            indicators.append(
                ExtractedIndicator(
                    IocType.IP, event.source_ip, ObservationRole.ORIGEM,
                    "IP de origem reportado pelo Wazuh",
                )
            )
        if is_external_ip(event.destination_ip):
            indicators.append(
                ExtractedIndicator(
                    IocType.IP, event.destination_ip, ObservationRole.DESTINO,
                    "IP de destino reportado pelo Wazuh",
                )
            )

        # A conta que executa a accao pertence ao lado do atacante; a conta
        # visada pertence ao lado da vitima. Os papeis mantem essa distincao.
        if acting := data.get("srcuser"):
            indicators.append(
                ExtractedIndicator(
                    IocType.UTILIZADOR, str(acting), ObservationRole.ACTOR,
                    "Conta que executou a accao",
                )
            )
        if targeted := data.get("dstuser"):
            indicators.append(
                ExtractedIndicator(
                    IocType.UTILIZADOR, str(targeted), ObservationRole.ALVO,
                    "Conta visada pela accao",
                )
            )
        if not data.get("srcuser") and not data.get("dstuser") and data.get("user"):
            indicators.append(
                ExtractedIndicator(
                    IocType.UTILIZADOR, str(data["user"]), ObservationRole.ACTOR,
                    "Conta envolvida no evento",
                )
            )

        hostname = agent.get("name")
        if hostname:
            indicators.append(
                ExtractedIndicator(
                    IocType.HOSTNAME, hostname, ObservationRole.ALVO,
                    "Agente Wazuh onde o evento foi observado",
                )
            )

        # Hashes de ficheiro: o Wazuh expõe-nos sob nomes variados conforme o
        # decoder (FIM, Sysmon, VirusTotal).
        for key in ("md5", "sha1", "sha256", "md5_after", "sha1_after", "sha256_after"):
            value = data.get(key) or (data.get("syscheck") or {}).get(key)
            if not value:
                continue
            ioc_type = classify_hash(str(value))
            if ioc_type:
                indicators.append(
                    ExtractedIndicator(
                        ioc_type, str(value).lower(), ObservationRole.PAYLOAD,
                        f"Hash de ficheiro ({key})",
                    )
                )
                event.file_hash = str(value).lower()

        monitored_path = (data.get("syscheck") or {}).get("path")
        if monitored_path:
            indicators.append(
                ExtractedIndicator(
                    IocType.FICHEIRO, str(monitored_path), ObservationRole.ARTEFACTO,
                    "Ficheiro sinalizado pelo módulo de integridade",
                )
            )

        url = data.get("url")
        if url:
            indicators.append(
                ExtractedIndicator(
                    IocType.URL, str(url), ObservationRole.DESTINO, "URL observado"
                )
            )

        return indicators
