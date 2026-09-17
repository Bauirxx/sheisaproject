"""Ingestão: da recepção do sinal ao alerta triável (§8).

Percurso completo de um sinal:

    payload -> normalização -> idempotência -> activo -> deduplicação
            -> Event -> Alert -> IOCs -> pontuação -> correlação

Três decisões merecem justificação:

**Idempotência por (fonte, identificador da fonte).** O integrator do Wazuh
reenvia alertas quando uma entrega falha. Sem esta garantia, uma falha de rede
transitória inflacionaria as contagens do painel — números que o §17 exige que
sejam reais.

**Deduplicação por janela.** Eventos equivalentes dentro da janela agregam-se
num alerta existente em vez de criarem alertas novos. Uma força bruta com 4 000
tentativas é *um* alerta com 4 000 eventos, não 4 000 alertas.

**Os IOCs são actualizados na ingestão, as Observações só no incidente.** O IOC
é um facto global (este endereço foi visto, tantas vezes, pela última vez
agora); a Observação é um facto local ao incidente. Os indicadores extraídos
ficam guardados no evento para que a promoção a incidente possa materializar as
observações sem ter de normalizar tudo outra vez.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.config import settings
from app.core.enums import (
    ALERT_OPEN_STATUSES,
    AlertStatus,
    AuditOutcome,
    IocType,
    SourceKind,
)
from app.core.references import ReferenceKind, next_reference
from app.ingestion.base import ExtractedIndicator, NormalizedEvent
from app.ingestion.registry import normalize
from app.models.catalog import Asset, Ioc
from app.models.incident import Incident
from app.models.telemetry import Alert, Event

logger = logging.getLogger("sheisa.ingestao")


@dataclass(slots=True)
class IngestionResult:
    """Resultado da ingestão de um sinal, devolvido ao integrador."""

    event_id: uuid.UUID
    alert_id: uuid.UUID | None
    alert_reference: str | None
    status: str  # "criado" | "agregado" | "duplicado_ignorado" | "suprimido"
    detail: str
    triage_score: int | None = None
    correlated_incident_reference: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "evento_id": str(self.event_id),
            "estado": self.status,
            "detalhe": self.detail,
        }
        if self.alert_id:
            payload["alerta_id"] = str(self.alert_id)
            payload["alerta_referencia"] = self.alert_reference
        if self.triage_score is not None:
            payload["pontuacao_triagem"] = self.triage_score
        if self.correlated_incident_reference:
            payload["incidente"] = self.correlated_incident_reference
        return payload


# --------------------------------------------------------------------- activos
async def resolve_asset(session: AsyncSession, event: NormalizedEvent) -> Asset | None:
    """Liga o evento a um activo conhecido.

    A procura segue a ordem de fiabilidade dos identificadores: o id do agente
    Wazuh é inequívoco, o hostname é quase sempre fiável, o IP é o menos fiável
    (muda por DHCP). Não criamos activos automaticamente a partir de IPs — o
    inventário ficaria poluído com entradas efémeras sem dono nem criticidade.
    """
    if event.agent_id:
        result = await session.execute(
            select(Asset).where(Asset.wazuh_agent_id == event.agent_id)
        )
        if asset := result.scalar_one_or_none():
            return asset

    candidate_host = event.agent_name or event.host
    if candidate_host:
        result = await session.execute(
            select(Asset).where(
                func.lower(Asset.hostname) == candidate_host.lower()
            )
        )
        if asset := result.scalar_one_or_none():
            return asset
        result = await session.execute(
            select(Asset).where(
                func.lower(Asset.identifier) == candidate_host.lower()
            )
        )
        if asset := result.scalar_one_or_none():
            return asset

    # O IP de destino identifica melhor o alvo do que o de origem, que numa
    # intrusão pertence tipicamente ao atacante.
    for ip in (event.destination_ip, event.source_ip):
        if not ip:
            continue
        result = await session.execute(select(Asset).where(Asset.ip_address == ip))
        if asset := result.scalar_one_or_none():
            return asset

    return None


# ----------------------------------------------------------------------- IOCs
#: Comprimento de cada tipo de hash, em dígitos hexadecimais.
_HASH_LENGTHS: dict[IocType, int] = {
    IocType.HASH_MD5: 32, IocType.HASH_SHA1: 40, IocType.HASH_SHA256: 64,
}


def ioc_value_problem(ioc_type: IocType, value: str) -> str | None:
    """Porque é que o valor é impossível para o tipo, ou `None` se servir.

    A normalização devolve o texto tal como vem quando não o consegue
    interpretar, pelo que um "IP" `banana` era guardado como IP — e podia chegar a
    ser proposto como endereço a bloquear. Só se verificam os tipos com forma
    inequívoca: domínios, contas, processos ou caminhos variam demasiado entre
    sistemas para uma regra que não recuse valores legítimos.
    """
    import ipaddress
    import string

    text = value.strip()
    if ioc_type == IocType.IP:
        try:
            ipaddress.ip_address(text)
        except ValueError:
            return f"'{text}' não é um endereço IP válido"
        return None
    if (length := _HASH_LENGTHS.get(ioc_type)) is not None:
        if len(text) != length or any(c not in string.hexdigits for c in text):
            return f"um {ioc_type.value} tem exactamente {length} dígitos hexadecimais"
    return None


def normalise_ioc_value(ioc_type: IocType, value: str) -> str:
    """Forma canónica de um indicador.

    Sem normalização, `EVIL.COM`, `evil.com` e `evil.com.` seriam três
    indicadores distintos e a correlação por entidade partilhada falharia.
    """
    text = value.strip()
    if ioc_type in (IocType.DOMINIO, IocType.HOSTNAME, IocType.EMAIL):
        return text.lower().rstrip(".")
    if ioc_type in (IocType.HASH_MD5, IocType.HASH_SHA1, IocType.HASH_SHA256):
        return text.lower()
    if ioc_type == IocType.URL:
        return text
    if ioc_type == IocType.IP:
        import ipaddress

        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text
    return text


async def upsert_ioc(
    session: AsyncSession,
    indicator: ExtractedIndicator,
    observed_at: datetime,
) -> Ioc:
    """Cria ou actualiza o indicador global e regista o avistamento."""
    value = normalise_ioc_value(indicator.ioc_type, indicator.value)

    result = await session.execute(
        select(Ioc).where(Ioc.ioc_type == indicator.ioc_type, Ioc.value == value)
    )
    ioc = result.scalar_one_or_none()

    if ioc is None:
        ioc = Ioc(
            ioc_type=indicator.ioc_type,
            value=value,
            source="ingestao",
            context=indicator.context,
            first_seen=observed_at,
            last_seen=observed_at,
            sighting_count=1,
        )
        session.add(ioc)
        await session.flush()
        return ioc

    # Primeira e última observação derivam de avistamentos reais (§10).
    if ioc.first_seen is None or observed_at < ioc.first_seen:
        ioc.first_seen = observed_at
    if ioc.last_seen is None or observed_at > ioc.last_seen:
        ioc.last_seen = observed_at
    ioc.sighting_count += 1
    return ioc


# ------------------------------------------------------------------- ingestão
async def ingest_event(
    session: AsyncSession,
    ctx: AuditContext,
    payload: dict[str, Any],
    *,
    source_name: str,
    source_kind: SourceKind | None = None,
    integration_id: uuid.UUID | None = None,
    is_demo: bool = False,
) -> IngestionResult:
    """Ingere um sinal e devolve o que lhe aconteceu."""
    event = normalize(payload, source_name=source_name, source_kind=source_kind)
    received_at = datetime.now(UTC)

    # --- 1. idempotência ---
    existing = await session.execute(
        select(Event).where(
            Event.source_kind == event.source_kind,
            Event.source_event_id == event.source_event_id,
        )
    )
    if duplicate := existing.scalar_one_or_none():
        return IngestionResult(
            event_id=duplicate.id,
            alert_id=duplicate.alert_id,
            alert_reference=None,
            status="duplicado_ignorado",
            detail=(
                "Evento já recebido anteriormente "
                f"({event.source_kind.value}:{event.source_event_id})."
            ),
        )

    # --- 2. activo ---
    asset = await resolve_asset(session, event)

    # --- 3. supressão por lista de permitidos ---
    # Se todos os indicadores externos do evento estiverem explicitamente
    # marcados como benignos, não vale a pena gerar um alerta. A supressão é
    # registada, nunca silenciosa.
    suppressed_by = await _check_allowlist(session, event)

    # --- 4. persistir o evento ---
    db_event = Event(
        source_kind=event.source_kind,
        source_name=event.source_name,
        source_event_id=event.source_event_id,
        integration_id=integration_id,
        occurred_at=event.occurred_at,
        received_at=received_at,
        severity=event.severity,
        source_severity=event.source_severity,
        event_type=event.event_type,
        description=event.description,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        protocol=event.protocol,
        host=event.host,
        username=event.username,
        process=event.process,
        file_hash=event.file_hash,
        rule_id=event.rule_id,
        rule_name=event.rule_name,
        rule_groups=event.rule_groups,
        reported_techniques=event.reported_techniques,
        raw_payload=event.raw_payload,
        normalized_extra={
            **event.normalized_extra,
            # Indicadores guardados para que a promoção a incidente possa
            # materializar observações sem renormalizar o payload.
            "indicadores": [
                {
                    "tipo": i.ioc_type.value,
                    "valor": normalise_ioc_value(i.ioc_type, i.value),
                    "papel": i.role.value,
                    "contexto": i.context,
                }
                for i in event.indicators
            ],
        },
        asset_id=asset.id if asset else None,
    )
    session.add(db_event)
    await session.flush()

    # --- 5. IOCs globais ---
    for indicator in event.indicators:
        await upsert_ioc(session, indicator, event.occurred_at)

    if suppressed_by:
        db_event.normalized_extra["suprimido_por"] = suppressed_by
        await audit.record(
            session, ctx,
            action="EVENTO_SUPRIMIDO", resource_type="evento", resource_id=db_event.id,
            description=(
                "Evento não gerou alerta: todos os indicadores externos estão "
                f"na lista de permitidos ({', '.join(suppressed_by)})."
            ),
        )
        return IngestionResult(
            event_id=db_event.id, alert_id=None, alert_reference=None,
            status="suprimido",
            detail=f"Indicadores na lista de permitidos: {', '.join(suppressed_by)}.",
        )

    # --- 6. deduplicação ---
    dedup_key = event.dedup_key()
    window_start = event.occurred_at - timedelta(
        minutes=settings.correlation_window_minutes
    )
    result = await session.execute(
        select(Alert)
        .where(
            Alert.dedup_key == dedup_key,
            Alert.status.in_(list(ALERT_OPEN_STATUSES)),
            Alert.last_event_at >= window_start,
        )
        .order_by(Alert.last_event_at.desc())
        .limit(1)
    )
    alert = result.scalar_one_or_none()

    if alert is not None:
        alert.event_count += 1
        alert.last_event_at = max(alert.last_event_at, event.occurred_at)
        # Um evento mais grave eleva o alerta agregado: a severidade do
        # conjunto é a do pior caso observado, não a do primeiro evento.
        if event.severity.rank > alert.severity.rank:
            alert.severity = event.severity
        db_event.alert_id = alert.id
        await session.flush()
        status, detail = "agregado", (
            f"Evento agregado ao alerta {alert.reference} "
            f"({alert.event_count} eventos)."
        )
    else:
        reference = await next_reference(session, ReferenceKind.ALERT)
        alert = Alert(
            reference=reference,
            title=event.alert_title[:300],
            description=event.description,
            source_kind=event.source_kind,
            source_name=event.source_name,
            severity=event.severity,
            status=AlertStatus.NOVO,
            dedup_key=dedup_key,
            event_count=1,
            first_event_at=event.occurred_at,
            last_event_at=event.occurred_at,
            asset_id=asset.id if asset else None,
            rule_id=event.rule_id,
            rule_name=event.rule_name,
            tags=list(event.rule_groups),
            is_demo_data=is_demo,
        )
        session.add(alert)
        await session.flush()
        db_event.alert_id = alert.id
        # A ligação evento->alerta tem de estar escrita antes da pontuação: o
        # motor de triagem lê os indicadores através de `Event.alert_id`.
        await session.flush()
        status, detail = "criado", f"Alerta {alert.reference} criado."

    # --- 7. pontuação de triagem (motor determinístico) ---
    from app.intelligence.triage import score_alert

    await score_alert(session, alert, asset=asset)

    # --- 8. correlação ---
    # Corre sempre, mesmo em alertas agregados: um alerta que já existia pode
    # passar a fazer parte de uma campanha quando chega o sinal que a revela.
    from app.correlation.engine import correlate_alert
    from app.services import incident_service

    incident_reference: str | None = None
    if alert.incident_id is None:
        decision = await correlate_alert(session, alert)
        if decision.matched:
            incident = await incident_service.apply_correlation(
                session, ctx, alert=alert, decision=decision, is_demo=is_demo
            )
            if incident is not None:
                incident_reference = incident.reference
    else:
        existing_incident = await session.get(Incident, alert.incident_id)
        incident_reference = existing_incident.reference if existing_incident else None

    await audit.record(
        session, ctx,
        action="INGESTAO", resource_type="alerta",
        resource_id=alert.id, resource_reference=alert.reference,
        description=(
            f"{detail} Fonte: {event.source_name} ({event.source_kind.value}). "
            f"Pontuação de triagem: {alert.triage_score}."
            + (f" Incidente: {incident_reference}." if incident_reference else "")
        ),
    )

    return IngestionResult(
        event_id=db_event.id,
        alert_id=alert.id,
        alert_reference=alert.reference,
        status=status,
        detail=detail,
        triage_score=alert.triage_score,
        correlated_incident_reference=incident_reference,
    )


async def _check_allowlist(
    session: AsyncSession, event: NormalizedEvent
) -> list[str]:
    """Indicadores externos do evento que estão marcados como benignos.

    Devolve lista vazia se o evento tiver pelo menos um indicador externo não
    permitido — ou se não tiver indicadores externos de todo, caso em que não há
    base para suprimir.
    """
    external_types = {IocType.IP, IocType.DOMINIO, IocType.URL, IocType.HASH_SHA256,
                      IocType.HASH_MD5, IocType.HASH_SHA1}
    candidates = [i for i in event.indicators if i.ioc_type in external_types]
    if not candidates:
        return []

    allowed: list[str] = []
    for indicator in candidates:
        value = normalise_ioc_value(indicator.ioc_type, indicator.value)
        result = await session.execute(
            select(Ioc).where(
                Ioc.ioc_type == indicator.ioc_type,
                Ioc.value == value,
                Ioc.is_allowlisted.is_(True),
            )
        )
        if result.scalar_one_or_none() is not None:
            allowed.append(value)

    # Só suprime se *todos* os indicadores externos forem permitidos.
    return allowed if len(allowed) == len(candidates) else []


async def ingest_batch(
    session: AsyncSession,
    ctx: AuditContext,
    payloads: list[dict[str, Any]],
    *,
    source_name: str,
    source_kind: SourceKind | None = None,
    integration_id: uuid.UUID | None = None,
    is_demo: bool = False,
) -> list[IngestionResult]:
    """Ingere vários sinais.

    Um payload malformado não interrompe o lote: numa recepção de 500 alertas,
    deixar cair os 499 restantes por causa de um seria perder telemetria de
    segurança.

    Cada elemento corre dentro do seu próprio ponto de salvaguarda. Sem isso,
    uma falha a meio de um `flush` deixaria a transacção inutilizável e até o
    registo da falha na auditoria rebentaria — perder-se-ia o lote inteiro
    *e* o rasto do que correu mal.
    """
    results: list[IngestionResult] = []
    for index, payload in enumerate(payloads):
        try:
            async with session.begin_nested():
                results.append(
                    await ingest_event(
                        session, ctx, payload,
                        source_name=source_name,
                        source_kind=source_kind,
                        integration_id=integration_id,
                        is_demo=is_demo,
                    )
                )
        except Exception as exc:
            # O ponto de salvaguarda já reverteu; a sessão volta a estar utilizável.
            logger.exception("Falha ao ingerir o elemento %d do lote", index)
            await audit.record(
                session, ctx,
                action="INGESTAO", resource_type="evento",
                description=f"Falha ao ingerir o elemento {index} do lote: {exc}",
                outcome=AuditOutcome.FALHA,
                failure_reason=str(exc)[:500],
            )
    return results
