"""Motor de triagem determinístico (§12).

Atribui a cada alerta uma pontuação de 0 a 100 e uma probabilidade estimada de
falso positivo, **sempre acompanhadas da decomposição que as produziu**. O
analista não recebe "confiança: 78%"; recebe a lista de factores, cada um com o
seu contributo em pontos e a razão pela qual contribuiu.

Porque é determinístico e não generativo:

* é **reprodutível** — a mesma entrada dá sempre a mesma saída, e a soma dos
  factores confere com a pontuação final, o que pode ser verificado ao vivo;
* é **auditável** — cada contributo remete para um dado concreto na base de
  dados, não para um peso latente;
* **não inventa** — se não há histórico da regra, o factor correspondente vale
  zero e di-lo, em vez de produzir um número plausível.

O modelo aprende, mas com dados reais: a taxa de falsos positivos vem das
decisões que os analistas efectivamente tomaram sobre alertas da mesma regra
(§36 — APRENDER).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AlertStatus,
    AssetCriticality,
    IocReputation,
    IocType,
    Severity,
)
from app.models.catalog import Asset, Ioc
from app.models.incident import Incident
from app.models.investigation import Observation
from app.models.telemetry import Alert, Event

ENGINE_NAME = "deterministico"
ENGINE_VERSION = "1.0"

#: Contributo máximo de cada factor. A soma dos máximos positivos é 100,
#: pelo que a pontuação é directamente interpretável como percentagem.
WEIGHT_SEVERITY = 35
WEIGHT_ASSET = 20
WEIGHT_REPUTATION = 20
WEIGHT_VOLUME = 10
WEIGHT_EXPOSURE = 5
WEIGHT_CORRELATION = 10
#: Penalização máxima aplicada pelo histórico de falsos positivos.
PENALTY_FALSE_POSITIVE = -30

SEVERITY_POINTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.BAIXA: 8,
    Severity.MEDIA: 18,
    Severity.ALTA: 28,
    Severity.CRITICA: 35,
}

ASSET_POINTS: dict[AssetCriticality, int] = {
    AssetCriticality.BAIXA: 4,
    AssetCriticality.MEDIA: 9,
    AssetCriticality.ALTA: 15,
    AssetCriticality.CRITICA: 20,
}

REPUTATION_POINTS: dict[IocReputation, int] = {
    IocReputation.DESCONHECIDA: 0,
    IocReputation.BENIGNA: 0,
    IocReputation.SUSPEITA: 10,
    IocReputation.MALICIOSA: 20,
}

#: Número mínimo de decisões históricas para a taxa de falsos positivos ser
#: considerada significativa. Abaixo disto, duas decisões ao acaso poderiam
#: suprimir uma regra legítima.
MIN_HISTORY_FOR_FP = 5


@dataclass(slots=True)
class Factor:
    """Contributo isolado para a pontuação."""

    nome: str
    pontos: int
    razao: str
    dados: dict = field(default_factory=dict)


@dataclass(slots=True)
class TriageOutcome:
    score: int
    false_positive_score: int
    factors: list[Factor]
    rationale: str

    def as_dict(self) -> dict:
        return {
            f.nome: {"pontos": f.pontos, "razao": f.razao, **({"dados": f.dados} if f.dados else {})}
            for f in self.factors
        }


async def _factor_severity(alert: Alert) -> Factor:
    points = SEVERITY_POINTS.get(alert.severity, 0)
    return Factor(
        "severidade_da_fonte",
        points,
        f"A fonte classificou o alerta como {alert.severity.value}.",
        {"severidade": alert.severity.value, "maximo": WEIGHT_SEVERITY},
    )


async def _factor_asset(session: AsyncSession, alert: Alert, asset: Asset | None) -> Factor:
    if asset is None:
        return Factor(
            "criticidade_do_activo",
            0,
            "O alerta não foi associado a nenhum activo do inventário.",
            {"maximo": WEIGHT_ASSET},
        )
    points = ASSET_POINTS.get(asset.criticality, 0)
    return Factor(
        "criticidade_do_activo",
        points,
        f"Afecta '{asset.name}', de criticidade {asset.criticality.value}.",
        {
            "activo": asset.identifier,
            "criticidade": asset.criticality.value,
            "maximo": WEIGHT_ASSET,
        },
    )


async def _factor_reputation(session: AsyncSession, alert: Alert) -> Factor:
    """Reputação máxima entre os indicadores observados neste alerta."""
    values = await _alert_indicator_values(session, alert)
    if not values:
        return Factor(
            "reputacao_dos_indicadores",
            0,
            "O alerta não contém indicadores externos conhecidos.",
            {"maximo": WEIGHT_REPUTATION},
        )

    result = await session.execute(
        select(Ioc).where(
            Ioc.value.in_([v for _, v in values]),
        )
    )
    iocs = list(result.scalars())
    if not iocs:
        return Factor(
            "reputacao_dos_indicadores",
            0,
            "Nenhum dos indicadores tem reputação registada.",
            {"maximo": WEIGHT_REPUTATION},
        )

    worst = max(iocs, key=lambda i: REPUTATION_POINTS.get(i.reputation, 0))
    points = REPUTATION_POINTS.get(worst.reputation, 0)

    if points == 0:
        return Factor(
            "reputacao_dos_indicadores",
            0,
            f"Os {len(iocs)} indicadores presentes não têm reputação adversa registada.",
            {"indicadores_avaliados": len(iocs), "maximo": WEIGHT_REPUTATION},
        )

    return Factor(
        "reputacao_dos_indicadores",
        points,
        f"O indicador {worst.value} está classificado como {worst.reputation.value}.",
        {
            "indicador": worst.value,
            "tipo": worst.ioc_type.value,
            "reputacao": worst.reputation.value,
            "maximo": WEIGHT_REPUTATION,
        },
    )


async def _factor_volume(alert: Alert) -> Factor:
    """Volume de eventos agregados.

    Escala logarítmica: a diferença entre 1 e 10 eventos é informativa, a
    diferença entre 1 000 e 1 010 não é. Uma escala linear faria um alerta
    ruidoso dominar a fila só por ser repetitivo.
    """
    count = max(1, alert.event_count)
    points = min(WEIGHT_VOLUME, int(round(math.log10(count) * 5)))
    if count == 1:
        razao = "Evento único."
    else:
        razao = f"{count} eventos equivalentes agregados neste alerta."
    return Factor(
        "volume_de_eventos", points, razao,
        {"eventos": count, "maximo": WEIGHT_VOLUME},
    )


async def _factor_exposure(session: AsyncSession, alert: Alert) -> Factor:
    """Envolvimento de endereços externos à organização."""
    result = await session.execute(
        select(func.count())
        .select_from(Event)
        .where(
            Event.alert_id == alert.id,
            (Event.source_ip.isnot(None)) | (Event.destination_ip.isnot(None)),
        )
    )
    has_network = (result.scalar_one() or 0) > 0
    values = await _alert_indicator_values(session, alert)
    external_ips = [v for t, v in values if t == IocType.IP.value]

    if not external_ips:
        return Factor(
            "exposicao_externa",
            0,
            "Não foram observados endereços externos à organização."
            if has_network else "O alerta não tem componente de rede.",
            {"maximo": WEIGHT_EXPOSURE},
        )
    return Factor(
        "exposicao_externa",
        WEIGHT_EXPOSURE,
        f"Envolve {len(external_ips)} endereço(s) externo(s): "
        f"{', '.join(external_ips[:3])}.",
        {"enderecos": external_ips[:10], "maximo": WEIGHT_EXPOSURE},
    )


async def _factor_correlation(session: AsyncSession, alert: Alert) -> Factor:
    """Indicadores deste alerta já observados noutros incidentes recentes."""
    values = await _alert_indicator_values(session, alert)
    if not values:
        return Factor(
            "actividade_relacionada", 0,
            "Sem indicadores para relacionar com actividade anterior.",
            {"maximo": WEIGHT_CORRELATION},
        )

    since = datetime.now(UTC) - timedelta(days=30)
    result = await session.execute(
        select(Incident.reference)
        .join(Observation, Observation.incident_id == Incident.id)
        .join(Ioc, Ioc.id == Observation.ioc_id)
        .where(
            Ioc.value.in_([v for _, v in values]),
            Observation.observed_at >= since,
        )
        .distinct()
        .limit(10)
    )
    references = [r for (r,) in result.all()]

    if not references:
        return Factor(
            "actividade_relacionada", 0,
            "Nenhum destes indicadores foi observado em incidentes dos últimos 30 dias.",
            {"maximo": WEIGHT_CORRELATION},
        )

    points = min(WEIGHT_CORRELATION, 4 + 3 * len(references))
    return Factor(
        "actividade_relacionada", points,
        f"Indicadores já observados em {len(references)} incidente(s) recente(s): "
        f"{', '.join(references[:3])}.",
        {"incidentes": references, "maximo": WEIGHT_CORRELATION},
    )


async def _factor_false_positive_history(
    session: AsyncSession, alert: Alert
) -> tuple[Factor, int]:
    """Histórico real de decisões sobre alertas da mesma regra.

    Devolve (factor, probabilidade estimada de falso positivo 0-100).
    Esta é a componente que "aprende": nenhuma regra é considerada ruidosa por
    suposição, apenas por decisões que analistas tomaram de facto.
    """
    if not alert.rule_id:
        return (
            Factor(
                "historico_de_falsos_positivos", 0,
                "O alerta não identifica uma regra, pelo que não há histórico a consultar.",
                {"maximo_penalizacao": PENALTY_FALSE_POSITIVE},
            ),
            0,
        )

    decided_statuses = [
        AlertStatus.PROMOVIDO, AlertStatus.CORRELACIONADO,
        AlertStatus.FALSO_POSITIVO, AlertStatus.DESCARTADO,
    ]
    result = await session.execute(
        select(Alert.status, func.count())
        .where(
            Alert.rule_id == alert.rule_id,
            Alert.id != alert.id,
            Alert.status.in_(decided_statuses),
        )
        .group_by(Alert.status)
    )
    counts = dict(result.all())
    total = sum(counts.values())

    if total < MIN_HISTORY_FOR_FP:
        return (
            Factor(
                "historico_de_falsos_positivos", 0,
                f"Histórico insuficiente para esta regra ({total} decisão/ões; "
                f"são necessárias {MIN_HISTORY_FOR_FP}).",
                {"decisoes": total, "minimo": MIN_HISTORY_FOR_FP},
            ),
            0,
        )

    false_positives = counts.get(AlertStatus.FALSO_POSITIVO, 0) + counts.get(
        AlertStatus.DESCARTADO, 0
    )
    rate = false_positives / total
    fp_score = int(round(rate * 100))
    points = int(round(rate * PENALTY_FALSE_POSITIVE))

    return (
        Factor(
            "historico_de_falsos_positivos", points,
            f"{false_positives} de {total} alertas da regra {alert.rule_id} foram "
            f"descartados ou marcados como falso positivo ({fp_score}%).",
            {
                "regra": alert.rule_id,
                "descartados": false_positives,
                "total_decidido": total,
                "taxa_percentagem": fp_score,
            },
        ),
        fp_score,
    )


async def _alert_indicator_values(
    session: AsyncSession, alert: Alert
) -> list[tuple[str, str]]:
    """Indicadores (tipo, valor) extraídos dos eventos do alerta.

    Lidos do que foi guardado na ingestão, e não renormalizados: o que se
    pontua tem de ser exactamente o que foi registado.
    """
    result = await session.execute(
        select(Event.normalized_extra).where(Event.alert_id == alert.id).limit(50)
    )
    seen: set[tuple[str, str]] = set()
    for (extra,) in result.all():
        for item in (extra or {}).get("indicadores", []):
            tipo, valor = item.get("tipo"), item.get("valor")
            if tipo and valor:
                seen.add((tipo, valor))
    return sorted(seen)


async def score_alert(
    session: AsyncSession, alert: Alert, *, asset: Asset | None = None
) -> TriageOutcome:
    """Calcula e persiste a pontuação de triagem do alerta."""
    if asset is None and alert.asset_id is not None:
        asset = await session.get(Asset, alert.asset_id)

    fp_factor, fp_score = await _factor_false_positive_history(session, alert)

    factors = [
        await _factor_severity(alert),
        await _factor_asset(session, alert, asset),
        await _factor_reputation(session, alert),
        await _factor_volume(alert),
        await _factor_exposure(session, alert),
        await _factor_correlation(session, alert),
        fp_factor,
    ]

    raw = sum(f.pontos for f in factors)
    score = max(0, min(100, raw))

    positivos = sorted(
        (f for f in factors if f.pontos > 0), key=lambda f: f.pontos, reverse=True
    )
    if positivos:
        principais = "; ".join(f"{f.nome} (+{f.pontos})" for f in positivos[:3])
        rationale = f"Pontuação {score}/100. Principais contributos: {principais}."
    else:
        rationale = f"Pontuação {score}/100. Nenhum factor de risco relevante."

    if fp_factor.pontos < 0:
        rationale += f" Penalizado em {fp_factor.pontos} pelo histórico da regra."

    alert.triage_score = score
    alert.triage_factors = {
        "motor": ENGINE_NAME,
        "versao": ENGINE_VERSION,
        "total_bruto": raw,
        "total_final": score,
        "factores": TriageOutcome(score, fp_score, factors, rationale).as_dict(),
    }
    alert.false_positive_score = fp_score
    alert.triage_rationale = rationale
    alert.scored_at = datetime.now(UTC)

    return TriageOutcome(score, fp_score, factors, rationale)


def severity_from_score(score: int) -> Severity:
    """Severidade sugerida a partir da pontuação de triagem."""
    if score >= 85:
        return Severity.CRITICA
    if score >= 65:
        return Severity.ALTA
    if score >= 40:
        return Severity.MEDIA
    if score >= 20:
        return Severity.BAIXA
    return Severity.INFO
