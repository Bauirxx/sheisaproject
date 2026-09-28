"""Selecção do normalizador adequado a cada payload.

A ordem importa: os normalizadores específicos são consultados primeiro e o
genérico só entra como plano de recurso. Acrescentar uma fonte nova é
acrescentar um normalizador a esta lista — nada mais no sistema muda, que é o
requisito do §24 ("adicionar novas fontes sem reescrever o sistema inteiro").
"""

from __future__ import annotations

from typing import Any

from app.core.enums import SourceKind
from app.ingestion.base import NormalizedEvent, Normalizer
from app.ingestion.generic import (
    GenericNormalizer,
    NetScoutNormalizer,
    QRadarNormalizer,
)
from app.ingestion.suricata import SuricataNormalizer
from app.ingestion.wazuh import WazuhNormalizer

_SPECIFIC: tuple[Normalizer, ...] = (
    WazuhNormalizer(),
    SuricataNormalizer(),
    # QRadar e NetScout: o conector já converte para o formato comum; estes só
    # fixam a proveniência. `can_handle` exige o prefixo do `id`, pelo que não
    # capturam a auto-detecção de payloads genéricos.
    QRadarNormalizer(),
    NetScoutNormalizer(),
)
_GENERIC = GenericNormalizer()

_BY_KIND: dict[SourceKind, Normalizer] = {n.source_kind: n for n in _SPECIFIC}


def normalize(
    payload: dict[str, Any],
    *,
    source_name: str,
    source_kind: SourceKind | None = None,
) -> NormalizedEvent:
    """Normaliza um payload para o formato interno comum.

    Quando `source_kind` é indicado pela chave de API, usamos o normalizador
    correspondente. Caso contrário, deduzimos a fonte pela forma do payload.
    """
    if source_kind is not None:
        normalizer = _BY_KIND.get(source_kind)
        if normalizer is not None and normalizer.can_handle(payload):
            return normalizer.normalize(payload, source_name)
        # A chave declara uma fonte mas o payload não tem a forma esperada.
        # Aceitamos pelo genérico, preservando o tipo declarado, e deixamos
        # registo do desencontro em vez de o esconder.
        event = _GENERIC.normalize(payload, source_name, source_kind=source_kind)
        event.normalized_extra.setdefault("avisos_normalizacao", []).append(
            f"payload não corresponde ao formato esperado de {source_kind.value}; "
            "normalizado de forma genérica"
        )
        return event

    for normalizer in _SPECIFIC:
        if normalizer.can_handle(payload):
            return normalizer.normalize(payload, source_name)

    return _GENERIC.normalize(payload, source_name)


def detect_source(payload: dict[str, Any]) -> SourceKind:
    """Identifica a fonte provável de um payload, sem o normalizar."""
    for normalizer in _SPECIFIC:
        if normalizer.can_handle(payload):
            return normalizer.source_kind
    return SourceKind.API_GENERICA
