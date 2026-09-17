"""Carregamento do catálogo MITRE ATT&CK a partir do bundle STIX oficial (§11).

Os dados vêm do repositório `mitre-attack/attack-stix-data`. Nada é escrito à
mão: as tácticas, técnicas e subtécnicas que a plataforma apresenta são as que a
MITRE publica, com o identificador, a descrição e a URL canónica.

Estrutura relevante do STIX:

* `x-mitre-tactic`         -> táctica, com `x_mitre_shortname`
* `attack-pattern`         -> técnica ou subtécnica
* `kill_chain_phases`      -> tácticas a que a técnica pertence
* `external_references[0]` -> identificador (T1078) e URL, quando
  `source_name == "mitre-attack"`
* `x_mitre_is_subtechnique`-> distingue T1078.004 de T1078
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import SheisaError
from app.models.catalog import MitreTactic, MitreTechnique

logger = logging.getLogger("sheisa.mitre")

#: Ordem de recurso, usada apenas se o bundle não trouxer a matriz.
#:
#: A ordenação real é lida do objecto `x-mitre-matrix`, que lista as tácticas
#: na sequência canónica em `tactic_refs`. Derivá-la do bundle em vez de a
#: fixar aqui não é um detalhe: na versão 19 a MITRE substituiu
#: `defense-evasion` por `stealth` e acrescentou `defense-impairment`. Uma
#: lista fixa teria deixado silenciosamente duas tácticas sem posição e
#: desenhado a cadeia de ataque pela ordem errada.
FALLBACK_TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)


def _resolve_tactic_order(objects: list[dict[str, Any]]) -> dict[str, int]:
    """Ordem das tácticas, lida da matriz do próprio bundle."""
    tactic_by_stix_id = {
        obj["id"]: obj for obj in objects if obj.get("type") == "x-mitre-tactic"
    }
    for obj in objects:
        if obj.get("type") != "x-mitre-matrix":
            continue
        refs = obj.get("tactic_refs", [])
        order = {
            tactic_by_stix_id[ref]["x_mitre_shortname"]: index
            for index, ref in enumerate(refs)
            if ref in tactic_by_stix_id
        }
        if order:
            logger.info("Ordem das tácticas obtida da matriz (%d tácticas).", len(order))
            return order

    logger.warning(
        "Matriz ATT&CK não encontrada no bundle; a usar a ordem de recurso."
    )
    return {name: index for index, name in enumerate(FALLBACK_TACTIC_ORDER)}


def _attack_reference(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extrai (identificador ATT&CK, URL) das referências externas."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


async def _obtain_bundle(
    source_file: Path | None, force_download: bool
) -> dict[str, Any]:
    """Obtém o bundle STIX, preferindo a cópia local quando existe."""
    if source_file is not None:
        if not source_file.exists():
            raise SheisaError(f"Ficheiro STIX não encontrado: {source_file}")
        logger.info("A ler ATT&CK de %s", source_file)
        return json.loads(source_file.read_text(encoding="utf-8"))

    cache = settings.mitre_stix_cache
    if cache.exists() and not force_download:
        logger.info("A ler ATT&CK da cópia local %s", cache)
        return json.loads(cache.read_text(encoding="utf-8"))

    logger.info("A transferir ATT&CK de %s", settings.mitre_stix_url)
    cache.parent.mkdir(parents=True, exist_ok=True)
    # O bundle ronda os 50 MB; o tempo limite é generoso de propósito.
    async with httpx.AsyncClient(timeout=httpx.Timeout(300.0)) as client:
        response = await client.get(settings.mitre_stix_url, follow_redirects=True)
        response.raise_for_status()
        cache.write_bytes(response.content)
    logger.info("Bundle guardado em %s (%.1f MB)", cache, cache.stat().st_size / 1e6)
    return json.loads(cache.read_text(encoding="utf-8"))


async def load_attack_data(
    session: AsyncSession,
    *,
    source_file: Path | None = None,
    force_download: bool = False,
) -> dict[str, Any]:
    """Carrega ou actualiza o catálogo. Idempotente: pode correr de novo."""
    bundle = await _obtain_bundle(source_file, force_download)
    objects = bundle.get("objects", [])

    attack_version = "desconhecida"
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            attack_version = obj.get("x_mitre_version", attack_version)
            break

    tactic_order = _resolve_tactic_order(objects)

    # --- tácticas ---
    existing_tactics = {
        t.tactic_id: t for t in (await session.execute(select(MitreTactic))).scalars()
    }
    tactic_by_shortname: dict[str, MitreTactic] = {}
    tactics_loaded = 0

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tactic_id, url = _attack_reference(obj)
        if not tactic_id:
            continue

        shortname = obj.get("x_mitre_shortname", "")
        ordering = tactic_order.get(shortname, 99)

        tactic = existing_tactics.get(tactic_id)
        if tactic is None:
            tactic = MitreTactic(tactic_id=tactic_id)
            session.add(tactic)
        tactic.shortname = shortname
        tactic.name = obj.get("name", "")
        tactic.description = obj.get("description", "") or ""
        tactic.url = url
        tactic.ordering = ordering

        tactic_by_shortname[shortname] = tactic
        tactics_loaded += 1

    # Necessário para que as técnicas possam referenciar o id das tácticas.
    await session.flush()

    # --- técnicas e subtécnicas ---
    existing_techniques = {
        t.technique_id: t
        for t in (await session.execute(select(MitreTechnique))).scalars()
    }
    techniques_loaded = subtechniques_loaded = 0
    revoked_ids: set[str] = set()
    loaded_ids: set[str] = set()

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        technique_id, url = _attack_reference(obj)
        if not technique_id:
            continue
        if obj.get("revoked"):
            revoked_ids.add(technique_id)
            continue
        loaded_ids.add(technique_id)

        is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
        shortnames = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        # A táctica primária é a primeira na ordem canónica da cadeia, e não a
        # primeira listada no STIX - assim a progressão apresentada ao analista
        # corresponde à sequência real do ataque.
        primary = min(
            (s for s in shortnames if s in tactic_by_shortname),
            key=lambda s: tactic_order.get(s, 99),
            default=None,
        )

        technique = existing_techniques.get(technique_id)
        if technique is None:
            technique = MitreTechnique(technique_id=technique_id)
            session.add(technique)

        technique.name = obj.get("name", "")
        technique.description = obj.get("description", "") or ""
        technique.url = url
        technique.is_subtechnique = is_sub
        technique.parent_technique_id = technique_id.split(".")[0] if is_sub else None
        technique.tactic_id = tactic_by_shortname[primary].id if primary else None
        technique.tactic_shortnames = [s for s in shortnames if s]
        technique.platforms = obj.get("x_mitre_platforms", []) or []
        technique.data_sources = obj.get("x_mitre_data_sources", []) or []
        technique.detection = obj.get("x_mitre_detection", "") or ""
        technique.is_deprecated = bool(obj.get("x_mitre_deprecated", False))
        technique.attack_version = attack_version

        if is_sub:
            subtechniques_loaded += 1
        else:
            techniques_loaded += 1

    # Uma técnica revogada mantém o identificador e ganha `revoked: true`. Numa
    # base vazia basta saltá-la; numa actualização, a linha trazida pela versão
    # anterior continuava válida e o catálogo continuava a oferecê-la. Marca-se
    # como depreciada em vez de a apagar, para não partir os incidentes que já a
    # referem.
    for technique_id in revoked_ids - loaded_ids:
        if (stale := existing_techniques.get(technique_id)) is not None:
            stale.is_deprecated = True

    await session.flush()

    return {
        "version": attack_version,
        "tactics": tactics_loaded,
        "techniques": techniques_loaded,
        "subtechniques": subtechniques_loaded,
    }


async def find_technique(
    session: AsyncSession, technique_id: str
) -> MitreTechnique | None:
    result = await session.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == technique_id.upper())
    )
    return result.scalar_one_or_none()


async def find_techniques(
    session: AsyncSession, technique_ids: list[str]
) -> dict[str, MitreTechnique]:
    """Procura várias técnicas de uma vez, devolvendo um índice por identificador."""
    if not technique_ids:
        return {}
    normalised = [t.upper().strip() for t in technique_ids if t and t.strip()]
    result = await session.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id.in_(normalised))
    )
    return {t.technique_id: t for t in result.scalars()}
