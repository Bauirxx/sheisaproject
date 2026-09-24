"""Gestão de evidências com integridade verificável (§15).

Decisões de segurança, porque um sistema que recebe ficheiros de origem
suspeita é ele próprio um alvo:

* **O nome do ficheiro nunca determina o caminho em disco.** O caminho é
  gerado pelo servidor a partir do identificador da evidência. Um nome como
  ``../../etc/passwd`` é guardado apenas como texto para apresentação.
* **O conteúdo é lido em blocos.** Um ficheiro de 64 MiB nunca é carregado
  inteiro em memória, e o limite é aplicado *durante* a leitura — verificar o
  tamanho só no fim permitiria a um cliente esgotar a memória do processo.
* **O hash é calculado sobre os bytes recebidos**, no momento da recepção, e
  passa a ser o valor de referência. A verificação posterior compara o
  ficheiro em disco com esse valor: é isso que detecta adulteração.
* **Nada é servido com um tipo executável.** A descarga usa sempre
  ``application/octet-stream`` e ``Content-Disposition: attachment``.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.config import settings
from app.core.enums import AuditOutcome, EvidenceType
from app.core.errors import (
    NotFoundError,
    PayloadTooLargeError,
    ValidationError,
)
from app.models.incident import Incident
from app.models.investigation import Evidence

#: Blocos de 1 MiB: equilíbrio entre chamadas de sistema e memória residente.
CHUNK_SIZE = 1024 * 1024


def _storage_path(incident_reference: str, evidence_id: uuid.UUID, suffix: str) -> Path:
    """Caminho relativo, gerado pelo servidor.

    Organizado por incidente para facilitar a inspecção manual e a recolha de
    tudo o que respeita a um caso.
    """
    safe_suffix = suffix.lower() if suffix and len(suffix) <= 12 else ".bin"
    return Path(incident_reference) / f"{evidence_id}{safe_suffix}"


def _validate_filename(filename: str) -> str:
    """Valida o nome apresentado e extrai a extensão."""
    if not filename or not filename.strip():
        raise ValidationError("O ficheiro tem de ter nome.")

    # Usamos apenas o último componente: um nome com caminho é sempre suspeito.
    name = Path(filename.replace("\\", "/")).name
    suffix = Path(name).suffix.lower()

    if suffix and suffix not in settings.evidence_allowed_suffixes:
        raise ValidationError(
            f"Extensão não permitida: {suffix}.",
            code="EXTENSAO_NAO_PERMITIDA",
            details={"extensoes_permitidas": sorted(settings.evidence_allowed_suffixes)},
        )
    return suffix


async def store_evidence(
    session: AsyncSession,
    ctx: AuditContext,
    *,
    incident: Incident,
    upload: UploadFile,
    name: str | None = None,
    description: str = "",
    evidence_type: EvidenceType = EvidenceType.OUTRO,
    source: str = "",
    collected_at: datetime | None = None,
    task_id: uuid.UUID | None = None,
) -> Evidence:
    """Guarda uma evidência e calcula os seus hashes de integridade."""
    original_filename = upload.filename or "sem-nome"
    suffix = _validate_filename(original_filename)

    evidence_id = uuid.uuid4()
    relative_path = _storage_path(incident.reference, evidence_id, suffix)
    absolute_path = settings.evidence_storage_path / relative_path
    absolute_path.parent.mkdir(parents=True, exist_ok=True)

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0

    try:
        with absolute_path.open("wb") as destination:
            while chunk := await upload.read(CHUNK_SIZE):
                size += len(chunk)
                if size > settings.evidence_max_bytes:
                    raise PayloadTooLargeError(
                        f"O ficheiro excede o limite de "
                        f"{settings.evidence_max_bytes // (1024 * 1024)} MiB.",
                    )
                sha256.update(chunk)
                md5.update(chunk)
                destination.write(chunk)
    except Exception:
        # Um ficheiro parcial em disco sem registo correspondente seria lixo
        # indetectável; removemo-lo antes de propagar o erro.
        absolute_path.unlink(missing_ok=True)
        raise

    if size == 0:
        absolute_path.unlink(missing_ok=True)
        raise ValidationError("O ficheiro está vazio.", code="FICHEIRO_VAZIO")

    evidence = Evidence(
        id=evidence_id,
        incident_id=incident.id,
        name=(name or original_filename)[:255],
        description=description,
        evidence_type=evidence_type,
        original_filename=original_filename[:255],
        storage_path=str(relative_path).replace("\\", "/"),
        # Deliberadamente genérico: nunca devolvemos um tipo que o navegador
        # possa interpretar como conteúdo activo.
        content_type="application/octet-stream",
        size_bytes=size,
        sha256=sha256.hexdigest(),
        md5=md5.hexdigest(),
        source=source or (ctx.actor_email or "desconhecida"),
        collected_at=collected_at or datetime.now(UTC),
        uploaded_by_id=ctx.actor_id,
        task_id=task_id,
        extra_metadata={
            "content_type_declarado": upload.content_type,
            "nome_original": original_filename,
        },
        integrity_verified_at=datetime.now(UTC),
        integrity_ok=True,
    )
    session.add(evidence)
    await session.flush()

    await audit.record(
        session, ctx,
        action="CARREGAR_EVIDENCIA", resource_type="evidencia",
        resource_id=evidence.id, resource_reference=incident.reference,
        description=(
            f"Evidência '{evidence.name}' ({size} bytes) associada a "
            f"{incident.reference}. SHA-256: {evidence.sha256}."
        ),
        new_value={
            "nome": evidence.name,
            "sha256": evidence.sha256,
            "bytes": size,
            "tipo": evidence_type.value,
        },
    )
    return evidence


async def get_evidence(session: AsyncSession, evidence_id: uuid.UUID) -> Evidence:
    evidence = await session.get(Evidence, evidence_id)
    if evidence is None:
        raise NotFoundError("Evidência", evidence_id)
    return evidence


def absolute_path_for(evidence: Evidence) -> Path:
    return settings.evidence_storage_path / evidence.storage_path


async def verify_integrity(
    session: AsyncSession, ctx: AuditContext, evidence: Evidence
) -> dict:
    """Confronta o ficheiro em disco com o hash registado na recepção.

    Devolve o resultado e persiste-o. Um resultado negativo é uma conclusão
    válida e importante — significa que a evidência foi alterada ou perdida, e
    o relatório tem de o dizer em vez de a apresentar como íntegra.
    """
    path = absolute_path_for(evidence)
    now = datetime.now(UTC)

    if not path.exists():
        evidence.integrity_ok = False
        evidence.integrity_verified_at = now
        detail = "O ficheiro não foi encontrado no armazenamento."
        await audit.record(
            session, ctx,
            action="VERIFICAR_INTEGRIDADE", resource_type="evidencia",
            resource_id=evidence.id,
            description=f"Verificação de '{evidence.name}': {detail}",
            outcome=AuditOutcome.FALHA,
            failure_reason=detail,
        )
        return {"integra": False, "detalhe": detail, "sha256_esperado": evidence.sha256}

    digest = hashlib.sha256()
    actual_size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            actual_size += len(chunk)
            digest.update(chunk)

    computed = digest.hexdigest()
    ok = computed == evidence.sha256

    evidence.integrity_ok = ok
    evidence.integrity_verified_at = now

    detail = (
        "O ficheiro corresponde ao hash registado na recepção."
        if ok
        else "O conteúdo não corresponde ao hash registado: a evidência foi alterada."
    )
    # Uma verificação que conclui adulteração é uma verificação falhada, como a
    # do ficheiro em falta. Registada como SUCESSO, não aparecia a quem
    # procurasse na auditoria as verificações falhadas — e é o caso mais grave.
    await audit.record(
        session, ctx,
        action="VERIFICAR_INTEGRIDADE", resource_type="evidencia",
        resource_id=evidence.id,
        description=f"Verificação de '{evidence.name}': {detail}",
        outcome=AuditOutcome.SUCESSO if ok else AuditOutcome.FALHA,
        failure_reason=None if ok else "conteúdo não corresponde ao hash da recepção",
    )
    return {
        "integra": ok,
        "detalhe": detail,
        "sha256_esperado": evidence.sha256,
        "sha256_calculado": computed,
        "bytes_esperados": evidence.size_bytes,
        "bytes_encontrados": actual_size,
        "verificado_em": now.isoformat(),
    }



async def delete_evidence(
    session: AsyncSession, ctx: AuditContext, evidence: Evidence
) -> None:
    """Elimina uma evidência e o respectivo ficheiro.

    O registo de auditoria preserva o nome e o hash do que foi eliminado — é o
    que permite, mais tarde, saber que a evidência existiu e o que continha.
    """
    incident = await session.get(Incident, evidence.incident_id)
    if incident is not None:
        from app.services import incident_service

        incident_service.garantir_editavel(incident)
    path = absolute_path_for(evidence)

    await audit.record(
        session, ctx,
        action="ELIMINAR_EVIDENCIA", resource_type="evidencia",
        resource_id=evidence.id,
        resource_reference=incident.reference if incident else None,
        description=(
            f"Evidência '{evidence.name}' eliminada. "
            f"SHA-256 do conteúdo removido: {evidence.sha256}."
        ),
        old_value={
            "nome": evidence.name,
            "sha256": evidence.sha256,
            "bytes": evidence.size_bytes,
            "tipo": evidence.evidence_type.value,
        },
    )
    await session.delete(evidence)
    path.unlink(missing_ok=True)


async def list_for_incident(
    session: AsyncSession, incident_id: uuid.UUID
) -> list[Evidence]:
    from sqlalchemy.orm import selectinload

    result = await session.execute(
        select(Evidence)
        .where(Evidence.incident_id == incident_id)
        .options(selectinload(Evidence.uploaded_by))
        .order_by(Evidence.created_at.desc())
    )
    return list(result.scalars())
