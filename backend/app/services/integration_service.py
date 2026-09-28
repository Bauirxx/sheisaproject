"""Gestão de integrações e chaves de ingestão (§26).

Princípio do §4 aplicado literalmente: **uma integração só aparece como ACTIVA
depois de um teste de ligação bem-sucedido**, cujo resultado e instante ficam
registados. Declarar credenciais coloca-a em CONFIGURADA, não em ACTIVA.

Os segredos nunca são guardados na base de dados: a integração regista apenas
o *nome* das variáveis de ambiente que os contêm (§23).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import audit
from app.core.audit import AuditContext
from app.core.enums import (
    AuditOutcome,
    IntegrationDirection,
    IntegrationStatus,
    SourceKind,
)
from app.core.errors import ConflictError, NotFoundError, ValidationError
from app.core.security import generate_api_key
from app.models.identity import ApiKey
from app.models.system import Integration

#: Catálogo de conectores conhecidos.
#:
#: `implementado` diz se existe código capaz de falar com o produto. Wazuh e
#: Suricata são testáveis num laboratório real; QRadar e NetScout têm cliente
#: implementado mas não foi possível verificá-lo contra instâncias reais, e a
#: interface apresenta-os como tal. Não os marcamos como activos por omissão.
CONNECTOR_CATALOG: dict[SourceKind, dict] = {
    SourceKind.WAZUH: {
        "nome": "Wazuh",
        "descricao": (
            "Recebe alertas do gestor Wazuh através do daemon integrator "
            "(script custom-sheisa) ou da API do Wazuh."
        ),
        "direccao": IntegrationDirection.BIDIRECIONAL,
        "variaveis": ["SHEISA_WAZUH_API_URL", "SHEISA_WAZUH_API_USER", "SHEISA_WAZUH_API_PASSWORD"],
        "accoes": ["EXECUTAR_VARRIMENTO", "RECOLHER_ARTEFACTOS", "ISOLAR_ACTIVO"],
        "implementado": True,
        "verificavel": True,
    },
    SourceKind.SURICATA: {
        "nome": "Suricata",
        "descricao": "Recebe eventos EVE JSON do IDS Suricata.",
        "direccao": IntegrationDirection.ENTRADA,
        "variaveis": [],
        "accoes": [],
        "implementado": True,
        "verificavel": True,
    },
    SourceKind.QRADAR: {
        "nome": "IBM QRadar",
        "descricao": (
            "Importa offenses abertas via API REST (fetch_offenses) e ingere-as "
            "pelo pipeline normal, accionada por POST /integrations/{id}/import. "
            "Testada contra um servidor simulado; não verificada contra uma "
            "instância QRadar real."
        ),
        "direccao": IntegrationDirection.ENTRADA,
        "variaveis": ["SHEISA_QRADAR_API_URL", "SHEISA_QRADAR_API_TOKEN"],
        "accoes": [],
        "implementado": True,
        "verificavel": False,
    },
    SourceKind.NETSCOUT: {
        "nome": "NetScout",
        "descricao": (
            "Importa alertas de tráfego via API REST (fetch_alerts) e ingere-os "
            "pelo pipeline normal, accionada por POST /integrations/{id}/import. "
            "Testada contra um servidor simulado; não verificada contra uma "
            "instância NetScout real."
        ),
        "direccao": IntegrationDirection.ENTRADA,
        "variaveis": ["SHEISA_NETSCOUT_API_URL", "SHEISA_NETSCOUT_API_TOKEN"],
        "accoes": [],
        "implementado": True,
        "verificavel": False,
    },
    SourceKind.API_GENERICA: {
        "nome": "API genérica",
        "descricao": "Aceita eventos no formato interno comum via POST.",
        "direccao": IntegrationDirection.ENTRADA,
        "variaveis": [],
        "accoes": [],
        "implementado": True,
        "verificavel": True,
    },
}


async def ensure_catalog(session: AsyncSession) -> int:
    """Regista os conectores do catálogo em falta e sincroniza os textos dos
    que já existem.

    A descrição, direcção, variáveis, acções e os sinalizadores
    `implementado`/`verificavel` vivem no código e são a fonte de verdade: um
    conector já registado é actualizado para reflectir o catálogo, **sem tocar**
    no que o operador configurou (`status`, `is_enabled`, segredos). Sem isto,
    corrigir um texto do catálogo não chegaria à base de dados que a interface
    lê. Devolve quantos conectores foram criados de novo.
    """
    existentes = {
        i.kind: i for i in (await session.execute(select(Integration))).scalars()
    }
    criados = 0
    for kind, spec in CONNECTOR_CATALOG.items():
        integracao = existentes.get(kind)
        if integracao is None:
            session.add(
                Integration(
                    name=spec["nome"],
                    kind=kind,
                    direction=spec["direccao"],
                    description=spec["descricao"],
                    status=IntegrationStatus.NAO_CONFIGURADA,
                    is_enabled=False,
                    secret_env_vars=spec["variaveis"],
                    supported_actions=spec["accoes"],
                    config={
                        "implementado": spec["implementado"],
                        "verificavel_neste_ambiente": spec["verificavel"],
                    },
                )
            )
            criados += 1
            continue
        # Só os campos descritivos; o estado configurado pelo operador fica.
        integracao.name = spec["nome"]
        integracao.direction = spec["direccao"]
        integracao.description = spec["descricao"]
        integracao.secret_env_vars = spec["variaveis"]
        integracao.supported_actions = spec["accoes"]
        integracao.config = {
            **(integracao.config or {}),
            "implementado": spec["implementado"],
            "verificavel_neste_ambiente": spec["verificavel"],
        }
    await session.flush()
    return criados


async def get_integration(session: AsyncSession, integration_id: uuid.UUID) -> Integration:
    integration = await session.get(Integration, integration_id)
    if integration is None:
        raise NotFoundError("Integração", integration_id)
    return integration


async def get_or_create_for_kind(
    session: AsyncSession, kind: SourceKind
) -> Integration:
    result = await session.execute(select(Integration).where(Integration.kind == kind))
    integration = result.scalar_one_or_none()
    if integration is not None:
        return integration

    spec = CONNECTOR_CATALOG.get(kind, {})
    integration = Integration(
        name=spec.get("nome", kind.value),
        kind=kind,
        direction=spec.get("direccao", IntegrationDirection.ENTRADA),
        description=spec.get("descricao", ""),
        status=IntegrationStatus.NAO_CONFIGURADA,
        secret_env_vars=spec.get("variaveis", []),
        supported_actions=spec.get("accoes", []),
    )
    session.add(integration)
    await session.flush()
    return integration


async def create_ingestion_key(
    session: AsyncSession,
    *,
    name: str,
    kind: str,
    description: str = "",
    created_by_id: uuid.UUID | None = None,
    ctx: AuditContext | None = None,
) -> tuple[str, ApiKey]:
    """Cria uma chave de ingestão. Devolve (chave em claro, registo)."""
    try:
        source_kind = SourceKind(kind.upper())
    except ValueError as exc:
        raise ValidationError(
            f"Fonte desconhecida: '{kind}'.",
            details={"fontes_validas": [s.value for s in SourceKind]},
        ) from exc

    existing = await session.execute(select(ApiKey).where(ApiKey.name == name))
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Já existe uma chave com o nome '{name}'.")

    integration = await get_or_create_for_kind(session, source_kind)

    raw, prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        name=name,
        description=description,
        key_prefix=prefix,
        key_hash=key_hash,
        integration_id=integration.id,
        created_by_id=created_by_id,
        is_active=True,
    )
    session.add(api_key)

    # A existência de uma chave torna a integração configurada — mas não
    # activa: só o tráfego real ou um teste de ligação o confirmam.
    if integration.status == IntegrationStatus.NAO_CONFIGURADA:
        integration.status = IntegrationStatus.CONFIGURADA
        integration.is_enabled = True

    await session.flush()

    if ctx is not None:
        await audit.record(
            session, ctx,
            action="CRIAR_CHAVE_API", resource_type="chave_api", resource_id=api_key.id,
            description=(
                f"Chave de ingestão '{name}' criada para {source_kind.value} "
                f"(prefixo {prefix})."
            ),
        )

    return raw, api_key


async def record_ingestion(
    session: AsyncSession, integration_id: uuid.UUID | None
) -> None:
    """Actualiza as estatísticas reais de uma integração após receber um evento.

    Receber tráfego é a prova mais forte de que a integração funciona, por isso
    promove-a a ACTIVA.
    """
    if integration_id is None:
        return
    integration = await session.get(Integration, integration_id)
    if integration is None:
        return
    integration.events_received += 1
    integration.last_event_at = datetime.now(UTC)
    if integration.status in (
        IntegrationStatus.NAO_CONFIGURADA,
        IntegrationStatus.CONFIGURADA,
        IntegrationStatus.ERRO,
    ):
        integration.status = IntegrationStatus.ACTIVA
        integration.is_enabled = True
        integration.last_check_at = datetime.now(UTC)
        integration.last_check_ok = True
        integration.last_check_detail = (
            "Promovida a activa por ter recebido eventos reais."
        )


def missing_secrets(integration: Integration) -> list[str]:
    """Variáveis de ambiente declaradas mas ausentes."""
    return [name for name in integration.secret_env_vars if not os.environ.get(name)]


async def test_connection(
    session: AsyncSession, integration: Integration, ctx: AuditContext
) -> dict:
    """Testa a ligação real ao sistema externo.

    Nunca devolve sucesso sem ter falado com o serviço. Se faltarem segredos ou
    não existir cliente, di-lo explicitamente (§4).
    """
    from app.integrations.registry import get_connector

    now = datetime.now(UTC)
    missing = missing_secrets(integration)

    if missing:
        integration.status = IntegrationStatus.NAO_CONFIGURADA
        integration.last_check_at = now
        integration.last_check_ok = False
        integration.last_check_detail = (
            f"Variáveis de ambiente em falta: {', '.join(missing)}."
        )
        await audit.record(
            session, ctx,
            action="TESTAR_INTEGRACAO", resource_type="integracao",
            resource_id=integration.id,
            description=f"Teste não realizado: faltam {', '.join(missing)}.",
        )
        return {
            "sucesso": False,
            "estado": integration.status.value,
            "detalhe": integration.last_check_detail,
            "variaveis_em_falta": missing,
        }

    connector = get_connector(integration.kind)
    if connector is None:
        integration.last_check_at = now
        integration.last_check_ok = False
        integration.last_check_detail = (
            f"Não existe cliente implementado para {integration.kind.value}."
        )
        return {
            "sucesso": False,
            "estado": integration.status.value,
            "detalhe": integration.last_check_detail,
        }

    try:
        detail = await connector.test_connection(integration)
        integration.status = IntegrationStatus.ACTIVA
        integration.is_enabled = True
        integration.last_check_ok = True
        integration.last_check_detail = detail
        integration.last_error = None
        success = True
    except Exception as exc:  # noqa: BLE001 - qualquer falha é resultado válido do teste
        integration.status = IntegrationStatus.ERRO
        integration.last_check_ok = False
        integration.last_check_detail = f"Falha ao contactar o serviço: {exc}"
        integration.last_error = str(exc)[:1000]
        success = False

    integration.last_check_at = now
    await audit.record(
        session, ctx,
        action="TESTAR_INTEGRACAO", resource_type="integracao", resource_id=integration.id,
        description=(
            f"Teste de ligação a {integration.name}: "
            f"{'bem-sucedido' if success else 'falhado'}. "
            f"{integration.last_check_detail}"
        ),
    )
    return {
        "sucesso": success,
        "estado": integration.status.value,
        "detalhe": integration.last_check_detail,
    }


async def importar_de_fonte(
    session: AsyncSession, integration: Integration, ctx: AuditContext, *, limit: int = 50
) -> dict:
    """Importa sinais de uma fonte de pull (QRadar, NetScout) e ingere-os.

    Vai buscar os sinais ao serviço e passa-os pelo **mesmo pipeline de ingestão**
    de qualquer outra fonte, pelo que viram Eventos e Alertas normais, com a
    idempotência habitual por `(fonte, id)`: reimportar não duplica. Nunca inventa
    dados — se o serviço não responder, falha de forma visível (§4).
    """
    from app.integrations.registry import get_connector
    from app.services import ingestion_service

    now = datetime.now(UTC)
    missing = missing_secrets(integration)
    if missing:
        integration.last_check_at = now
        integration.last_check_ok = False
        integration.last_check_detail = (
            f"Variáveis de ambiente em falta: {', '.join(missing)}."
        )
        await audit.record(
            session, ctx,
            action="IMPORTAR_INTEGRACAO", resource_type="integracao",
            resource_id=integration.id,
            description=f"Importação não realizada: faltam {', '.join(missing)}.",
            outcome=AuditOutcome.FALHA,
        )
        return {
            "sucesso": False, "estado": integration.status.value,
            "detalhe": integration.last_check_detail, "variaveis_em_falta": missing,
        }

    connector = get_connector(integration.kind)
    if connector is None or not getattr(connector, "supports_pull", False):
        detalhe = (
            f"O conector {integration.kind.value} não suporta importação: os dados "
            "desta fonte chegam por envio (push), não se vão buscar."
        )
        await audit.record(
            session, ctx,
            action="IMPORTAR_INTEGRACAO", resource_type="integracao",
            resource_id=integration.id, description=detalhe, outcome=AuditOutcome.FALHA,
        )
        return {"sucesso": False, "estado": integration.status.value, "detalhe": detalhe}

    try:
        payloads = await connector.fetch_events(integration, limit=limit)
    except Exception as exc:  # noqa: BLE001 - a falha externa é um resultado válido
        integration.status = IntegrationStatus.ERRO
        integration.last_check_at = now
        integration.last_check_ok = False
        integration.last_check_detail = f"Falha ao importar de {integration.name}: {exc}"
        integration.last_error = str(exc)[:1000]
        await audit.record(
            session, ctx,
            action="IMPORTAR_INTEGRACAO", resource_type="integracao",
            resource_id=integration.id, description=integration.last_check_detail,
            outcome=AuditOutcome.FALHA, failure_reason=str(exc)[:500],
        )
        return {
            "sucesso": False, "estado": integration.status.value,
            "detalhe": integration.last_check_detail,
        }

    resultados = await ingestion_service.ingest_batch(
        session, ctx, payloads,
        source_name=integration.name, source_kind=integration.kind,
        integration_id=integration.id,
    )
    importados = sum(1 for r in resultados if r.status == "criado")
    duplicados = sum(1 for r in resultados if r.status == "duplicado_ignorado")
    outros = len(resultados) - importados - duplicados

    integration.status = IntegrationStatus.ACTIVA
    integration.is_enabled = True
    integration.last_check_at = now
    integration.last_check_ok = True
    integration.events_received += importados
    if importados:
        integration.last_event_at = now
    integration.last_check_detail = (
        f"Importados {importados} de {len(payloads)} sinais; {duplicados} já existiam."
    )
    integration.last_error = None

    await audit.record(
        session, ctx,
        action="IMPORTAR_INTEGRACAO", resource_type="integracao",
        resource_id=integration.id,
        description=f"Importação de {integration.name}: {integration.last_check_detail}",
        new_value={
            "importados": importados, "duplicados": duplicados, "total": len(payloads),
        },
    )

    return {
        "sucesso": True, "estado": integration.status.value,
        "importados": importados, "duplicados": duplicados, "outros": outros,
        "total": len(payloads), "detalhe": integration.last_check_detail,
    }
