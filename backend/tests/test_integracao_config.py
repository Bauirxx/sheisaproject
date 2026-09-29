"""Configuração não-secreta de uma integração (URL base, certificado).

Para ligar o SHEISA a uma instância **real** de QRadar ou NetScout — o passo que
o simulador de laboratório não exige — falta uma coisa que não é segredo mas
muda por instalação: aceitar o certificado auto-assinado que uma appliance como
o QRadar Community Edition usa. O token continua a vir de uma variável de
ambiente; isto é só a opção de ligação, guardada e auditada.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.enums import SourceKind
from app.models.system import AuditLog, Integration
from app.services.integration_service import ensure_catalog
from tests.conftest import cabecalho


async def _qradar_id(sessao) -> str:
    await ensure_catalog(sessao)
    integracao = (
        await sessao.execute(select(Integration).where(Integration.kind == SourceKind.QRADAR))
    ).scalar_one()
    return str(integracao.id)


async def test_configurar_certificado_e_url_base(cliente, sessao, token_admin):
    ident = await _qradar_id(sessao)

    resposta = await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={
            "base_url": "https://qradar.incm.local",
            "permitir_certificado_auto_assinado": True,
        },
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["config"]["base_url"] == "https://qradar.incm.local"
    assert resposta.json()["config"]["permitir_certificado_auto_assinado"] is True
    guardada = await sessao.get(Integration, __import__("uuid").UUID(ident))
    await sessao.refresh(guardada)
    assert guardada.config["permitir_certificado_auto_assinado"] is True
    registo = (
        await sessao.execute(
            select(AuditLog).where(AuditLog.action == "CONFIGURAR_INTEGRACAO")
        )
    ).scalars().all()
    assert len(registo) == 1


async def test_url_base_vazio_limpa_a_sobreposicao(cliente, sessao, token_admin):
    ident = await _qradar_id(sessao)
    await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={"base_url": "https://a-remover.local"}, headers=cabecalho(token_admin),
    )

    resposta = await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={"base_url": ""}, headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 200, resposta.text
    assert "base_url" not in resposta.json()["config"]


async def test_so_altera_o_que_vem_no_pedido(cliente, sessao, token_admin):
    """Enviar só o certificado não apaga o URL base já definido."""
    ident = await _qradar_id(sessao)
    await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={"base_url": "https://fica.local"}, headers=cabecalho(token_admin),
    )

    resposta = await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={"permitir_certificado_auto_assinado": True}, headers=cabecalho(token_admin),
    )

    corpo = resposta.json()
    assert corpo["config"]["base_url"] == "https://fica.local"
    assert corpo["config"]["permitir_certificado_auto_assinado"] is True


async def test_configurar_exige_gestao_de_integracoes(cliente, sessao, token_analista):
    ident = await _qradar_id(sessao)

    resposta = await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={"permitir_certificado_auto_assinado": True}, headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 403, resposta.text


async def test_campo_desconhecido_e_recusado(cliente, sessao, token_admin):
    """A configuração não é um saco aberto: só as chaves declaradas passam."""
    ident = await _qradar_id(sessao)

    resposta = await cliente.patch(
        f"/api/integrations/{ident}/config",
        json={"api_token": "segredo-que-nao-deve-entrar-aqui"},
        headers=cabecalho(token_admin),
    )

    assert resposta.status_code == 422, resposta.text
