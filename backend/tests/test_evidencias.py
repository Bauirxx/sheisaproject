"""Evidências: carregamento, integridade e travessia de caminhos (§15, §32).

Uma evidência só serve se for possível demonstrar que não foi alterada desde a
recolha. Por isso o que aqui se testa não é "o carregamento funciona", mas que o
hash é calculado sobre os bytes recebidos, que a verificação posterior detecta
adulteração, e que um nome de ficheiro hostil não escreve fora da pasta.
"""

from __future__ import annotations

import hashlib

from tests.conftest import cabecalho


async def _incidente(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={
            "title": "Incidente com evidências",
            "description": "x",
            "category": "INTRUSAO",
            "severity": "MEDIA",
        },
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _carregar(cliente, token, incidente_id, *, nome, conteudo: bytes, tipo="LOG"):
    return await cliente.post(
        "/api/evidence",
        data={"incident_id": incidente_id, "tipo": tipo, "descricao": "Recolha de teste"},
        files={"ficheiro": (nome, conteudo, "application/octet-stream")},
        headers=cabecalho(token),
    )


async def test_carregar_evidencia_calcula_o_hash_dos_bytes_recebidos(
    cliente, token_analista
):
    incidente = await _incidente(cliente, token_analista)
    conteudo = b"Jan 01 00:00:00 srv-web-01 sshd: Failed password for admin\n" * 20

    resposta = await _carregar(
        cliente, token_analista, incidente["id"], nome="auth.log", conteudo=conteudo
    )
    assert resposta.status_code == 201, resposta.text
    evidencia = resposta.json()

    assert evidencia["sha256"] == hashlib.sha256(conteudo).hexdigest()
    assert evidencia["size_bytes"] == len(conteudo)


async def test_a_verificacao_de_integridade_confirma_o_ficheiro(
    cliente, token_analista
):
    incidente = await _incidente(cliente, token_analista)
    resposta = await _carregar(
        cliente, token_analista, incidente["id"],
        nome="captura.pcap", conteudo=b"\xd4\xc3\xb2\xa1dados de rede",
    )
    evidencia = resposta.json()

    verificacao = await cliente.post(
        f"/api/evidence/{evidencia['id']}/verify", headers=cabecalho(token_analista)
    )
    assert verificacao.status_code == 200, verificacao.text
    corpo = verificacao.json()
    assert corpo["integra"] is True
    assert corpo["sha256_calculado"] == corpo["sha256_esperado"]


async def test_a_verificacao_detecta_adulteracao(cliente, token_analista, sessao):
    """Se o ficheiro mudar em disco, a verificação tem de o dizer.

    É esta propriedade que torna a evidência utilizável: sem ela, o hash seria
    um número guardado ao lado do ficheiro, sem valor probatório.
    """
    from app.services import evidence_service

    incidente = await _incidente(cliente, token_analista)
    evidencia = (
        await _carregar(
            cliente, token_analista, incidente["id"],
            nome="artefacto.bin", conteudo=b"conteudo original",
        )
    ).json()

    registo = await evidence_service.get_evidence(sessao, evidencia["id"])
    caminho = evidence_service.absolute_path_for(registo)
    caminho.write_bytes(b"conteudo adulterado")

    verificacao = await cliente.post(
        f"/api/evidence/{evidencia['id']}/verify", headers=cabecalho(token_analista)
    )
    assert verificacao.status_code == 200
    assert verificacao.json()["integra"] is False


async def test_extensao_nao_permitida_e_recusada(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    resposta = await _carregar(
        cliente, token_analista, incidente["id"],
        nome="malicioso.svg", conteudo=b"<svg onload=alert(1)>",
    )
    assert resposta.status_code == 422
    assert resposta.json()["erro"]["codigo"] == "EXTENSAO_NAO_PERMITIDA"
    assert resposta.json()["erro"]["detalhes"]["extensoes_permitidas"]


async def test_nome_com_caminho_nao_escapa_da_pasta(cliente, token_analista, sessao):
    """Um nome com `../` é tratado como nome, nunca como caminho."""
    from app.core.config import settings
    from app.services import evidence_service

    incidente = await _incidente(cliente, token_analista)
    resposta = await _carregar(
        cliente, token_analista, incidente["id"],
        nome="../../../../etc/passwd.log", conteudo=b"tentativa de travessia",
    )
    assert resposta.status_code == 201, resposta.text

    registo = await evidence_service.get_evidence(sessao, resposta.json()["id"])
    caminho = evidence_service.absolute_path_for(registo).resolve()
    raiz = settings.evidence_storage_path.resolve()
    assert raiz in caminho.parents, f"o ficheiro foi escrito fora de {raiz}: {caminho}"


async def test_ficheiro_sem_nome_e_recusado(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    resposta = await _carregar(
        cliente, token_analista, incidente["id"], nome="", conteudo=b"x"
    )
    assert resposta.status_code == 422


async def test_descarregar_devolve_os_mesmos_bytes(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    conteudo = b"linha de registo para descarregar\n" * 5
    evidencia = (
        await _carregar(
            cliente, token_analista, incidente["id"],
            nome="registo.txt", conteudo=conteudo,
        )
    ).json()

    descarga = await cliente.get(
        f"/api/evidence/{evidencia['id']}/download", headers=cabecalho(token_analista)
    )
    assert descarga.status_code == 200
    assert descarga.content == conteudo
    # Um executável carregado como artefacto nunca é servido como executável.
    assert "text/html" not in descarga.headers.get("content-type", "")


async def test_carregar_exige_permissao(cliente, token_gestor):
    """O gestor lê evidências mas não as carrega: a cadeia de custódia é de quem recolhe."""
    from tests.conftest import autenticar

    token_analista = await autenticar(cliente, "analista")
    incidente = await _incidente(cliente, token_analista)

    resposta = await _carregar(
        cliente, token_gestor, incidente["id"], nome="a.log", conteudo=b"x"
    )
    assert resposta.status_code == 403


async def test_o_carregamento_fica_auditado_com_o_hash(
    cliente, token_analista, sessao
):
    from sqlalchemy import select

    from app.models.system import AuditLog

    incidente = await _incidente(cliente, token_analista)
    conteudo = b"prova"
    evidencia = (
        await _carregar(
            cliente, token_analista, incidente["id"],
            nome="prova.log", conteudo=conteudo,
        )
    ).json()

    registo = (
        await sessao.execute(
            select(AuditLog)
            .where(AuditLog.resource_type == "evidencia")
            .order_by(AuditLog.created_at.desc())
            .limit(1)
        )
    ).scalar_one()

    assert evidencia["sha256"] in registo.description or (
        evidencia["sha256"] in str(registo.new_value)
    ), "a auditoria do carregamento não regista o hash"
