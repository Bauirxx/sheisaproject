"""Evidências: o que falha, o que se perde e o que se elimina (`evidence_service`).

`test_evidencias.py` cobre o carregamento, o hash e a travessia de caminhos. Aqui
fica o resto do ciclo, e um defeito:

**A adulteração ficava auditada como sucesso.** Quando o ficheiro em disco já não
correspondia ao hash da recepção, a verificação dizia-o na resposta mas registava
a auditoria com resultado SUCESSO. O ficheiro em falta ficava FALHA. Quem
procurasse na auditoria as verificações falhadas (`resultado=FALHA`) via o
ficheiro perdido e não via o adulterado — que é precisamente o caso grave.

Estes testes guardam os ficheiros numa pasta temporária, e não em `var/evidence`.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.system import AuditLog
from app.services import evidence_service
from tests.conftest import cabecalho


@pytest.fixture(autouse=True)
def armazenamento(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_storage_path", tmp_path)
    return tmp_path


async def _incidente(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": "Incidente com provas", "description": "x",
              "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _carregar(cliente, token, incidente, *, nome="auth.log", conteudo=b"linha de log\n"):
    return await cliente.post(
        "/api/evidence",
        data={"incident_id": incidente["id"], "tipo": "LOG"},
        files={"ficheiro": (nome, conteudo, "application/octet-stream")},
        headers=cabecalho(token),
    )


def _ficheiros(pasta) -> list:
    return [p for p in pasta.rglob("*") if p.is_file()]


async def _verificacoes(sessao, evidencia_id) -> list[AuditLog]:
    return (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "VERIFICAR_INTEGRIDADE",
                AuditLog.resource_id == uuid.UUID(evidencia_id),
            )
        )
    ).scalars().all()


# ------------------------------------------------------------- recepção
async def test_ficheiro_vazio_e_recusado_sem_deixar_nada_em_disco(
    cliente, token_analista, armazenamento
):
    incidente = await _incidente(cliente, token_analista)

    resposta = await _carregar(cliente, token_analista, incidente, conteudo=b"")

    assert resposta.status_code == 422
    assert resposta.json()["erro"]["codigo"] == "FICHEIRO_VAZIO"
    assert _ficheiros(armazenamento) == []


async def test_ficheiro_acima_do_limite_e_recusado_e_o_parcial_apagado(
    cliente, token_analista, armazenamento, monkeypatch
):
    """O limite é aplicado durante a leitura, e o que já foi escrito não fica."""
    monkeypatch.setattr(settings, "evidence_max_bytes", 16)
    incidente = await _incidente(cliente, token_analista)

    resposta = await _carregar(cliente, token_analista, incidente, conteudo=b"x" * 64)

    assert resposta.status_code == 413, resposta.text
    assert _ficheiros(armazenamento) == []


# ----------------------------------------------------------- integridade
async def test_ficheiro_perdido_da_integridade_falsa_e_fica_auditado(
    cliente, sessao, token_analista
):
    incidente = await _incidente(cliente, token_analista)
    evidencia = (await _carregar(cliente, token_analista, incidente)).json()
    registo = await evidence_service.get_evidence(sessao, uuid.UUID(evidencia["id"]))
    evidence_service.absolute_path_for(registo).unlink()

    resposta = await cliente.post(
        f"/api/evidence/{evidencia['id']}/verify", headers=cabecalho(token_analista)
    )

    assert resposta.json()["integra"] is False
    assert "não foi encontrado" in resposta.json()["detalhe"]
    await sessao.refresh(registo)
    assert registo.integrity_ok is False
    assert [v.outcome.value for v in await _verificacoes(sessao, evidencia["id"])] == ["FALHA"]


async def test_adulteracao_fica_auditada_como_falha(cliente, sessao, token_analista):
    """Regressão: o conteúdo alterado ficava registado com resultado SUCESSO."""
    incidente = await _incidente(cliente, token_analista)
    evidencia = (await _carregar(cliente, token_analista, incidente)).json()
    registo = await evidence_service.get_evidence(sessao, uuid.UUID(evidencia["id"]))
    evidence_service.absolute_path_for(registo).write_bytes(b"linha alterada\n")

    resposta = await cliente.post(
        f"/api/evidence/{evidencia['id']}/verify", headers=cabecalho(token_analista)
    )

    assert resposta.json()["integra"] is False
    [verificacao] = await _verificacoes(sessao, evidencia["id"])
    assert verificacao.outcome.value == "FALHA"
    assert verificacao.failure_reason


async def test_ficheiro_intacto_fica_auditado_como_sucesso(cliente, sessao, token_analista):
    incidente = await _incidente(cliente, token_analista)
    evidencia = (await _carregar(cliente, token_analista, incidente)).json()

    await cliente.post(
        f"/api/evidence/{evidencia['id']}/verify", headers=cabecalho(token_analista)
    )

    assert [v.outcome.value for v in await _verificacoes(sessao, evidencia["id"])] == ["SUCESSO"]


# ------------------------------------------------------------- eliminação
async def test_eliminar_apaga_o_ficheiro_e_preserva_nome_e_hash_na_auditoria(
    cliente, sessao, token_analista, token_admin, armazenamento
):
    incidente = await _incidente(cliente, token_analista)
    evidencia = (await _carregar(cliente, token_analista, incidente, nome="captura.pcap")).json()

    resposta = await cliente.delete(
        f"/api/evidence/{evidencia['id']}", headers=cabecalho(token_admin)
    )

    assert resposta.status_code == 200, resposta.text
    assert _ficheiros(armazenamento) == []
    entrada = (
        await sessao.execute(
            select(AuditLog).where(
                AuditLog.action == "ELIMINAR_EVIDENCIA",
                AuditLog.resource_id == uuid.UUID(evidencia["id"]),
            )
        )
    ).scalar_one()
    assert entrada.old_value["sha256"] == evidencia["sha256"]
    assert entrada.old_value["nome"] == "captura.pcap"
    detalhe = await cliente.get(
        f"/api/evidence/{evidencia['id']}", headers=cabecalho(token_analista)
    )
    assert detalhe.status_code == 404


async def test_so_quem_tem_permissao_elimina(cliente, token_analista, armazenamento):
    incidente = await _incidente(cliente, token_analista)
    evidencia = (await _carregar(cliente, token_analista, incidente)).json()

    resposta = await cliente.delete(
        f"/api/evidence/{evidencia['id']}", headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 403
    assert len(_ficheiros(armazenamento)) == 1


async def test_lista_as_evidencias_do_incidente(cliente, token_analista):
    incidente = await _incidente(cliente, token_analista)
    outro = await _incidente(cliente, token_analista)
    await _carregar(cliente, token_analista, incidente, nome="a.log")
    await _carregar(cliente, token_analista, incidente, nome="b.log")
    await _carregar(cliente, token_analista, outro, nome="c.log")

    resposta = await cliente.get(
        f"/api/evidence?incident_id={incidente['id']}", headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 200, resposta.text
    assert {e["original_filename"] for e in resposta.json()} == {"a.log", "b.log"}
