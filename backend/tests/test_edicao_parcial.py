"""Edição parcial (PATCH) com `null` explícito.

Num PATCH, omitir um campo quer dizer "não mexer"; enviá-lo a `null` quer dizer
"apagar". Os esquemas de edição declaram todos os campos como opcionais, e cinco
rotas aplicavam o que viesse com `setattr` — incluindo `null` em colunas que a
base de dados exige preenchidas. O objecto ficava inválido e rebentava ao
serializar a resposta: **HTTP 500** para o que é um erro do cliente.

Confirmado na API a correr antes de corrigir: `PATCH /api/assets/{id}` com
`{"criticality": null}` devolveu 500 `ERRO_INTERNO`, e o activo ficou inalterado.

A interface não o desencadeia — só envia campos alterados —, mas a API é
documentada e é usada por máquinas. O último teste garante que a correcção não
foi longe demais: `null` num campo que admite vazio continua a limpá-lo.
"""

from __future__ import annotations

import pytest

from tests.conftest import cabecalho


async def _incidente(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": "Incidente editável", "description": "x",
              "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _activo(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/assets",
        json={"identifier": "srv-editavel-01", "name": "Servidor editável",
              "hostname": "srv-editavel-01"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _indicador(cliente, token) -> dict:
    resposta = await cliente.post(
        "/api/iocs", json={"ioc_type": "IP", "value": "203.0.113.200"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _tarefa(cliente, token) -> dict:
    incidente = await _incidente(cliente, token)
    resposta = await cliente.post(
        f"/api/tasks?incident_id={incidente['id']}",
        json={"title": "Tarefa editável"}, headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _rota(cliente, token, recurso, semente) -> str:
    if recurso == "incidente":
        return f"/api/incidents/{(await _incidente(cliente, token))['id']}"
    if recurso == "activo":
        return f"/api/assets/{(await _activo(cliente, token))['id']}"
    if recurso == "indicador":
        return f"/api/iocs/{(await _indicador(cliente, token))['id']}"
    if recurso == "tarefa":
        return f"/api/tasks/{(await _tarefa(cliente, token))['id']}"
    return f"/api/users/{semente['utilizadores']['investigador']}"


@pytest.mark.parametrize(
    ("recurso", "campo"),
    [
        ("incidente", "severity"),
        ("incidente", "title"),
        ("activo", "criticality"),
        ("activo", "name"),
        ("indicador", "reputation"),
        ("tarefa", "title"),
        ("tarefa", "status"),
        ("utilizador", "full_name"),
        ("utilizador", "is_active"),
    ],
)
async def test_null_num_campo_obrigatorio_e_recusado_com_422(
    cliente, token_admin, semente, recurso, campo
):
    rota = await _rota(cliente, token_admin, recurso, semente)

    resposta = await cliente.patch(rota, json={campo: None}, headers=cabecalho(token_admin))

    assert resposta.status_code == 422, resposta.text
    erro = resposta.json()["erro"]
    assert erro["codigo"] == "CAMPO_OBRIGATORIO"
    assert erro["detalhes"]["campos"] == [campo]


async def test_null_num_campo_que_admite_vazio_continua_a_limpa_lo(cliente, token_admin):
    activo = await _activo(cliente, token_admin)

    resposta = await cliente.patch(
        f"/api/assets/{activo['id']}", json={"hostname": None}, headers=cabecalho(token_admin)
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["hostname"] is None
