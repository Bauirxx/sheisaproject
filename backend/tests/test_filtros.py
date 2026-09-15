"""Listagens: filtros, paginação e ordenação (§27, §32).

A ordenação tem um teste de segurança e não apenas de funcionalidade. Aceitar um
nome de coluna arbitrário vindo do cliente permitiria ordenar por uma coluna
sensível — `password_hash`, por exemplo — e inferir o seu conteúdo a partir da
ordem devolvida, sem nunca a ler. Daí a lista branca.
"""

from __future__ import annotations

import pytest

from tests.conftest import cabecalho


async def _incidentes(cliente, token, quantos=5) -> list[dict]:
    criados = []
    for i in range(quantos):
        resposta = await cliente.post(
            "/api/incidents",
            json={
                "title": f"Incidente número {i} para filtragem",
                "description": f"Descrição do incidente {i}.",
                "category": "INTRUSAO" if i % 2 else "FRAUDE",
                "severity": "CRITICA" if i % 2 else "BAIXA",
            },
            headers=cabecalho(token),
        )
        assert resposta.status_code == 201, resposta.text
        criados.append(resposta.json())
    return criados


# ------------------------------------------------------------------ envelope
async def test_o_envelope_de_paginacao_e_coerente(cliente, token_analista):
    await _incidentes(cliente, token_analista, 5)

    resposta = await cliente.get(
        "/api/incidents?page=1&size=2", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200
    corpo = resposta.json()

    assert corpo["pagina"] == 1
    assert corpo["tamanho"] == 2
    assert len(corpo["itens"]) == 2
    assert corpo["total"] >= 5
    # O total de páginas deriva do total e do tamanho — não é contado à parte.
    assert corpo["total_paginas"] == (corpo["total"] + 1) // 2


async def test_paginas_seguintes_nao_repetem_registos(cliente, token_analista):
    await _incidentes(cliente, token_analista, 6)

    primeira = (
        await cliente.get(
            "/api/incidents?page=1&size=3&sort=reference",
            headers=cabecalho(token_analista),
        )
    ).json()
    segunda = (
        await cliente.get(
            "/api/incidents?page=2&size=3&sort=reference",
            headers=cabecalho(token_analista),
        )
    ).json()

    ids_primeira = {i["id"] for i in primeira["itens"]}
    ids_segunda = {i["id"] for i in segunda["itens"]}
    assert not ids_primeira & ids_segunda


async def test_o_total_respeita_o_filtro(cliente, token_analista):
    """O total é contado sobre a mesma consulta filtrada, não sobre a tabela."""
    await _incidentes(cliente, token_analista, 6)

    sem_filtro = (
        await cliente.get("/api/incidents?size=1", headers=cabecalho(token_analista))
    ).json()
    filtrado = (
        await cliente.get(
            "/api/incidents?size=1&severidade=CRITICA", headers=cabecalho(token_analista)
        )
    ).json()

    assert filtrado["total"] < sem_filtro["total"]
    assert filtrado["total"] == 3


# ------------------------------------------------------------------- filtros
async def test_filtrar_por_severidade(cliente, token_analista):
    await _incidentes(cliente, token_analista, 6)
    resposta = await cliente.get(
        "/api/incidents?severidade=CRITICA&size=50", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200
    assert all(i["severity"] == "CRITICA" for i in resposta.json()["itens"])


async def test_filtrar_por_varias_severidades(cliente, token_analista):
    await _incidentes(cliente, token_analista, 6)
    resposta = await cliente.get(
        "/api/incidents?severidade=CRITICA&severidade=BAIXA&size=50",
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 200
    valores = {i["severity"] for i in resposta.json()["itens"]}
    assert valores <= {"CRITICA", "BAIXA"}


async def test_filtrar_por_categoria(cliente, token_analista):
    await _incidentes(cliente, token_analista, 6)
    resposta = await cliente.get(
        "/api/incidents?categoria=FRAUDE&size=50", headers=cabecalho(token_analista)
    )
    assert all(i["category"] == "FRAUDE" for i in resposta.json()["itens"])


async def test_pesquisa_textual_incide_na_referencia_titulo_e_descricao(
    cliente, token_analista
):
    criados = await _incidentes(cliente, token_analista, 3)
    alvo = criados[0]

    por_referencia = await cliente.get(
        f"/api/incidents?q={alvo['reference']}", headers=cabecalho(token_analista)
    )
    assert por_referencia.json()["total"] == 1

    por_titulo = await cliente.get(
        "/api/incidents?q=número 1 para filtragem", headers=cabecalho(token_analista)
    )
    assert por_titulo.json()["total"] >= 1


async def test_filtrar_sem_responsavel(cliente, token_analista):
    await _incidentes(cliente, token_analista, 3)
    resposta = await cliente.get(
        "/api/incidents?sem_responsavel=true&size=50", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200
    assert all(i["assignee"] is None for i in resposta.json()["itens"])


async def test_apenas_activos_exclui_encerrados(cliente, token_analista):
    criados = await _incidentes(cliente, token_analista, 3)
    alvo = criados[0]
    await cliente.post(
        f"/api/incidents/{alvo['id']}/transition",
        json={
            "status": "FALSO_POSITIVO",
            "false_positive_reason": "Actividade autorizada.",
        },
        headers=cabecalho(token_analista),
    )

    activos = await cliente.get(
        "/api/incidents?apenas_activos=true&size=50", headers=cabecalho(token_analista)
    )
    ids = {i["id"] for i in activos.json()["itens"]}
    assert alvo["id"] not in ids


# ---------------------------------------------------------------- ordenação
async def test_ordenar_ascendente_e_descendente(cliente, token_analista):
    await _incidentes(cliente, token_analista, 4)

    ascendente = (
        await cliente.get(
            "/api/incidents?sort=reference&size=50", headers=cabecalho(token_analista)
        )
    ).json()["itens"]
    descendente = (
        await cliente.get(
            "/api/incidents?sort=-reference&size=50", headers=cabecalho(token_analista)
        )
    ).json()["itens"]

    referencias = [i["reference"] for i in ascendente]
    assert referencias == sorted(referencias)
    assert [i["reference"] for i in descendente] == sorted(referencias, reverse=True)


@pytest.mark.parametrize(
    "campo", ["password_hash", "id; DROP TABLE incidents", "role_id", "email"]
)
async def test_ordenar_por_campo_fora_da_lista_branca_e_recusado(
    cliente, token_analista, campo
):
    """Segurança, não cosmética: a ordem de uma listagem é um canal de fuga.

    Ordenar por `password_hash` não revela o hash directamente, mas revela a sua
    ordem relativa — e com pedidos suficientes, isso é suficiente para o
    reconstruir carácter a carácter.
    """
    resposta = await cliente.get(
        f"/api/incidents?sort={campo}", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 422
    assert resposta.json()["erro"]["codigo"] == "ORDENACAO_INVALIDA"
    # A resposta diz o que *é* permitido, para o cliente se corrigir.
    assert resposta.json()["erro"]["detalhes"]["campos_permitidos"]


async def test_limites_de_paginacao_sao_validados(cliente, token_analista):
    """`size` sem limite superior seria uma negação de serviço trivial."""
    demasiado = await cliente.get(
        "/api/incidents?size=100000", headers=cabecalho(token_analista)
    )
    assert demasiado.status_code == 422

    pagina_zero = await cliente.get(
        "/api/incidents?page=0", headers=cabecalho(token_analista)
    )
    assert pagina_zero.status_code == 422


async def test_filtros_de_alertas(cliente, chave_ingestao, token_analista):
    from tests.test_ingestao import alerta_wazuh

    for i, nivel in enumerate([3, 10, 14]):
        await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(id_fonte=f"f-{i}", level=nivel, agente=f"host-{i}"),
            headers={"X-API-Key": chave_ingestao},
        )

    todos = await cliente.get("/api/alerts?size=50", headers=cabecalho(token_analista))
    assert todos.json()["total"] == 3

    criticos = await cliente.get(
        "/api/alerts?size=50&severidade=CRITICA", headers=cabecalho(token_analista)
    )
    assert criticos.json()["total"] == 1
