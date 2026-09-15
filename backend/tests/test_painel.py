"""Painel, centro de operações e grafo investigativo (§17, §21, §30).

A afirmação que estes endpoints fazem — "todos os valores são contados na base
de dados no momento do pedido, não há números em cache" — é verificável, e é
isso que aqui se faz: cria-se actividade real e confirma-se que os números se
movem com ela. Um painel que devolvesse constantes passaria num teste que só
verificasse o formato da resposta.
"""

from __future__ import annotations

from tests.conftest import cabecalho


async def _actividade(cliente, chave, token) -> dict:
    """Ingere alertas e promove um deles, para haver o que contar."""
    from tests.test_ingestao import alerta_wazuh

    for i, anfitriao in enumerate(["srv-web-01", "srv-bd-01", "est-financas-07"]):
        await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(
                id_fonte=f"painel-{i}", agente=anfitriao,
                dados={"srcip": f"203.0.113.{20 + i}", "srcuser": "root"},
            ),
            headers={"X-API-Key": chave},
        )

    alertas = (await cliente.get("/api/alerts?size=50", headers=cabecalho(token))).json()
    alvo = alertas["itens"][0]
    incidente = await cliente.post(
        f"/api/alerts/{alvo['id']}/promote",
        json={"title": "Incidente do painel", "rationale": "Actividade externa."},
        headers=cabecalho(token),
    )
    assert incidente.status_code == 201, incidente.text
    return incidente.json()


# ----------------------------------------------------------------- painel
async def test_o_painel_conta_a_actividade_real(
    cliente, chave_ingestao, token_analista
):
    vazio = await cliente.get("/api/dashboard", headers=cabecalho(token_analista))
    assert vazio.status_code == 200
    antes = vazio.json()

    await _actividade(cliente, chave_ingestao, token_analista)

    depois = (
        await cliente.get("/api/dashboard", headers=cabecalho(token_analista))
    ).json()
    assert depois != antes, "o painel não reflectiu a actividade criada"


async def test_o_painel_aceita_a_janela_de_analise(cliente, token_analista):
    resposta = await cliente.get(
        "/api/dashboard?dias=7", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200

    invalida = await cliente.get(
        "/api/dashboard?dias=0", headers=cabecalho(token_analista)
    )
    assert invalida.status_code == 422


async def test_distribuicoes(cliente, chave_ingestao, token_analista):
    await _actividade(cliente, chave_ingestao, token_analista)
    resposta = await cliente.get(
        "/api/dashboard/distribution", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text
    assert resposta.json()


async def test_metricas_de_resposta(cliente, token_analista):
    resposta = await cliente.get(
        "/api/dashboard/response-metrics", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text


async def test_tendencia_diaria(cliente, chave_ingestao, token_analista):
    await _actividade(cliente, chave_ingestao, token_analista)
    resposta = await cliente.get(
        "/api/dashboard/trend", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text


async def test_carga_por_analista(cliente, token_analista):
    resposta = await cliente.get(
        "/api/dashboard/workload", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text


# --------------------------------------------------- centro de operações
async def test_centro_de_operacoes_reune_o_trabalho_em_aberto(
    cliente, chave_ingestao, token_analista
):
    incidente = await _actividade(cliente, chave_ingestao, token_analista)

    resposta = await cliente.get("/api/soc", headers=cabecalho(token_analista))
    assert resposta.status_code == 200, resposta.text
    vista = resposta.json()

    texto = str(vista)
    assert incidente["reference"] in texto, (
        "o incidente acabado de criar não aparece no centro de operações"
    )


# -------------------------------------------------------------- grafo
async def test_grafo_do_incidente_tem_nos_e_arestas(
    cliente, chave_ingestao, token_analista
):
    """§21: o grafo é construído a partir das observações reais.

    Os nós têm de existir porque houve avistamentos, não porque o endpoint
    inventa uma estrutura para a interface desenhar.
    """
    incidente = await _actividade(cliente, chave_ingestao, token_analista)

    resposta = await cliente.get(
        f"/api/graph/incident/{incidente['id']}", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text
    grafo = resposta.json()

    nos = grafo.get("nos") or grafo.get("nodes") or []
    arestas = grafo.get("arestas") or grafo.get("edges") or []
    assert nos, "o grafo veio sem nós"
    assert arestas, "o grafo veio sem arestas"

    # Cada aresta liga nós que existem: um grafo com arestas soltas não é
    # desenhável e denuncia que foi construído por partes.
    identificadores = {n["id"] for n in nos}
    for aresta in arestas:
        origem = aresta.get("origem") or aresta.get("source") or aresta.get("de")
        destino = aresta.get("destino") or aresta.get("target") or aresta.get("para")
        assert origem in identificadores, f"aresta com origem inexistente: {aresta}"
        assert destino in identificadores, f"aresta com destino inexistente: {aresta}"


async def test_grafo_de_incidente_inexistente_devolve_404(cliente, token_analista):
    import uuid

    resposta = await cliente.get(
        f"/api/graph/incident/{uuid.uuid4()}", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 404


async def test_o_painel_exige_permissao(cliente, chave_ingestao):
    """Sem token não há painel — nem sequer os números agregados."""
    resposta = await cliente.get("/api/dashboard")
    assert resposta.status_code == 401
