"""Grafo investigativo (`analytics_service.investigation_graph` e `ioc_graph`).

O grafo com profundidade 2 é o que a API oferece para ver uma campanha: juntam-se
os incidentes que partilham indicadores. Dois defeitos:

* **Uma relação entre incidentes aparecia duas vezes.** A aresta era desenhada a
  partir de cada um dos dois incidentes visitados, e `resumo.arestas` contava-a
  em dobro.
* **O grafo de um indicador inexistente devolvia 200** com um grafo vazio e
  `centro: null` — ao contrário do grafo de um incidente, que devolve 404. Um
  identificador errado parecia um indicador sem observações.
"""

from __future__ import annotations

import uuid

from tests.conftest import cabecalho


async def _incidente(cliente, token, titulo) -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": titulo, "description": "x", "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _indicador(cliente, token, valor, tipo="IP") -> dict:
    resposta = await cliente.post(
        "/api/iocs", json={"ioc_type": tipo, "value": valor}, headers=cabecalho(token)
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _observar(cliente, token, incidente, indicador, papel="ORIGEM"):
    resposta = await cliente.post(
        f"/api/incidents/{incidente['id']}/observations",
        json={"ioc_id": indicador["id"], "role": papel},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text


async def _grafo(cliente, token, incidente, profundidade=1) -> dict:
    resposta = await cliente.get(
        f"/api/graph/incident/{incidente['id']}?profundidade={profundidade}",
        headers=cabecalho(token),
    )
    assert resposta.status_code == 200, resposta.text
    return resposta.json()


def _incidentes(grafo) -> set[str]:
    return {n["rotulo"] for n in grafo["nos"] if n["tipo"] == "incidente"}


async def test_uma_relacao_aparece_uma_so_vez(cliente, token_analista):
    """Regressão: desenhada a partir de cada lado, a relação contava em dobro."""
    origem = await _incidente(cliente, token_analista, "Incidente de origem")
    destino = await _incidente(cliente, token_analista, "Incidente relacionado")
    relacao = await cliente.post(
        f"/api/incidents/{origem['id']}/relations",
        json={"target_incident_id": destino["id"], "relation_type": "RELACIONADO_COM",
              "rationale": "Mesma origem."},
        headers=cabecalho(token_analista),
    )
    assert relacao.status_code == 201, relacao.text

    grafo = await _grafo(cliente, token_analista, origem, profundidade=2)

    relacoes = [a for a in grafo["arestas"] if a["tipo"] == "relacionado"]
    assert len(relacoes) == 1, relacoes
    assert grafo["resumo"]["arestas"] == len(grafo["arestas"])


async def test_profundidade_2_junta_quem_partilha_um_indicador(cliente, token_analista):
    primeiro = await _incidente(cliente, token_analista, "Primeiro ataque")
    segundo = await _incidente(cliente, token_analista, "Segundo ataque")
    atacante = await _indicador(cliente, token_analista, "203.0.113.200")
    for incidente in (primeiro, segundo):
        await _observar(cliente, token_analista, incidente, atacante)

    raso = await _grafo(cliente, token_analista, primeiro, profundidade=1)
    fundo = await _grafo(cliente, token_analista, primeiro, profundidade=2)

    assert _incidentes(raso) == {primeiro["reference"]}
    assert _incidentes(fundo) == {primeiro["reference"], segundo["reference"]}
    papeis = {a["rotulo"] for a in raso["arestas"] if a["tipo"] == "observou"}
    assert papeis == {"ORIGEM"}


async def test_indicador_permitido_nao_liga_incidentes(cliente, token_analista):
    """Um servidor de actualizações partilhado por todos não é uma campanha."""
    primeiro = await _incidente(cliente, token_analista, "Primeiro")
    segundo = await _incidente(cliente, token_analista, "Segundo")
    benigno = await _indicador(cliente, token_analista, "198.51.100.250")
    for incidente in (primeiro, segundo):
        await _observar(cliente, token_analista, incidente, benigno, papel="DESTINO")
    await cliente.post(
        f"/api/iocs/{benigno['id']}/allowlist",
        json={"is_allowlisted": True, "reason": "Servidor de actualizações."},
        headers=cabecalho(token_analista),
    )

    fundo = await _grafo(cliente, token_analista, primeiro, profundidade=2)

    assert _incidentes(fundo) == {primeiro["reference"]}


async def test_grafo_do_indicador_mostra_onde_foi_visto_e_com_que_coocorre(
    cliente, token_analista
):
    primeiro = await _incidente(cliente, token_analista, "Com o indicador")
    segundo = await _incidente(cliente, token_analista, "Também com o indicador")
    central = await _indicador(cliente, token_analista, "203.0.113.201")
    vizinho = await _indicador(cliente, token_analista, "e" * 64, tipo="HASH_SHA256")
    for incidente in (primeiro, segundo):
        await _observar(cliente, token_analista, incidente, central)
    await _observar(cliente, token_analista, primeiro, vizinho, papel="PAYLOAD")

    resposta = await cliente.get(
        f"/api/graph/ioc/{central['id']}", headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 200, resposta.text
    grafo = resposta.json()
    assert grafo["centro"] == f"ioc:{central['id']}"
    assert _incidentes(grafo) == {primeiro["reference"], segundo["reference"]}
    coocorrencias = [a for a in grafo["arestas"] if a["tipo"] == "coocorre"]
    assert [a["destino"] for a in coocorrencias] == [f"ioc:{vizinho['id']}"]


async def test_grafo_de_indicador_inexistente_da_404(cliente, token_analista):
    """Regressão: devolvia 200 com um grafo vazio."""
    resposta = await cliente.get(
        f"/api/graph/ioc/{uuid.uuid4()}", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 404
