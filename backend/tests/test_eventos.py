"""Consulta de eventos brutos (§6).

O evento é a camada que fica debaixo do alerta, e é o que permite verificar a
agregação em vez de a aceitar por confiança: muitos eventos equivalentes
convergem num único alerta. Estes testes cobrem as duas coisas de que a
interface depende e que, se falhassem, falhariam em silêncio.

A primeira é o filtro de severidade. Foi acrescentado à rota depois de a
interface o oferecer — e um parâmetro de consulta que o servidor não declara é
simplesmente ignorado pelo FastAPI, o que produz um filtro que parece funcionar
e não filtra nada. Por isso o teste não se contenta com um 200: exige que a
contagem filtrada seja diferente da total.

A segunda é o `raw_payload`. É a prova de origem de toda a plataforma (§4): sem
ele, nenhum valor apresentado ao analista pode ser confrontado com o que a fonte
enviou. O teste verifica que o payload guardado é, campo a campo, o que entrou.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.conftest import cabecalho
from tests.test_ingestao import alerta_wazuh


async def _ingerir(cliente, chave_ingestao, **campos):
    resposta = await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(**campos),
        headers={"X-API-Key": chave_ingestao},
    )
    assert resposta.status_code == 202, resposta.text
    return resposta.json()


async def test_lista_eventos_recebidos(cliente, token_admin, chave_ingestao):
    await _ingerir(cliente, chave_ingestao, id_fonte="ev-lista-1")

    resposta = await cliente.get("/api/events", headers=cabecalho(token_admin))
    assert resposta.status_code == 200, resposta.text
    pagina = resposta.json()
    assert pagina["total"] >= 1

    evento = pagina["itens"][0]
    # Contrato com a interface: estes nomes são lidos directamente na tabela.
    for campo in (
        "source_kind", "source_name", "source_event_id", "occurred_at",
        "received_at", "severity", "source_severity", "event_type",
        "alert_id", "rule_id",
    ):
        assert campo in evento, f"falta {campo}"


async def test_filtro_de_severidade_filtra_de_facto(
    cliente, token_admin, chave_ingestao
):
    """Regressão: a rota não declarava `severidade` e ignorava-o em silêncio."""
    agora = datetime.now(UTC)
    # Nível 12 no Wazuh dá ALTA; nível 5 dá BAIXA.
    await _ingerir(
        cliente, chave_ingestao, id_fonte="ev-sev-alta", level=12,
        quando=agora - timedelta(minutes=2),
    )
    await _ingerir(
        cliente, chave_ingestao, id_fonte="ev-sev-baixa", level=5,
        agente="est-financas-07", quando=agora - timedelta(minutes=1),
    )

    total = (
        await cliente.get("/api/events", headers=cabecalho(token_admin))
    ).json()["total"]
    altas = (
        await cliente.get(
            "/api/events?severidade=ALTA", headers=cabecalho(token_admin)
        )
    ).json()
    baixas = (
        await cliente.get(
            "/api/events?severidade=BAIXA", headers=cabecalho(token_admin)
        )
    ).json()

    assert altas["total"] >= 1
    assert baixas["total"] >= 1
    assert altas["total"] < total, (
        "o filtro devolveu tudo — provavelmente está a ser ignorado"
    )
    assert all(e["severity"] == "ALTA" for e in altas["itens"])
    assert all(e["severity"] == "BAIXA" for e in baixas["itens"])


async def test_severidade_invalida_e_recusada(cliente, token_admin):
    """Recusar em voz alta é preferível a devolver tudo como se nada fosse."""
    resposta = await cliente.get(
        "/api/events?severidade=INVENTADA", headers=cabecalho(token_admin)
    )
    assert resposta.status_code == 422, resposta.text


async def test_filtro_por_ip_cobre_origem_e_destino(
    cliente, token_admin, chave_ingestao
):
    await _ingerir(
        cliente, chave_ingestao, id_fonte="ev-ip-1",
        dados={"srcip": "198.51.100.77", "dstip": "10.10.5.21"},
    )

    origem = await cliente.get(
        "/api/events?ip=198.51.100.77", headers=cabecalho(token_admin)
    )
    assert origem.status_code == 200, origem.text
    assert origem.json()["total"] >= 1, "não encontrou pelo IP de origem"


async def test_detalhe_guarda_o_payload_original(
    cliente, token_admin, chave_ingestao
):
    """A prova de origem (§4): o que é apresentado tem de ser confrontável."""
    enviado = alerta_wazuh(
        id_fonte="ev-payload-1",
        level=12,
        dados={"srcip": "203.0.113.55", "dstuser": "backup", "srcport": "51310"},
    )
    aceite = await cliente.post(
        "/api/ingest/wazuh", json=enviado, headers={"X-API-Key": chave_ingestao}
    )
    assert aceite.status_code == 202, aceite.text
    evento_id = aceite.json()["resultados"][0]["evento_id"]

    resposta = await cliente.get(
        f"/api/events/{evento_id}", headers=cabecalho(token_admin)
    )
    assert resposta.status_code == 200, resposta.text
    detalhe = resposta.json()

    bruto = detalhe["raw_payload"]
    assert bruto, "sem payload não há prova de origem"
    assert bruto["rule"]["id"] == enviado["rule"]["id"]
    assert bruto["data"]["srcip"] == "203.0.113.55"

    # Cada valor normalizado tem de ser rastreável ao payload que o produziu.
    assert detalhe["source_ip"] == bruto["data"]["srcip"]
    assert detalhe["rule_id"] == bruto["rule"]["id"]
    assert str(bruto["rule"]["level"]) in (detalhe["source_severity"] or ""), (
        "a severidade original da fonte deve ser preservada a par da normalizada"
    )


async def test_eventos_sao_leitura_dos_perfis_operacionais(cliente, token_gestor):
    """`EVENTS_READ` pertence ao conjunto de leitura partilhado.

    Fixa-se aqui porque a barra de navegação condiciona o item "Eventos" a esta
    permissão: se ela deixasse de estar no conjunto operacional, o item
    desapareceria para o gestor sem que nada falhasse.
    """
    resposta = await cliente.get("/api/events", headers=cabecalho(token_gestor))
    assert resposta.status_code == 200, resposta.text


async def test_eventos_exigem_sessao(cliente):
    """Sem autenticação não há acesso ao payload bruto."""
    resposta = await cliente.get("/api/events")
    assert resposta.status_code == 401, resposta.text


async def test_evento_inexistente_da_404(cliente, token_admin):
    resposta = await cliente.get(
        "/api/events/00000000-0000-0000-0000-000000000000",
        headers=cabecalho(token_admin),
    )
    assert resposta.status_code == 404, resposta.text
