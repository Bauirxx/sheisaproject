"""Middlewares transversais: limitação de taxa, cabeçalhos de segurança, pedido.

A limitação de taxa não tinha nenhum teste — a fixture `rate_limit_ligado`
existia e ninguém a usava. Ao escrevê-los apareceu um defeito de segurança:

**O limite do login contornava-se com um cabeçalho.** A identidade de quem pede
era o `X-API-Key`, se viesse, e o IP só na falta dele — em qualquer rota,
incluindo `/auth/login`. Quem quisesse adivinhar palavras-passe só tinha de
mandar um `X-API-Key` diferente em cada tentativa: cada uma caía num balde novo
e o limite de 10 por minuto nunca chegava. A chave só identifica quem pede onde
é validada — na ingestão.

Cada teste usa um IP de origem próprio, porque a janela deslizante vive em
memória no middleware e atravessa os testes.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.main import app as fastapi_app


@pytest.fixture
async def de_ip(cliente, monkeypatch):
    """Fábrica de clientes com IP de origem escolhido e limitação ligada.

    Depende de `cliente` por causa das sessões de teste que ele instala.
    """
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    abertos: list[AsyncClient] = []

    async def fabricar(ip: str) -> AsyncClient:
        novo = AsyncClient(
            transport=ASGITransport(app=fastapi_app, client=(ip, 50000)),
            base_url="http://teste",
        )
        abertos.append(novo)
        return novo

    yield fabricar
    for aberto in abertos:
        await aberto.aclose()


async def _login_falhado(cliente, **cabecalhos):
    return await cliente.post(
        "/api/auth/login",
        json={"email": "ninguem@teste.local", "password": "NaoEstaCerta2026"},
        headers=cabecalhos,
    )


# ------------------------------------------------------ limitação de taxa
async def test_o_login_trava_ao_fim_do_limite(de_ip, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_auth_per_minute", 3)
    cliente = await de_ip("10.99.0.1")

    estados = [(await _login_falhado(cliente)).status_code for _ in range(3)]
    bloqueado = await _login_falhado(cliente)

    assert estados == [401, 401, 401]
    assert bloqueado.status_code == 429
    assert bloqueado.json()["erro"]["codigo"] == "DEMASIADOS_PEDIDOS"
    assert int(bloqueado.headers["Retry-After"]) >= 1


async def test_mudar_o_x_api_key_nao_contorna_o_limite_do_login(de_ip, monkeypatch):
    """Regressão: cada `X-API-Key` diferente abria um balde novo."""
    monkeypatch.setattr(settings, "rate_limit_auth_per_minute", 3)
    cliente = await de_ip("10.99.0.2")

    for _ in range(3):
        await _login_falhado(cliente, **{"X-API-Key": secrets.token_urlsafe(32)})
    quarta = await _login_falhado(cliente, **{"X-API-Key": secrets.token_urlsafe(32)})

    assert quarta.status_code == 429, "o limite do login foi contornado com X-API-Key"


async def test_outro_ip_tem_o_seu_proprio_limite(de_ip, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_auth_per_minute", 2)
    atacante = await de_ip("10.99.0.3")
    colega = await de_ip("10.99.0.4")

    for _ in range(3):
        await _login_falhado(atacante)

    assert (await _login_falhado(colega)).status_code == 401


async def test_fontes_de_ingestao_atras_do_mesmo_ip_tem_limites_separados(
    de_ip, monkeypatch
):
    """Na ingestão a chave identifica a fonte: várias podem sair pelo mesmo IP."""
    monkeypatch.setattr(settings, "rate_limit_ingest_per_minute", 2)
    cliente = await de_ip("10.99.0.5")
    wazuh, suricata = secrets.token_urlsafe(32), secrets.token_urlsafe(32)

    async def enviar(chave):
        return await cliente.post(
            "/api/ingest/events", json={"description": "x"}, headers={"X-API-Key": chave}
        )

    # Chaves que não existem: 401, mas contam para o limite como qualquer pedido.
    assert [(await enviar(wazuh)).status_code for _ in range(2)] == [401, 401]
    assert (await enviar(wazuh)).status_code == 429
    assert (await enviar(suricata)).status_code == 401


# ---------------------------------------------------- cabeçalhos e pedido
CABECALHOS_DE_SEGURANCA = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
}


async def test_cabecalhos_de_seguranca_em_respostas_de_sucesso_e_de_erro(cliente):
    for resposta in (
        await cliente.get("/api/health"),
        await cliente.get("/api/incidents"),  # 401, sem sessão
    ):
        for nome, valor in CABECALHOS_DE_SEGURANCA.items():
            assert resposta.headers.get(nome) == valor, (resposta.status_code, nome)
        assert "no-store" in resposta.headers["Cache-Control"]


async def test_a_resposta_429_tambem_leva_os_cabecalhos(de_ip, monkeypatch):
    """Regressão: o 429 saía antes de passar pelo middleware dos cabeçalhos."""
    monkeypatch.setattr(settings, "rate_limit_auth_per_minute", 1)
    cliente = await de_ip("10.99.0.6")

    await _login_falhado(cliente)
    bloqueado = await _login_falhado(cliente)

    assert bloqueado.status_code == 429
    for nome, valor in CABECALHOS_DE_SEGURANCA.items():
        assert bloqueado.headers.get(nome) == valor, nome


async def test_o_identificador_do_pedido_so_aceita_um_uuid_do_cliente(cliente):
    proprio = str(uuid.uuid4())

    ecoado = await cliente.get("/api/health", headers={"X-Request-Id": proprio})
    injectado = await cliente.get(
        "/api/health", headers={"X-Request-Id": "'; DROP TABLE audit_logs; --"}
    )
    sem_nada = await cliente.get("/api/health")

    assert ecoado.headers["X-Request-Id"] == proprio
    for resposta in (injectado, sem_nada):
        assert str(uuid.UUID(resposta.headers["X-Request-Id"])) == resposta.headers["X-Request-Id"]
    assert injectado.headers["X-Request-Id"] != sem_nada.headers["X-Request-Id"]


# ------------------------------------------------------- tempo de resposta
async def test_toda_a_resposta_leva_o_tempo_que_levou(cliente):
    """RNF07: o requisito pede tempo de resposta aceitável.

    Um requisito que não se mede não se pode afirmar cumprido. O número vai no
    cabeçalho, pelo que é observável em `curl` e no navegador — não é uma
    estatística que a plataforma calcula sobre si mesma e pede que se acredite.
    """
    resposta = await cliente.get("/api/health")

    assert "X-Tempo-Resposta-ms" in resposta.headers
    decorrido = float(resposta.headers["X-Tempo-Resposta-ms"])
    assert decorrido > 0, "uma duração de zero significa que nada foi medido"
    assert decorrido < 30_000, "a medição não pode devolver um valor absurdo"


async def test_tambem_mede_as_respostas_de_erro(cliente):
    """Um pedido que falha é o que mais interessa cronometrar.

    Se a medição vivesse dentro do tratamento do caso feliz, o pedido lento que
    acaba em erro — precisamente o suspeito — sairia sem número.
    """
    resposta = await cliente.get("/api/incidents")

    assert resposta.status_code == 401, resposta.text
    assert "X-Tempo-Resposta-ms" in resposta.headers


async def test_o_pedido_lento_fica_registado(cliente, monkeypatch):
    """O limiar existe para o registo apontar o que merece ser olhado.

    Baixa-se o limiar a zero em vez de tornar um pedido lento de propósito: o
    que se verifica é a decisão de registar, não a lentidão.

    Substitui-se o `logger` do módulo em vez de usar o `caplog`, que nesta suite
    não devolve registo nenhum — nem de um `warning` emitido directamente no
    teste, apesar de o registo não estar desligado e de o `caplog` ter ouvintes
    ligados. A substituição também é mais directa sobre o que está a ser
    afirmado: que o middleware decide registar, e com que conteúdo.
    """
    from app.core import middleware

    chamadas: list[tuple] = []

    class LoggerDeTeste:
        def warning(self, *argumentos, **_) -> None:
            chamadas.append(argumentos)

    monkeypatch.setattr(middleware, "LIMIAR_DE_LENTIDAO_MS", 0.0)
    monkeypatch.setattr(middleware, "logger", LoggerDeTeste())

    await cliente.get("/api/health")

    assert chamadas, "com o limiar a zero, qualquer pedido devia ficar registado"
    modelo, metodo, caminho, decorrido, request_id = chamadas[0]
    assert "Pedido lento" in modelo
    assert (metodo, caminho) == ("GET", "/api/health")
    assert decorrido > 0
    # O identificador do pedido tem de constar, senão não se liga o registo à
    # entrada de auditoria correspondente.
    assert request_id != "desconhecido", (
        "o identificador do pedido não chegou ao registo — a medição está a "
        "correr por fora do RequestIdMiddleware"
    )


async def test_o_pedido_rapido_nao_enche_o_registo(cliente, monkeypatch):
    """Abaixo do limiar não se regista nada.

    Sem isto, o limiar não estaria a ser consultado e cada pedido deixaria uma
    linha — um registo que avisa de tudo não avisa de nada.
    """
    from app.core import middleware

    chamadas: list[tuple] = []

    class LoggerDeTeste:
        def warning(self, *argumentos, **_) -> None:
            chamadas.append(argumentos)

    monkeypatch.setattr(middleware, "LIMIAR_DE_LENTIDAO_MS", 60_000.0)
    monkeypatch.setattr(middleware, "logger", LoggerDeTeste())

    await cliente.get("/api/health")

    assert not chamadas, chamadas
