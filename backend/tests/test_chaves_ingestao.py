"""Criação de chaves de ingestão (§26).

Estes testes existem por causa de um defeito real: `POST /integrations/api-keys`
devolvia 500 em qualquer pedido válido. O esquema de entrada `ApiKeyCreate`
herdava `ApiModel` — a base das **respostas**, que traz `use_enum_values=True` —
pelo que `payload.kind` chegava ao código como `str` e a leitura de
`payload.kind.value` levantava `AttributeError`. A rota nunca tinha sido
exercida por nenhum teste nem por nenhum ecrã, e por isso o defeito sobreviveu.

O que se verifica aqui é a cadeia inteira, e não apenas o código de estado: que
a chave é devolvida uma única vez, que a base de dados guarda apenas o hash, e
sobretudo que a chave **serve** — autentica ingestão a sério. Uma chave que é
criada mas não autentica nada seria uma funcionalidade apresentada como
implementada sem o estar (§4).
"""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import ApiKey
from tests.conftest import cabecalho
from tests.test_ingestao import alerta_wazuh


async def _criar(cliente, token, **campos):
    corpo = {
        "name": "Wazuh — laboratório",
        "kind": "WAZUH",
        "description": "chave de ingestão do laboratório",
    }
    corpo.update(campos)
    return await cliente.post(
        "/api/integrations/api-keys", json=corpo, headers=cabecalho(token)
    )


async def test_criar_chave_devolve_o_segredo_uma_vez(cliente, token_admin):
    """Regressão: este pedido devolvia 500 por causa da base do esquema."""
    resposta = await _criar(cliente, token_admin)
    assert resposta.status_code == 201, resposta.text

    corpo = resposta.json()
    # Os nomes destes campos são contrato com a interface: é por eles que o
    # formulário mostra a chave e explica o prefixo.
    for campo in ("id", "nome", "prefixo", "chave", "aviso"):
        assert campo in corpo, f"falta {campo} na resposta"

    assert corpo["chave"].startswith(corpo["prefixo"]), (
        "o prefixo deve ser o início da própria chave, senão não a identifica"
    )


async def test_a_base_de_dados_guarda_apenas_o_hash(
    cliente, token_admin, sessao: AsyncSession
):
    """A interface afirma-o ao utilizador; aqui prova-se que é verdade."""
    resposta = await _criar(cliente, token_admin)
    assert resposta.status_code == 201, resposta.text
    em_claro = resposta.json()["chave"]

    chave = (
        await sessao.execute(
            select(ApiKey).where(ApiKey.key_prefix == resposta.json()["prefixo"])
        )
    ).scalar_one()

    assert chave.key_hash != em_claro, "a chave em claro não pode ser persistida"
    assert chave.key_hash == hashlib.sha256(em_claro.encode()).hexdigest()
    assert em_claro not in (chave.name or "") + (chave.description or "")


async def test_a_chave_criada_autentica_ingestao_real(cliente, token_admin):
    """De pouco serviria criar uma chave que não abrisse nenhuma porta."""
    resposta = await _criar(cliente, token_admin)
    assert resposta.status_code == 201, resposta.text
    chave = resposta.json()["chave"]

    aceite = await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(id_fonte="chave-nova-1"),
        headers={"X-API-Key": chave},
    )
    assert aceite.status_code == 202, aceite.text
    assert aceite.json()["processados"] == 1

    recusado = await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(id_fonte="chave-nova-2"),
        headers={"X-API-Key": chave[:-4] + "0000"},
    )
    assert recusado.status_code == 401, (
        "uma chave alterada tem de ser recusada, senão o hash não está a ser comparado"
    )


async def test_fonte_desconhecida_e_recusada(cliente, token_admin):
    """O selector da interface só oferece fontes válidas; o servidor impõe-no."""
    resposta = await _criar(cliente, token_admin, kind="INVENTADA")
    assert resposta.status_code == 422, resposta.text


async def test_campo_desconhecido_e_recusado_em_voz_alta(cliente, token_admin):
    """`ApiInput` traz `extra='forbid'`: um nome trocado falha em vez de se perder."""
    resposta = await _criar(cliente, token_admin, nome="engano")
    assert resposta.status_code == 422, resposta.text


async def test_criar_chave_exige_permissao(cliente, token_analista):
    """Quem cria uma credencial de ingestão passa a poder injectar alertas."""
    resposta = await _criar(cliente, token_analista)
    assert resposta.status_code == 403, resposta.text
