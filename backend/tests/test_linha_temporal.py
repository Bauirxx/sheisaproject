"""Linha temporal do incidente.

É a vista que reconstitui o incidente do princípio ao fim, e é a que se mostra
numa defesa. Dois defeitos foram encontrados ao escrever estes testes, ambos
visíveis no cenário de demonstração:

**A ordem estava errada.** O `created_at` de comentários, evidências, tarefas e
acções usava `now()` do PostgreSQL, que devolve o **início da transacção** e não
a hora real. Tudo o que um mesmo pedido criasse ficava com esse instante — e
como a auditoria regista a hora real, "Estado alterado de RESOLVIDO para
ENCERRADO" aparecia **antes** de "Criar incidente". Nesta suite o efeito é
máximo, porque cada teste corre inteiro dentro de uma transacção.

**Cada mudança de estado aparecia duas vezes**: como comentário de sistema e
como entrada de auditoria. O mesmo com cada comentário.

A deduplicação é deliberadamente estreita. Só são duplicados os pares em que a
auditoria está ligada ao próprio incidente; quando está ligada à acção ou à
execução de playbook, o comentário de sistema é o único rasto no incidente e
tem de ficar — `test_a_decisao_de_accao_continua_na_linha_temporal` garante-o.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.conftest import autenticar, cabecalho


async def _incidente(cliente, token, titulo="Incidente da linha temporal") -> dict:
    resposta = await cliente.post(
        "/api/incidents",
        json={
            "title": titulo,
            "description": "Contexto.",
            "category": "INTRUSAO",
            "severity": "ALTA",
        },
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _linha(cliente, token, incidente_id) -> list[dict]:
    resposta = await cliente.get(
        f"/api/incidents/{incidente_id}/timeline", headers=cabecalho(token)
    )
    assert resposta.status_code == 200, resposta.text
    return resposta.json()


def _indice(linha: list[dict], predicado) -> int:
    for indice, entrada in enumerate(linha):
        if predicado(entrada):
            return indice
    raise AssertionError(
        "entrada não encontrada; a linha tem: "
        + " | ".join(f"{e['tipo']}:{e['titulo']}" for e in linha)
    )


# -------------------------------------------------------------- ordem
async def test_o_que_acontece_depois_aparece_depois(cliente, token_analista):
    """Regressão: `now()` datava tudo com o início da transacção."""
    incidente = await _incidente(cliente, token_analista)

    transicao = await cliente.post(
        f"/api/incidents/{incidente['id']}/transition",
        json={"status": "TRIAGEM"},
        headers=cabecalho(token_analista),
    )
    assert transicao.status_code == 200, transicao.text

    comentario = await cliente.post(
        f"/api/incidents/{incidente['id']}/comments",
        json={"body": "Observação escrita depois da triagem."},
        headers=cabecalho(token_analista),
    )
    assert comentario.status_code == 201, comentario.text

    linha = await _linha(cliente, token_analista, incidente["id"])

    criacao = _indice(linha, lambda e: e["titulo"] == "Criar incidente")
    triagem = _indice(
        linha, lambda e: "NOVO" in (e["detalhe"] or "") and "TRIAGEM" in (e["detalhe"] or "")
    )
    nota = _indice(linha, lambda e: e["detalhe"] == "Observação escrita depois da triagem.")

    assert criacao < triagem < nota, (
        f"ordem errada: criação na posição {criacao}, triagem na {triagem}, "
        f"comentário na {nota}"
    )


async def test_o_alerta_aparece_no_instante_do_primeiro_evento(
    cliente, chave_ingestao, token_analista, sessao
):
    """O instante de um alerta é quando a actividade ocorreu, não quando foi ligado.

    Três horas separam a detecção da promoção: a linha temporal tem de mostrar
    que o ataque começou antes de alguém abrir o incidente.
    """
    from sqlalchemy import select

    from app.models.telemetry import Alert
    from tests.test_ingestao import alerta_wazuh

    ha_tres_horas = datetime.now(UTC) - timedelta(hours=3)
    await cliente.post(
        "/api/ingest/wazuh",
        json=alerta_wazuh(id_fonte="linha-temporal-1", quando=ha_tres_horas),
        headers={"X-API-Key": chave_ingestao},
    )
    alerta = (await sessao.execute(select(Alert))).scalar_one()

    promocao = await cliente.post(
        f"/api/alerts/{alerta.id}/promote",
        json={"title": "Promovido para a linha temporal", "rationale": "Teste."},
        headers=cabecalho(token_analista),
    )
    assert promocao.status_code == 201, promocao.text

    linha = await _linha(cliente, token_analista, promocao.json()["id"])
    entrada = linha[_indice(linha, lambda e: e["tipo"] == "alerta")]

    instante = datetime.fromisoformat(entrada["instante"])
    assert abs((instante - ha_tres_horas).total_seconds()) < 5, (
        f"o alerta aparece em {instante}, e a actividade foi em {ha_tres_horas}"
    )
    # E vem antes da criação do incidente, que é o que conta a história certa.
    assert _indice(linha, lambda e: e["tipo"] == "alerta") < _indice(
        linha, lambda e: e["titulo"] == "Criar incidente"
    )


async def test_evidencias_e_tarefas_entram_na_narrativa(cliente, token_analista):
    """Quem investigou e que provas existem: as duas perguntas do §31 que faltavam."""
    import hashlib

    incidente = await _incidente(cliente, token_analista)
    conteudo = b"Jan 01 00:00:00 srv-web-01 sshd: Failed password for admin\n"
    evidencia = await cliente.post(
        "/api/evidence",
        data={"incident_id": incidente["id"], "tipo": "LOG", "descricao": "auth.log recolhido"},
        files={"ficheiro": ("auth.log", conteudo, "application/octet-stream")},
        headers=cabecalho(token_analista),
    )
    assert evidencia.status_code == 201, evidencia.text

    tarefa = await cliente.post(
        f"/api/tasks?incident_id={incidente['id']}",
        json={"title": "Rever acessos da origem"},
        headers=cabecalho(token_analista),
    )
    assert tarefa.status_code == 201, tarefa.text

    linha = await _linha(cliente, token_analista, incidente["id"])

    prova = linha[_indice(linha, lambda e: e["tipo"] == "evidencia")]
    assert prova["dados"]["sha256"] == hashlib.sha256(conteudo).hexdigest()
    assert prova["dados"]["tipo_evidencia"] == "LOG"
    assert prova["dados"]["bytes"] == len(conteudo)

    trabalho = linha[_indice(linha, lambda e: e["tipo"] == "tarefa")]
    assert trabalho["titulo"] == "Tarefa: Rever acessos da origem"
    assert trabalho["dados"]["estado"] == tarefa.json()["status"]

    criacao = _indice(linha, lambda e: e["titulo"] == "Criar incidente")
    assert criacao < linha.index(prova) < linha.index(trabalho)


# ---------------------------------------------------------- duplicação
async def test_cada_mudanca_de_estado_aparece_uma_so_vez(cliente, token_analista):
    """A mudança de estado fica como auditoria, que traz o valor anterior e o novo."""
    incidente = await _incidente(cliente, token_analista)
    await cliente.post(
        f"/api/incidents/{incidente['id']}/transition",
        json={"status": "TRIAGEM"},
        headers=cabecalho(token_analista),
    )

    linha = await _linha(cliente, token_analista, incidente["id"])
    mudancas = [
        e for e in linha
        if "NOVO" in (e["detalhe"] or "") and "TRIAGEM" in (e["detalhe"] or "")
    ]

    assert len(mudancas) == 1, (
        f"a mudança de estado aparece {len(mudancas)} vezes: "
        + " | ".join(f"{e['tipo']}:{e['detalhe']}" for e in mudancas)
    )
    unica = mudancas[0]
    assert unica["tipo"] == "auditoria"
    assert unica["dados"]["valor_anterior"] == {"estado": "NOVO"}
    assert unica["dados"]["valor_novo"] == {"estado": "TRIAGEM"}


async def test_cada_comentario_aparece_uma_so_vez(cliente, token_analista):
    """O comentário fica como comentário: a auditoria só diria "comentário adicionado"."""
    incidente = await _incidente(cliente, token_analista)
    texto = "Um comentário que tem de aparecer exactamente uma vez."
    await cliente.post(
        f"/api/incidents/{incidente['id']}/comments",
        json={"body": texto},
        headers=cabecalho(token_analista),
    )

    linha = await _linha(cliente, token_analista, incidente["id"])

    comentarios = [e for e in linha if e["detalhe"] == texto]
    assert len(comentarios) == 1
    assert comentarios[0]["tipo"] == "comentario"
    assert not [e for e in linha if e["titulo"] == "Comentar"], (
        "a auditoria do comentário continua na linha temporal a duplicá-lo"
    )


async def test_a_decisao_de_accao_continua_na_linha_temporal(
    cliente, token_analista, token_gestor
):
    """A deduplicação não pode apagar o que não é duplicado.

    A auditoria de uma decisão está ligada à acção, não ao incidente, pelo que
    não aparece na linha temporal. O comentário de sistema é o único rasto da
    decisão no incidente — se a deduplicação fosse "tirar todos os comentários
    de sistema", a aprovação desaparecia da história.
    """
    incidente = await _incidente(cliente, token_analista)
    accao = await cliente.post(
        "/api/actions",
        json={
            "incident_id": incidente["id"],
            "action_kind": "BLOQUEAR_IP",
            "title": "Bloquear origem",
            "rationale": "Origem externa responsável pelas tentativas.",
            "target": {"ip": "203.0.113.77"},
        },
        headers=cabecalho(token_analista),
    )
    assert accao.status_code == 201, accao.text

    decisao = await cliente.post(
        f"/api/approvals/{accao.json()['id']}/decide",
        json={"approved": True, "justification": "Origem confirmada."},
        headers=cabecalho(token_gestor),
    )
    assert decisao.status_code == 200, decisao.text

    linha = await _linha(cliente, token_analista, incidente["id"])
    referencia = accao.json()["reference"]
    assert [
        e for e in linha
        if e["tipo"] == "comentario" and "aprovada" in (e["detalhe"] or "")
        and referencia in (e["detalhe"] or "")
    ], "a aprovação da acção desapareceu da linha temporal"


# ------------------------------------------------------------ isolamento
async def test_a_linha_temporal_nao_mistura_incidentes(cliente, token_analista):
    primeiro = await _incidente(cliente, token_analista, "Primeiro incidente")
    segundo = await _incidente(cliente, token_analista, "Segundo incidente")

    texto = "Comentário que só pertence ao primeiro incidente."
    await cliente.post(
        f"/api/incidents/{primeiro['id']}/comments",
        json={"body": texto},
        headers=cabecalho(token_analista),
    )

    linha = await _linha(cliente, token_analista, segundo["id"])
    assert not [e for e in linha if e["detalhe"] == texto]
    assert not [e for e in linha if e["referencia"] == primeiro["reference"]]


async def test_incidente_inexistente_devolve_404(cliente, token_analista):
    import uuid

    resposta = await cliente.get(
        f"/api/incidents/{uuid.uuid4()}/timeline", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 404


async def test_exige_autenticacao(cliente):
    token = await autenticar(cliente, "analista")
    incidente = await _incidente(cliente, token)
    resposta = await cliente.get(f"/api/incidents/{incidente['id']}/timeline")
    assert resposta.status_code == 401
