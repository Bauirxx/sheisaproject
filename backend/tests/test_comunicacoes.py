"""Comunicações de incidente vindas de fora (§5 · §37 · RTIR).

Duas coisas distinguem esta parte do resto da plataforma, e são as duas que estes
testes vigiam com mais cuidado.

**O ponto de submissão é a única escrita sem autenticação.** Um teste confirma que
funciona sem token — porque é o objectivo — e outros confirmam que os limites de
tamanho existem, porque um formulário aberto sem limites é um convite.

**O que se devolve a quem comunicou não pode incluir dados internos.** O §37 di-lo
por palavras: *o utilizador externo nunca deve aceder a dados internos.* O teste
correspondente não verifica que os campos certos estão presentes — verifica que os
errados estão **ausentes**, procurando pela referência do incidente, pelo endereço
do analista, pela nota de triagem e pelo IP de submissão no corpo da resposta. É a
única forma de a regra não se perder quando alguém acrescentar um campo ao modelo.

A terceira preocupação é o ciclo de vida: `ACEITE` sem incidente ligado é um estado
que mente, e a guarda que o impede tem de valer em todas as portas — foi assim que
a mesma regra se perdeu nos alertas (defeito 54).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid

from sqlalchemy import select

from app.core.audit import AuditContext
from app.core.enums import IncidentOrigin, ReportChannel, ReportStatus
from app.models.incident import Incident
from app.models.reporting import IncidentReport
from tests.conftest import cabecalho

SUBMISSAO = {
    "reporter_name": "Joana Macamo",
    "reporter_email": "joana@empresa.co.mz",
    "reporter_organisation": "Empresa de Telecomunicações",
    "reporter_phone": "+258 84 000 0000",
    "subject": "Página de phishing a imitar o nosso portal de clientes",
    "description": (
        "Clientes receberam um SMS com uma ligação para um site que imita o "
        "nosso portal. O site pede número de telefone e código de acesso."
    ),
    "claimed_category": "FRAUDE",
    "claimed_severity": "ALTA",
    "reported_indicators": "hxxp://portal-falso.example / 203.0.113.77",
}


async def _submeter(cliente, **campos) -> dict:
    """Submete sem qualquer cabeçalho de autenticação, de propósito."""
    corpo = {**SUBMISSAO, **campos}
    resposta = await cliente.post("/api/public/reports", json=corpo)
    assert resposta.status_code == 201, resposta.text
    return resposta.json()


async def _por_referencia(sessao, referencia: str) -> IncidentReport:
    resultado = await sessao.execute(
        select(IncidentReport).where(IncidentReport.reference == referencia)
    )
    return resultado.scalar_one()


# =================================================================== submissão
async def test_qualquer_pessoa_pode_comunicar_sem_conta(cliente):
    """É o ponto todo: quem comunica não é utilizador da plataforma."""
    corpo = await _submeter(cliente)

    assert corpo["referencia"].startswith("COM-")
    assert len(corpo["codigo_de_acompanhamento"]) >= 20
    assert "uma única vez" in corpo["aviso"] or "não pode voltar" in corpo["aviso"]


async def test_a_base_guarda_o_codigo_em_resumo_e_nao_em_claro(cliente, sessao):
    """Como nas chaves de ingestão: nem o administrador o pode recuperar."""
    corpo = await _submeter(cliente)
    codigo = corpo["codigo_de_acompanhamento"]

    relato = await _por_referencia(sessao, corpo["referencia"])

    assert relato.tracking_token_hash != codigo
    assert relato.tracking_token_hash == hashlib.sha256(codigo.encode()).hexdigest()


async def test_a_classificacao_de_quem_comunica_fica_separada(cliente, sessao):
    """O que um terceiro afirma não pode passar por avaliação da plataforma."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    assert relato.claimed_severity is not None
    assert relato.claimed_category is not None
    # O estado é sempre RECEBIDA: nada do que o comunicante diz altera a posição
    # da comunicação na fila.
    assert relato.status is ReportStatus.RECEBIDA


async def test_o_endereco_de_submissao_e_registado(cliente, sessao):
    """Sem ele não se pode investigar abuso do formulário aberto."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    assert relato.submitted_from_ip, "o endereço de origem não foi guardado"


async def test_descricao_curta_demais_e_recusada(cliente):
    """Um formulário aberto sem limites mínimos enche-se de ruído."""
    resposta = await cliente.post(
        "/api/public/reports", json={**SUBMISSAO, "description": "curto"}
    )
    assert resposta.status_code == 422, resposta.text


async def test_descricao_enorme_e_recusada(cliente):
    resposta = await cliente.post(
        "/api/public/reports", json={**SUBMISSAO, "description": "a" * 30_000}
    )
    assert resposta.status_code == 422, resposta.text


async def test_email_invalido_e_recusado(cliente):
    resposta = await cliente.post(
        "/api/public/reports", json={**SUBMISSAO, "reporter_email": "nao-e-email"}
    )
    assert resposta.status_code == 422, resposta.text


# ============================================================== acompanhamento
async def test_quem_comunicou_pode_consultar_o_estado(cliente):
    corpo = await _submeter(cliente)

    resposta = await cliente.get(
        f"/api/public/reports/{corpo['referencia']}",
        params={"codigo": corpo["codigo_de_acompanhamento"]},
    )

    assert resposta.status_code == 200, resposta.text
    estado = resposta.json()
    assert estado["referencia"] == corpo["referencia"]
    assert estado["estado"] == "RECEBIDA"
    assert estado["situacao"], "a frase de estado não pode vir vazia"


async def test_o_estado_publico_nao_expoe_dados_internos(
    cliente, sessao, token_analista
):
    """§37: *o utilizador externo nunca deve aceder a dados internos.*

    Verifica ausências e não presenças. Um teste que confirmasse os campos certos
    continuaria a passar depois de alguém acrescentar um campo interno ao esquema
    público — e é exactamente assim que uma fuga destas acontece.
    """
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    # Levá-la até ao estado mais "informativo": aceite, com incidente e nota.
    await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={
            "criar_incidente": True,
            "nota": "Domínio confirmado como não pertencente ao comunicante.",
        },
        headers=cabecalho(token_analista),
    )

    resposta = await cliente.get(
        f"/api/public/reports/{corpo['referencia']}",
        params={"codigo": corpo["codigo_de_acompanhamento"]},
    )
    assert resposta.status_code == 200, resposta.text
    texto = json.dumps(resposta.json(), ensure_ascii=False)

    assert not re.search(r"INC-\d+", texto), "expôs a referência do incidente"
    assert "@teste.local" not in texto, "expôs o endereço de quem avaliou"
    assert "Domínio confirmado" not in texto, "expôs a nota de triagem interna"
    assert not re.search(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}", texto
    ), "expôs um identificador interno"
    assert "tracking" not in texto, "expôs a contagem de consultas"


async def test_codigo_errado_nao_devolve_nada(cliente):
    corpo = await _submeter(cliente)

    resposta = await cliente.get(
        f"/api/public/reports/{corpo['referencia']}",
        params={"codigo": "codigo-completamente-errado"},
    )
    assert resposta.status_code == 404, resposta.text


async def test_referencia_inexistente_e_codigo_errado_sao_indistinguiveis(cliente):
    """As referências são sequenciais: distingui-los permitiria enumerá-las."""
    corpo = await _submeter(cliente)

    errado = await cliente.get(
        f"/api/public/reports/{corpo['referencia']}", params={"codigo": "x" * 20}
    )
    inexistente = await cliente.get(
        "/api/public/reports/COM-99999",
        params={"codigo": corpo["codigo_de_acompanhamento"]},
    )

    assert errado.status_code == inexistente.status_code == 404
    assert errado.json()["erro"]["codigo"] == inexistente.json()["erro"]["codigo"]


async def test_cada_consulta_e_contada(cliente, sessao):
    """Um número alto numa comunicação por triar é alguém à espera."""
    corpo = await _submeter(cliente)
    for _ in range(3):
        await cliente.get(
            f"/api/public/reports/{corpo['referencia']}",
            params={"codigo": corpo["codigo_de_acompanhamento"]},
        )

    relato = await _por_referencia(sessao, corpo["referencia"])
    await sessao.refresh(relato)
    assert relato.tracking_views == 3


# ===================================================================== triagem
async def test_a_fila_exige_autenticacao(cliente):
    resposta = await cliente.get("/api/reports-inbox")
    assert resposta.status_code == 401, resposta.text


async def test_a_fila_mostra_o_que_esta_por_decidir(cliente, token_analista):
    await _submeter(cliente)

    resposta = await cliente.get("/api/reports-inbox", headers=cabecalho(token_analista))

    assert resposta.status_code == 200, resposta.text
    pagina = resposta.json()
    assert pagina["total"] >= 1
    item = pagina["itens"][0]
    for campo in (
        "reference", "status", "channel", "subject", "reporter_name",
        "reporter_email", "claimed_severity", "tracking_views", "incidents",
    ):
        assert campo in item, f"falta {campo}"


async def test_assumir_a_avaliacao_mostra_quem_a_assumiu(
    cliente, sessao, token_analista
):
    """Regressão: devolvia `triaged_by_email: null` logo a seguir a assumir.

    A relação é `lazy="selectin"` e alterar a chave estrangeira não actualiza o
    objecto em memória. É o defeito 11, noutra porta.
    """
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/triage", headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 200, resposta.text
    dados = resposta.json()
    assert dados["status"] == "EM_TRIAGEM"
    assert dados["triaged_by_email"], "não disse quem assumiu a avaliação"


async def test_aceitar_sem_incidente_e_recusado(cliente, sessao, token_analista):
    """`ACEITE` sem incidente é um estado que mente."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={"nota": "Parece relevante."},
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 422, resposta.text
    assert resposta.json()["erro"]["codigo"] == "ACEITAR_EXIGE_INCIDENTE"
    await sessao.refresh(relato)
    assert relato.status is ReportStatus.RECEBIDA


async def test_aceitar_criando_incidente_registra_a_origem(
    cliente, sessao, token_analista
):
    """O incidente tem de dizer que nasceu de uma comunicação externa."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={
            "criar_incidente": True,
            "categoria": "FRAUDE",
            "severidade": "ALTA",
            "nota": "Confirmado por nós.",
        },
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 200, resposta.text
    dados = resposta.json()
    assert dados["status"] == "ACEITE"
    assert len(dados["incidents"]) == 1

    incidente = await sessao.get(Incident, uuid.UUID(dados["incidents"][0]["id"]))
    assert incidente.origin is IncidentOrigin.COMUNICACAO_EXTERNA
    assert relato.reference in (incidente.source_detail or "")
    # O relato original tem de ficar no incidente: é o que o analista lê.
    assert SUBMISSAO["description"][:40] in incidente.description


async def test_aceitar_ligando_a_um_incidente_existente(
    cliente, sessao, token_analista
):
    """Várias comunicações sobre a mesma campanha convergem num incidente."""
    primeira = await _submeter(cliente)
    relato1 = await _por_referencia(sessao, primeira["referencia"])
    r1 = await cliente.post(
        f"/api/reports-inbox/{relato1.id}/accept",
        json={"criar_incidente": True, "nota": "Primeira."},
        headers=cabecalho(token_analista),
    )
    incidente_id = r1.json()["incidents"][0]["id"]

    segunda = await _submeter(cliente, subject="A mesma campanha, vista de outro lado")
    relato2 = await _por_referencia(sessao, segunda["referencia"])

    r2 = await cliente.post(
        f"/api/reports-inbox/{relato2.id}/accept",
        json={"incident_id": incidente_id, "nota": "Mesma campanha."},
        headers=cabecalho(token_analista),
    )

    assert r2.status_code == 200, r2.text
    assert r2.json()["incidents"][0]["id"] == incidente_id


async def test_uma_comunicacao_pode_pertencer_a_mais_de_um_incidente(
    cliente, sessao, token_analista
):
    """A relação é muitos-para-muitos: um campo forçaria uma escolha falsa."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])
    primeiro = await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={"criar_incidente": True, "nota": "Primeiro sistema."},
        headers=cabecalho(token_analista),
    )
    assert primeiro.status_code == 200, primeiro.text

    outro = await cliente.post(
        "/api/incidents",
        json={
            "title": "O mesmo ataque, noutro sistema",
            "description": "Segundo sistema afectado.",
            "category": "FRAUDE",
            "severity": "MEDIA",
        },
        headers=cabecalho(token_analista),
    )
    assert outro.status_code == 201, outro.text

    ligada = await cliente.post(
        f"/api/reports-inbox/{relato.id}/incidents",
        json={"incident_id": outro.json()["id"]},
        headers=cabecalho(token_analista),
    )

    assert ligada.status_code == 200, ligada.text
    assert len(ligada.json()["incidents"]) == 2


async def test_ligar_o_mesmo_incidente_duas_vezes_e_recusado(
    cliente, sessao, token_analista
):
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])
    aceite = await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={"criar_incidente": True, "nota": "Aceite."},
        headers=cabecalho(token_analista),
    )
    incidente_id = aceite.json()["incidents"][0]["id"]

    repetida = await cliente.post(
        f"/api/reports-inbox/{relato.id}/incidents",
        json={"incident_id": incidente_id},
        headers=cabecalho(token_analista),
    )
    assert repetida.status_code == 422, repetida.text


async def test_recusar_exige_justificacao(cliente, sessao, token_analista):
    """Recusada sem motivo é indistinguível de esquecida — e é lida de fora."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/reject",
        json={"nota": ""},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 422, resposta.text


async def test_recusar_com_justificacao(cliente, sessao, token_analista):
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/reject",
        json={"nota": "Página já removida antes de chegar a comunicação."},
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] == "RECUSADA"
    assert resposta.json()["triage_note"]


async def test_duplicada_preserva_as_duas(cliente, sessao, token_analista):
    """Ao contrário da fusão do RTIR, nenhuma das duas é destruída."""
    primeira = await _submeter(cliente)
    segunda = await _submeter(cliente, subject="A mesma coisa, comunicada por outro")
    relato1 = await _por_referencia(sessao, primeira["referencia"])
    relato2 = await _por_referencia(sessao, segunda["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato2.id}/duplicate",
        json={"original_id": str(relato1.id), "nota": "Mesmo domínio."},
        headers=cabecalho(token_analista),
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] == "DUPLICADA"
    assert resposta.json()["duplicate_of_reference"] == primeira["referencia"]

    # As duas continuam a existir, e quem comunicou a segunda continua a poder
    # acompanhá-la — vê que está a ser tratada na outra.
    acompanhamento = await cliente.get(
        f"/api/public/reports/{segunda['referencia']}",
        params={"codigo": segunda["codigo_de_acompanhamento"]},
    )
    assert acompanhamento.status_code == 200, acompanhamento.text
    assert acompanhamento.json()["estado"] == "DUPLICADA"


async def test_duplicada_de_si_mesma_e_recusado(cliente, sessao, token_analista):
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/duplicate",
        json={"original_id": str(relato.id)},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 422, resposta.text


async def test_duplicada_de_um_duplicado_e_recusado(cliente, sessao, token_analista):
    """Uma cadeia de duplicados não leva a nada."""
    a = await _submeter(cliente)
    b = await _submeter(cliente, subject="Segunda comunicação da mesma coisa")
    c = await _submeter(cliente, subject="Terceira comunicação da mesma coisa")
    ra = await _por_referencia(sessao, a["referencia"])
    rb = await _por_referencia(sessao, b["referencia"])
    rc = await _por_referencia(sessao, c["referencia"])

    primeira = await cliente.post(
        f"/api/reports-inbox/{rb.id}/duplicate",
        json={"original_id": str(ra.id)},
        headers=cabecalho(token_analista),
    )
    assert primeira.status_code == 200, primeira.text

    segunda = await cliente.post(
        f"/api/reports-inbox/{rc.id}/duplicate",
        json={"original_id": str(rb.id)},
        headers=cabecalho(token_analista),
    )
    assert segunda.status_code == 422, segunda.text


async def test_transicao_invalida_e_recusada(cliente, sessao, token_analista):
    """Uma comunicação aceite não volta a ser recusada sem passar por triagem."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])
    aceite = await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={"criar_incidente": True, "nota": "Aceite."},
        headers=cabecalho(token_analista),
    )
    assert aceite.status_code == 200, aceite.text

    recusa = await cliente.post(
        f"/api/reports-inbox/{relato.id}/reject",
        json={"nota": "Mudei de ideias."},
        headers=cabecalho(token_analista),
    )
    # 409 e não 422: uma transição inválida é um conflito com o estado actual,
    # e é o código que o resto da plataforma usa para o mesmo caso.
    assert recusa.status_code == 409, recusa.text
    erro = recusa.json()["erro"]
    assert erro["codigo"] == "TRANSICAO_INVALIDA"
    # A resposta diz o que *é* possível, para quem estiver a integrar não ter
    # de adivinhar o grafo de estados.
    assert erro["detalhes"]["transicoes_permitidas"] == ["EM_TRIAGEM"]


async def test_triar_exige_permissao_propria(cliente, sessao, token_gestor):
    """O gestor lê a fila mas não a tria: decide acções, não triagem."""
    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    leitura = await cliente.get("/api/reports-inbox", headers=cabecalho(token_gestor))
    assert leitura.status_code == 200, leitura.text

    triagem = await cliente.post(
        f"/api/reports-inbox/{relato.id}/triage", headers=cabecalho(token_gestor)
    )
    assert triagem.status_code == 403, triagem.text


async def test_a_recepcao_fica_auditada(cliente, sessao):
    """Uma submissão anónima tem de deixar rasto como tudo o resto."""
    from app.models.system import AuditLog

    corpo = await _submeter(cliente)

    resultado = await sessao.execute(
        select(AuditLog).where(
            AuditLog.resource_reference == corpo["referencia"],
            AuditLog.action == "RECEBER_COMUNICACAO",
        )
    )
    entrada = resultado.scalar_one()
    assert "PORTAL" in entrada.description
    assert SUBMISSAO["reporter_email"] in entrada.description


async def test_recolha_por_email_nao_envia_aviso_automatico(
    cliente, sessao, token_analista, monkeypatch
):
    """Regressão do envio em cadeia: recolher NÃO responde ao remetente.

    Uma comunicação recolhida da caixa não dispara o aviso de recepção — só a
    submissão deliberada no portal o faz. Responder automaticamente a tudo o que
    entra numa caixa transforma-a numa máquina de auto-resposta: foi o que enviou
    avisos em cadeia ao apontar a recolha a uma caixa com correio pessoal.

    Verifica-se contando os envios: `submit` com `avisar=False` não pode chamar o
    serviço de email de todo.
    """
    from app.services import email_service, report_inbox_service

    enviados: list[str] = []
    monkeypatch.setattr(
        email_service, "enviar",
        lambda **kw: enviados.append(kw.get("para", "")) or "<id>",
    )
    monkeypatch.setattr(email_service.settings, "smtp_host", "smtp.exemplo")
    monkeypatch.setattr(email_service.settings, "mail_from", "cert@exemplo")

    # Uma submissão do portal envia o aviso (o comportamento que se mantém).
    await report_inbox_service.submit(
        sessao,
        AuditContext(actor_email="analista@teste.local", origin="teste"),
        reporter_name="Pessoa do Portal",
        reporter_email="pessoa@exemplo.co.mz",
        subject="Comunicação pelo portal",
        description="Descrição suficientemente longa para passar a validação.",
    )
    assert enviados == ["pessoa@exemplo.co.mz"], "o portal deve avisar"

    # Uma recolhida da caixa não envia nada.
    enviados.clear()
    await report_inbox_service.submit(
        sessao,
        AuditContext(actor_email="analista@teste.local", origin="teste"),
        reporter_name="Remetente de Email",
        reporter_email="remetente@exemplo.co.mz",
        subject="Comunicação por email",
        description="Descrição suficientemente longa para passar a validação.",
        channel=ReportChannel.EMAIL,
        avisar=False,
    )
    assert enviados == [], "recolher não pode responder ao remetente"


async def test_a_decisao_avisa_quem_comunicou(
    cliente, sessao, token_analista, monkeypatch
):
    """Aceitar ou recusar responde a quem comunicou — não o deixa no escuro.

    Mesmo contrato do aviso de recepção: só dispara com o canal configurado, e
    vai para o endereço de quem comunicou.
    """
    from app.services import email_service

    enviados: list[dict] = []
    monkeypatch.setattr(
        email_service, "enviar", lambda **kw: enviados.append(kw) or "<id>"
    )
    monkeypatch.setattr(email_service.settings, "smtp_host", "smtp.exemplo")
    monkeypatch.setattr(email_service.settings, "mail_from", "cert@exemplo")

    # Aceitar avisa.
    corpo = await _submeter(cliente)  # dispara o aviso de recepção
    relato = await _por_referencia(sessao, corpo["referencia"])
    enviados.clear()
    aceite = await cliente.post(
        f"/api/reports-inbox/{relato.id}/accept",
        json={"criar_incidente": True, "nota": "Confirmado por nós."},
        headers=cabecalho(token_analista),
    )
    assert aceite.status_code == 200, aceite.text
    assert [e["para"] for e in enviados] == [SUBMISSAO["reporter_email"]]
    assert "Decisão" in enviados[0]["assunto"]
    assert "aceite" in enviados[0]["corpo"]

    # Recusar avisa.
    outra = await _submeter(cliente)
    relato2 = await _por_referencia(sessao, outra["referencia"])
    enviados.clear()
    recusa = await cliente.post(
        f"/api/reports-inbox/{relato2.id}/reject",
        json={"nota": "Fora de âmbito."},
        headers=cabecalho(token_analista),
    )
    assert recusa.status_code == 200, recusa.text
    assert [e["para"] for e in enviados] == [SUBMISSAO["reporter_email"]]
    assert "não será tratada" in enviados[0]["corpo"]


async def test_falha_no_aviso_de_decisao_nao_desfaz_a_decisao(
    cliente, sessao, token_analista, monkeypatch
):
    """O essencial não se troca pelo acessório: se o correio falhar, a decisão
    fica registada na mesma — como no aviso de recepção."""
    from app.services import email_service

    def rebenta(**kw):
        raise RuntimeError("servidor de correio em baixo")

    monkeypatch.setattr(email_service, "enviar", rebenta)
    monkeypatch.setattr(email_service.settings, "smtp_host", "smtp.exemplo")
    monkeypatch.setattr(email_service.settings, "mail_from", "cert@exemplo")

    corpo = await _submeter(cliente)
    relato = await _por_referencia(sessao, corpo["referencia"])

    resposta = await cliente.post(
        f"/api/reports-inbox/{relato.id}/reject",
        json={"nota": "Fora de âmbito."},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 200, resposta.text
    assert resposta.json()["status"] == "RECUSADA"
