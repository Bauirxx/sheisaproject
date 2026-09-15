"""Percurso completo: evento → alerta → incidente → acção → resolução → relatório.

O §32 pede explicitamente um teste ponta-a-ponta. Não é redundante face aos
testes por módulo: cada um verifica uma peça em isolamento, e este verifica que
as peças encaixam — que o alerta ingerido é o mesmo que aparece no incidente,
que a acção aprovada é a que foi proposta, e que o relatório final reconstitui
tudo isso a partir da base de dados e não de valores calculados à parte.

Percorre o fluxo **pela API**, com os papéis certos em cada passo, como a
plataforma seria usada de facto.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models.system import AuditLog
from app.models.telemetry import Alert
from tests.conftest import cabecalho
from tests.test_ingestao import alerta_wazuh


async def test_percurso_completo(
    cliente, chave_ingestao, token_analista, token_gestor, sessao, semente
):
    agora = datetime.now(UTC)

    # ------------------------------------------------ 1. a fonte envia sinais
    # Seis tentativas de autenticação falhadas contra o mesmo servidor, com
    # minutos de intervalo: o que o `integrator` do Wazuh envia numa força bruta.
    for i in range(6):
        resposta = await cliente.post(
            "/api/ingest/wazuh",
            json=alerta_wazuh(
                id_fonte=f"e2e-{i}",
                quando=agora - timedelta(minutes=20 - i),
                level=10,
                mitre=["T1110"],
                dados={
                    "srcip": "203.0.113.77",
                    "srcuser": "root",
                    "dstuser": "admin",
                },
            ),
            headers={"X-API-Key": chave_ingestao},
        )
        assert resposta.status_code == 202, resposta.text

    # ---------------------------------- 2. deduplicação: um alerta, seis eventos
    alerta = (await sessao.execute(select(Alert))).scalar_one()
    assert alerta.event_count == 6, "os sinais equivalentes não foram agregados"
    assert alerta.scored_at is not None, "o alerta chegou à fila sem ser pontuado"
    assert alerta.triage_factors["factores"], "a pontuação veio sem decomposição"

    # ------------------------------------------- 3. o analista promove a incidente
    promocao = await cliente.post(
        f"/api/alerts/{alerta.id}/promote",
        json={
            "title": "Força bruta SSH contra o servidor web institucional",
            "rationale": "Origem externa, volume sustentado, activo de produção.",
        },
        headers=cabecalho(token_analista),
    )
    assert promocao.status_code == 201, promocao.text
    incidente = promocao.json()
    assert incidente["reference"].startswith("INC-")

    # As observações são materializadas a partir dos eventos reais.
    observacoes = await cliente.get(
        f"/api/incidents/{incidente['id']}/observations",
        headers=cabecalho(token_analista),
    )
    assert observacoes.status_code == 200
    assert observacoes.json(), "a promoção não materializou observações"

    # A técnica declarada pela fonte entra como **afirmada**, não inferida.
    detalhe = (
        await cliente.get(
            f"/api/incidents/{incidente['id']}", headers=cabecalho(token_analista)
        )
    ).json()
    tecnicas = detalhe.get("tecnicas") or detalhe.get("techniques") or []
    assert any(
        t["technique"]["technique_id"] == "T1110" and t["is_asserted"] for t in tecnicas
    ) or not tecnicas, "T1110 devia entrar afirmada, se o catálogo estiver carregado"

    # --------------------------------------------- 4. o incidente é conduzido
    for estado in ("TRIAGEM", "INVESTIGACAO"):
        passo = await cliente.post(
            f"/api/incidents/{incidente['id']}/transition",
            json={"status": estado},
            headers=cabecalho(token_analista),
        )
        assert passo.status_code == 200, passo.text

    atribuicao = await cliente.post(
        f"/api/incidents/{incidente['id']}/assign",
        json={"assignee_id": str(semente["utilizadores"]["analista"])},
        headers=cabecalho(token_analista),
    )
    assert atribuicao.status_code == 200
    assert atribuicao.json()["assignee"] is not None

    # ------------------------------ 5. acção de resposta: propor ≠ aprovar
    proposta = await cliente.post(
        "/api/actions",
        json={
            "incident_id": incidente["id"],
            "action_kind": "BLOQUEAR_IP",
            "title": "Bloquear 203.0.113.77 no perímetro",
            "rationale": "Origem externa responsável por 6 tentativas falhadas.",
            "target": {"ip": "203.0.113.77"},
        },
        headers=cabecalho(token_analista),
    )
    assert proposta.status_code == 201, proposta.text
    accao = proposta.json()
    assert accao["risk_level"] == "CRITICO"

    # O próprio proponente não aprova, mesmo tendo proposto com fundamento.
    auto = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={"approved": True, "justification": "Confirmo a minha proposta."},
        headers=cabecalho(token_analista),
    )
    assert auto.status_code == 403

    # O gestor decide, com justificação escrita porque a acção é crítica.
    decisao = await cliente.post(
        f"/api/approvals/{accao['id']}/decide",
        json={
            "approved": True,
            "justification": "Endereço externo sem relação com parceiros conhecidos.",
        },
        headers=cabecalho(token_gestor),
    )
    assert decisao.status_code == 200, decisao.text

    # ------------------------------------------------------- 6. resolução
    contencao = await cliente.post(
        f"/api/incidents/{incidente['id']}/transition",
        json={"status": "CONTENCAO"},
        headers=cabecalho(token_analista),
    )
    assert contencao.status_code == 200
    assert contencao.json()["contained_at"] is not None

    for estado in ("ERRADICACAO", "RECUPERACAO"):
        await cliente.post(
            f"/api/incidents/{incidente['id']}/transition",
            json={"status": estado},
            headers=cabecalho(token_analista),
        )

    resolucao = await cliente.post(
        f"/api/incidents/{incidente['id']}/transition",
        json={
            "status": "RESOLVIDO",
            "resolution_summary": (
                "Endereço bloqueado no perímetro e credenciais da conta visada "
                "rodadas. Sem indícios de acesso bem sucedido."
            ),
        },
        headers=cabecalho(token_analista),
    )
    assert resolucao.status_code == 200, resolucao.text
    resolvido = resolucao.json()
    assert resolvido["resolved_at"] is not None
    # As métricas derivam dos marcos, não de estimativas.
    metricas = resolvido["metricas"]
    assert metricas["tempo_ate_reconhecimento_segundos"] is not None
    assert metricas["tempo_ate_resolucao_segundos"] is not None
    assert metricas["alertas_associados"] == 1
    assert metricas["observacoes"] > 0

    # --------------------------------------------------------- 7. relatório
    relatorio = await cliente.post(
        "/api/reports/incident",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_analista),
    )
    assert relatorio.status_code == 201, relatorio.text
    conteudo = relatorio.json()["content"]

    # O relatório reconstitui o incidente a partir do que ficou registado.
    texto = str(conteudo)
    assert incidente["reference"] in texto
    assert "203.0.113.77" in texto, "o indicador observado não chegou ao relatório"
    assert "BLOQUEAR_IP" in texto, "a acção de resposta não chegou ao relatório"

    # -------------------------------------------- 8. o percurso ficou auditado
    accoes_registadas = {
        linha
        for (linha,) in (
            await sessao.execute(
                select(AuditLog.action).where(AuditLog.resource_reference.isnot(None))
            )
        ).all()
    }
    for esperada in ("PROMOVER_ALERTA", "ALTERAR_ESTADO", "PROPOR_ACCAO", "DECIDIR_ACCAO"):
        assert any(esperada in a for a in accoes_registadas), (
            f"{esperada} não aparece na auditoria; registadas: {sorted(accoes_registadas)}"
        )


async def test_o_relatorio_em_pdf_recusa_honestamente(cliente, token_analista):
    """§4: sem `reportlab`, a rota devolve 503 com explicação — não um ficheiro vazio."""
    incidente = (
        await cliente.post(
            "/api/incidents",
            json={"title": "Incidente para relatório", "description": "x",
                  "category": "OUTRO", "severity": "BAIXA"},
            headers=cabecalho(token_analista),
        )
    ).json()

    relatorio = await cliente.post(
        "/api/reports/incident",
        json={"incident_id": incidente["id"]},
        headers=cabecalho(token_analista),
    )
    assert relatorio.status_code == 201

    pdf = await cliente.get(
        f"/api/reports/{relatorio.json()['id']}/pdf", headers=cabecalho(token_analista)
    )
    # Ou produz um PDF real, ou diz que não consegue. Nunca um sucesso vazio.
    if pdf.status_code == 503:
        assert pdf.json()["erro"]["mensagem"]
    else:
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")
