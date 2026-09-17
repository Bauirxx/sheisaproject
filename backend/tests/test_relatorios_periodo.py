"""Relatórios de período e a sua exportação (`report_service`, `reports.py`, `pdf.py`).

Três defeitos, os dois primeiros num documento que se entrega como registo formal:

* **As métricas de resposta não eram as do período pedido.** O relatório contava
  os incidentes do intervalo, mas os tempos de reconhecimento e de resolução
  vinham de `response_metrics(days=...)`, que conta a partir de *hoje*. Um
  relatório de Janeiro gerado em Setembro mostrava os tempos dos últimos 31 dias,
  ao lado da lista de incidentes de Janeiro.
* **No PDF, esses tempos saíam em segundos e sem unidade** ("5400"), enquanto o
  resto do relatório os escreve legíveis ("1h 30min").
* **Um intervalo com um instante com fuso e outro sem ele dava 500**
  (`can't compare offset-naive and offset-aware datetimes`). Um instante sem fuso
  é ambíguo, e o resto da plataforma não os aceita em silêncio.
"""

from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.enums import IncidentStatus, ReportKind
from app.models.incident import Incident
from app.models.system import Report
from tests.auxiliares_pdf import texto_do_pdf
from tests.conftest import cabecalho

AGORA = datetime.now(UTC)


async def _incidente(cliente, sessao, token, *, titulo, detectado, reconhecido_apos):
    resposta = await cliente.post(
        "/api/incidents",
        json={"title": titulo, "description": "x", "category": "INTRUSAO", "severity": "ALTA"},
        headers=cabecalho(token),
    )
    assert resposta.status_code == 201, resposta.text
    incidente = await sessao.get(Incident, uuid.UUID(resposta.json()["id"]))
    incidente.detected_at = detectado
    incidente.acknowledged_at = detectado + reconhecido_apos
    incidente.status = IncidentStatus.TRIAGEM
    await sessao.flush()
    return incidente


async def _periodo(cliente, token, inicio: datetime, fim: datetime):
    return await cliente.post(
        "/api/reports/period",
        json={"start": inicio.isoformat(), "end": fim.isoformat()},
        headers=cabecalho(token),
    )


async def _dois_periodos(cliente, sessao, token):
    """Um incidente há 60 dias (reconhecido em 1h30) e outro recente (em 10 min)."""
    antigo = await _incidente(cliente, sessao, token, titulo="Incidente antigo",
                              detectado=AGORA - timedelta(days=60),
                              reconhecido_apos=timedelta(minutes=90))
    await _incidente(cliente, sessao, token, titulo="Incidente recente",
                     detectado=AGORA - timedelta(days=2),
                     reconhecido_apos=timedelta(minutes=10))
    return antigo


# --------------------------------------------------------------- métricas
async def test_as_metricas_sao_as_do_periodo_pedido(cliente, sessao, token_analista):
    """Regressão: eram as dos últimos N dias a contar de hoje."""
    antigo = await _dois_periodos(cliente, sessao, token_analista)

    resposta = await _periodo(cliente, token_analista,
                              AGORA - timedelta(days=70), AGORA - timedelta(days=50))

    assert resposta.status_code == 201, resposta.text
    conteudo = resposta.json()["content"]
    assert [i["referencia"] for i in conteudo["incidentes"]] == [antigo.reference]
    metricas = conteudo["metricas_de_resposta"]
    assert metricas["incidentes_reconhecidos"] == 1
    assert metricas["tempo_medio_reconhecimento_segundos"] == 90 * 60


async def test_o_pdf_escreve_os_tempos_de_resposta_legiveis(cliente, sessao, token_analista):
    """Regressão: saíam em segundos, sem unidade."""
    pytest.importorskip("reportlab")
    await _dois_periodos(cliente, sessao, token_analista)
    relatorio = (
        await _periodo(cliente, token_analista,
                       AGORA - timedelta(days=70), AGORA - timedelta(days=50))
    ).json()

    pdf = await cliente.get(f"/api/reports/{relatorio['id']}/pdf",
                            headers=cabecalho(token_analista))

    assert pdf.status_code == 200, pdf.text
    texto = texto_do_pdf(pdf.content)
    assert "1h 30min" in texto
    assert "5400" not in texto


# ---------------------------------------------------------------- pedido
@pytest.mark.parametrize(
    ("inicio", "fim"),
    [
        ("2026-09-01T00:00:00Z", "2026-09-17T00:00:00"),
        ("2026-09-01T00:00:00", "2026-09-17T00:00:00"),
    ],
    ids=["um-com-fuso-outro-sem", "ambos-sem-fuso"],
)
async def test_instantes_sem_fuso_sao_recusados(cliente, token_analista, inicio, fim):
    """Regressão: misturar os dois dava 500; sem fuso nenhum, eram tomados por UTC."""
    resposta = await cliente.post(
        "/api/reports/period", json={"start": inicio, "end": fim},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 422, resposta.text


@pytest.mark.parametrize(
    ("dias_inicio", "dias_fim"), [(0, 1), (400, 0)], ids=["fim-antes-do-inicio", "mais-de-um-ano"]
)
async def test_intervalos_invalidos_sao_recusados(cliente, token_analista, dias_inicio, dias_fim):
    resposta = await _periodo(cliente, token_analista,
                              AGORA - timedelta(days=dias_inicio), AGORA - timedelta(days=dias_fim))
    assert resposta.status_code == 422, resposta.text


# ------------------------------------------------------------ consulta
async def test_listar_filtrar_e_consultar_relatorios(cliente, sessao, token_analista):
    antigo = await _dois_periodos(cliente, sessao, token_analista)
    do_incidente = (
        await cliente.post("/api/reports/incident", json={"incident_id": str(antigo.id)},
                           headers=cabecalho(token_analista))
    ).json()
    await _periodo(cliente, token_analista, AGORA - timedelta(days=7), AGORA)

    async def referencias(consulta):
        resposta = await cliente.get(f"/api/reports?{consulta}", headers=cabecalho(token_analista))
        assert resposta.status_code == 200, resposta.text
        return {r["reference"] for r in resposta.json()["itens"]}

    assert do_incidente["reference"] in await referencias(f"incident_id={antigo.id}")
    assert do_incidente["reference"] not in await referencias("tipo=PERIODO")
    detalhe = await cliente.get(f"/api/reports/{do_incidente['id']}",
                                headers=cabecalho(token_analista))
    assert detalhe.json()["content"]["tipo"] == "relatorio_de_incidente"
    em_falta = await cliente.get(f"/api/reports/{uuid.uuid4()}", headers=cabecalho(token_analista))
    assert em_falta.status_code == 404


# ------------------------------------------------------------- exportação
async def test_sem_reportlab_a_exportacao_responde_503(
    cliente, sessao, token_analista, monkeypatch
):
    relatorio = (
        await _periodo(cliente, token_analista, AGORA - timedelta(days=7), AGORA)
    ).json()
    monkeypatch.setitem(sys.modules, "app.reporting.pdf", None)

    resposta = await cliente.get(f"/api/reports/{relatorio['id']}/pdf",
                                 headers=cabecalho(token_analista))

    assert resposta.status_code == 503, resposta.text
    assert resposta.json()["erro"]["codigo"] == "PDF_INDISPONIVEL"


async def test_relatorio_de_tipo_sem_apresentacao_continua_exportavel(
    cliente, sessao, token_analista
):
    pytest.importorskip("reportlab")
    registo = Report(
        reference="REL-TESTE-1", kind=ReportKind.PERIODO, title="Formato futuro",
        content={"tipo": "formato_futuro", "campo_novo": "valor preservado"},
        parameters={}, record_count=0,
    )
    sessao.add(registo)
    await sessao.flush()

    pdf = await cliente.get(f"/api/reports/{registo.id}/pdf", headers=cabecalho(token_analista))

    assert pdf.status_code == 200, pdf.text
    # O extractor devolve os acentos codificados; procuram-se frases sem eles.
    texto = texto_do_pdf(pdf.content)
    assert "dedicada em PDF" in texto
    assert "valor preservado" in texto
    assert (await sessao.execute(select(Report).where(Report.id == registo.id))).scalar_one()
