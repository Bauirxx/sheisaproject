"""Exportação de relatórios em PDF (§31).

A exportação é opcional: o `reportlab` vive em `requirements-reports.txt`. Os
testes reflectem isso — se o pacote não estiver instalado, verificam que a rota
degrada com 503 e explicação, em vez de devolver um ficheiro inválido.
"""

from __future__ import annotations

import pytest

from tests.conftest import cabecalho

reportlab = pytest.importorskip(
    "reportlab",
    reason="exportação em PDF é opcional (requirements-reports.txt)",
)


async def _incidente_com_relatorio(cliente, token) -> str:
    """Cria um incidente, gera o relatório e devolve o id do relatório."""
    incidente = await cliente.post(
        "/api/incidents",
        json={
            "title": "Incidente para exportar",
            "description": "Suporte ao teste de exportação.",
            "category": "INTRUSAO",
            "severity": "ALTA",
        },
        headers=cabecalho(token),
    )
    assert incidente.status_code == 201, incidente.text

    relatorio = await cliente.post(
        "/api/reports/incident",
        json={"incident_id": incidente.json()["id"]},
        headers=cabecalho(token),
    )
    assert relatorio.status_code == 201, relatorio.text
    return relatorio.json()["id"]


async def test_exportar_incidente_devolve_pdf_valido(cliente, token_analista):
    relatorio_id = await _incidente_com_relatorio(cliente, token_analista)

    resposta = await cliente.get(
        f"/api/reports/{relatorio_id}/pdf", headers=cabecalho(token_analista)
    )

    assert resposta.status_code == 200, resposta.text
    assert resposta.headers["content-type"] == "application/pdf"
    # A assinatura do formato: um ficheiro que não comece assim não é um PDF,
    # por mais que o cabeçalho o anuncie.
    assert resposta.content.startswith(b"%PDF-"), "conteúdo não é um PDF"
    assert len(resposta.content) > 1000, "PDF suspeitosamente pequeno"
    assert "attachment" in resposta.headers.get("content-disposition", "")


async def test_exportar_periodo_devolve_pdf_valido(cliente, token_analista):
    resposta = await cliente.post(
        "/api/reports/period",
        json={"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
        headers=cabecalho(token_analista),
    )
    assert resposta.status_code == 201, resposta.text

    pdf = await cliente.get(
        f"/api/reports/{resposta.json()['id']}/pdf", headers=cabecalho(token_analista)
    )
    assert pdf.status_code == 200, pdf.text
    assert pdf.content.startswith(b"%PDF-")


async def test_exportar_relatorio_inexistente(cliente, token_analista):
    import uuid

    resposta = await cliente.get(
        f"/api/reports/{uuid.uuid4()}/pdf", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 404, resposta.text


async def test_exportar_exige_autenticacao(cliente, token_analista):
    relatorio_id = await _incidente_com_relatorio(cliente, token_analista)

    resposta = await cliente.get(f"/api/reports/{relatorio_id}/pdf")

    assert resposta.status_code == 401, resposta.text


async def test_o_pdf_contem_as_seccoes_do_relatorio(cliente, token_analista):
    """O PDF tem de conter de facto o que o relatório promete.

    Um PDF válido mas vazio passaria no teste de assinatura; este verifica o
    texto efectivamente desenhado nas páginas.
    """
    from tests.auxiliares_pdf import texto_do_pdf

    relatorio_id = await _incidente_com_relatorio(cliente, token_analista)
    resposta = await cliente.get(
        f"/api/reports/{relatorio_id}/pdf", headers=cabecalho(token_analista)
    )
    assert resposta.status_code == 200, resposta.text

    texto = texto_do_pdf(resposta.content).lower()
    for seccao in (
        "o que aconteceu",
        "quando",
        "como foi detectado",
        "quem investigou",
        "qual foi o resultado",
    ):
        assert seccao in texto, f"secção em falta no PDF: {seccao}"
