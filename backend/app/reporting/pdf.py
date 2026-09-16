"""Exportação de relatórios em PDF (§31).

Opcional por construção: o `reportlab` está em `requirements-reports.txt` e não
nas dependências obrigatórias. Sem ele, a rota responde 503 com explicação em
vez de devolver um ficheiro inválido — o relatório continua disponível em JSON.

O PDF é gerado a partir do **conteúdo persistido** do relatório, não de uma
nova consulta à base de dados. Um relatório é um instantâneo: reconstruí-lo no
momento da exportação produziria um documento diferente do que foi apresentado
a quem o leu.

Sobre a apresentação: nenhuma secção vazia é escondida. "Nenhuma evidência foi
recolhida" é uma conclusão relevante num relatório de incidente, e omiti-la
deixaria o leitor sem saber se não houve evidências ou se ninguém as procurou.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models.system import Report

#: Paleta sóbria. Um relatório de incidente é lido impresso e fotocopiado;
#: cores fortes sobrevivem mal a ambos.
COR_TITULO = colors.HexColor("#1f2937")
COR_SECUNDARIA = colors.HexColor("#6b7280")
COR_LINHA = colors.HexColor("#d1d5db")
COR_FUNDO_CABECALHO = colors.HexColor("#f3f4f6")

SEVERIDADE_COR = {
    "CRITICA": colors.HexColor("#b91c1c"),
    "ALTA": colors.HexColor("#c2410c"),
    "MEDIA": colors.HexColor("#a16207"),
    "BAIXA": colors.HexColor("#15803d"),
    "INFO": colors.HexColor("#475569"),
}


def _estilos() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "titulo": ParagraphStyle(
            "TituloSheisa", parent=base["Title"], fontSize=18, spaceAfter=2 * mm,
            textColor=COR_TITULO, alignment=TA_LEFT,
        ),
        "subtitulo": ParagraphStyle(
            "SubtituloSheisa", parent=base["Normal"], fontSize=9,
            textColor=COR_SECUNDARIA, spaceAfter=6 * mm,
        ),
        "seccao": ParagraphStyle(
            "SeccaoSheisa", parent=base["Heading2"], fontSize=12,
            textColor=COR_TITULO, spaceBefore=6 * mm, spaceAfter=2 * mm,
        ),
        "corpo": ParagraphStyle(
            "CorpoSheisa", parent=base["Normal"], fontSize=9.5, leading=13,
            spaceAfter=1.5 * mm,
        ),
        "nota": ParagraphStyle(
            "NotaSheisa", parent=base["Normal"], fontSize=8.5, leading=11,
            textColor=COR_SECUNDARIA, spaceAfter=1.5 * mm,
        ),
        "mono": ParagraphStyle(
            "MonoSheisa", parent=base["Normal"], fontName="Courier", fontSize=8,
            leading=10, textColor=COR_SECUNDARIA,
        ),
    }


def _escapar(valor: Any) -> str:
    """Escapa texto para os marcadores do reportlab.

    Sem isto, um título de incidente que contenha `<` ou `&` — coisa banal em
    registos de segurança, onde aparecem payloads — partiria a geração ou
    seria interpretado como marcação.
    """
    if valor is None:
        return "—"
    texto = str(valor)
    return (
        texto.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _tabela_de_propriedades(linhas: list[tuple[str, Any]], estilos) -> Table:
    dados = [
        [
            Paragraph(f"<b>{_escapar(r)}</b>", estilos["nota"]),
            Paragraph(_escapar(v), estilos["corpo"]),
        ]
        for r, v in linhas
    ]
    tabela = Table(dados, colWidths=[45 * mm, 120 * mm])
    tabela.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, COR_LINHA),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ])
    )
    return tabela


def _tabela(cabecalhos: list[str], linhas: list[list[Any]], estilos,
            larguras: list[float] | None = None) -> Table:
    dados = [[Paragraph(f"<b>{_escapar(c)}</b>", estilos["nota"]) for c in cabecalhos]]
    dados += [[Paragraph(_escapar(c), estilos["nota"]) for c in linha] for linha in linhas]

    tabela = Table(dados, colWidths=larguras, repeatRows=1)
    tabela.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COR_FUNDO_CABECALHO),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, COR_LINHA),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    return tabela


def _rodape(canvas, documento) -> None:
    """Numeração e marca de origem em cada página."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(COR_SECUNDARIA)
    canvas.drawString(
        20 * mm, 12 * mm,
        "SHEISA — plataforma de gestão e resposta a incidentes cibernéticos",
    )
    canvas.drawRightString(190 * mm, 12 * mm, f"Página {documento.page}")
    canvas.setStrokeColor(COR_LINHA)
    canvas.line(20 * mm, 15 * mm, 190 * mm, 15 * mm)
    canvas.restoreState()


# ------------------------------------------------------ relatório de incidente
def _incidente(conteudo: dict, estilos) -> list:
    elementos: list = []
    e = elementos.append

    o_que = conteudo.get("o_que_aconteceu", {})
    quando = conteudo.get("quando", {})
    detectado = conteudo.get("como_foi_detectado", {})
    quem = conteudo.get("quem_investigou", {})
    evidencias = conteudo.get("que_evidencias_existem", {})
    indicadores = conteudo.get("indicadores_observados", {})
    mitre = conteudo.get("tecnicas_mitre", {})
    decisoes = conteudo.get("que_decisoes_foram_tomadas", [])
    accoes = conteudo.get("que_accoes_foram_executadas", {})
    resultado = conteudo.get("qual_foi_o_resultado", {})

    # --- 1 ---
    e(Paragraph("1. O que aconteceu", estilos["seccao"]))
    e(_tabela_de_propriedades([
        ("Referência", o_que.get("referencia")),
        ("Título", o_que.get("titulo")),
        ("Categoria", o_que.get("categoria")),
        ("Subtipo", o_que.get("subtipo")),
        ("Severidade", o_que.get("severidade")),
        ("Prioridade", o_que.get("prioridade")),
        ("Estado final", o_que.get("estado_final")),
        ("Confiança", o_que.get("confianca")),
    ], estilos))
    if descricao := o_que.get("descricao"):
        e(Spacer(1, 3 * mm))
        e(Paragraph(_escapar(descricao), estilos["corpo"]))

    activos = o_que.get("activos_afectados") or []
    e(Spacer(1, 3 * mm))
    if activos:
        e(_tabela(
            ["Activo afectado", "Nome", "Criticidade", "Endereço"],
            [[a.get("identificador"), a.get("nome"), a.get("criticidade"), a.get("ip")]
             for a in activos],
            estilos, [35 * mm, 60 * mm, 30 * mm, 40 * mm],
        ))
    else:
        e(Paragraph("Nenhum activo do inventário foi associado.", estilos["nota"]))

    # --- 2 ---
    e(Paragraph("2. Quando", estilos["seccao"]))
    e(_tabela_de_propriedades([
        ("Detectado", quando.get("detectado_em")),
        ("Reconhecido", quando.get("reconhecido_em")),
        ("Contido", quando.get("contido_em")),
        ("Erradicado", quando.get("erradicado_em")),
        ("Resolvido", quando.get("resolvido_em")),
        ("Encerrado", quando.get("encerrado_em")),
        ("Prazo", quando.get("prazo")),
        ("Até reconhecimento", quando.get("tempo_ate_reconhecimento")),
        ("Até resolução", quando.get("tempo_ate_resolucao")),
        ("Cumpriu o prazo",
         "sim" if quando.get("cumpriu_prazo") else
         ("não" if quando.get("cumpriu_prazo") is False else "—")),
    ], estilos))

    # --- 3 ---
    e(Paragraph("3. Como foi detectado", estilos["seccao"]))
    e(_tabela_de_propriedades([
        ("Origem", detectado.get("origem")),
        ("Fonte", detectado.get("fonte")),
        ("Detalhe", detectado.get("detalhe_da_fonte")),
        ("Eventos agregados", detectado.get("total_eventos")),
    ], estilos))
    alertas = detectado.get("alertas") or []
    e(Spacer(1, 3 * mm))
    if alertas:
        e(_tabela(
            ["Alerta", "Regra", "Severidade", "Eventos", "Pontuação"],
            [[a.get("referencia"), a.get("regra"), a.get("severidade"),
              a.get("eventos_agregados"), a.get("pontuacao_triagem")]
             for a in alertas],
            estilos, [28 * mm, 30 * mm, 28 * mm, 25 * mm, 25 * mm],
        ))
        # A justificação da triagem é o que torna a pontuação defensável.
        for a in alertas:
            if justificacao := a.get("justificacao_triagem"):
                e(Spacer(1, 1.5 * mm))
                e(Paragraph(
                    f"<b>{_escapar(a.get('referencia'))}</b>: {_escapar(justificacao)}",
                    estilos["nota"],
                ))
    if nota := detectado.get("nota"):
        e(Paragraph(_escapar(nota), estilos["nota"]))

    # --- 4 ---
    e(Paragraph("4. Quem investigou", estilos["seccao"]))
    participantes = quem.get("participantes") or []
    e(_tabela_de_propriedades([
        ("Responsável", quem.get("responsavel")),
        ("Equipa", quem.get("equipa")),
        ("Registado por", quem.get("registado_por")),
        ("Participantes", ", ".join(participantes) if participantes else "—"),
        ("Comentários", quem.get("comentarios")),
        ("Notas do sistema", quem.get("notas_do_sistema")),
    ], estilos))

    # --- 5 ---
    e(Paragraph("5. Que evidências existem", estilos["seccao"]))
    itens = evidencias.get("itens") or []
    if itens:
        e(_tabela(
            ["Nome", "Tipo", "Bytes", "Íntegra", "Recolhida por"],
            [[i.get("nome"), i.get("tipo"), i.get("bytes"),
              "sim" if i.get("integra") else ("não" if i.get("integra") is False else "—"),
              i.get("recolhida_por")]
             for i in itens],
            estilos, [50 * mm, 30 * mm, 22 * mm, 20 * mm, 43 * mm],
        ))
        # O hash completo é o que dá valor probatório: vai por extenso.
        e(Spacer(1, 2 * mm))
        for i in itens:
            e(Paragraph(
                f"{_escapar(i.get('nome'))} — SHA-256: {_escapar(i.get('sha256'))}",
                estilos["mono"],
            ))
    else:
        e(Paragraph(
            _escapar(evidencias.get("nota", "Nenhuma evidência foi recolhida.")),
            estilos["nota"],
        ))

    # --- indicadores e MITRE ---
    e(Paragraph("6. Indicadores observados", estilos["seccao"]))
    ind = indicadores.get("itens") or []
    if ind:
        e(_tabela(
            ["Tipo", "Valor", "Papel", "Reputação", "Origem"],
            [[i.get("tipo"), i.get("valor"), i.get("papel"), i.get("reputacao"),
              i.get("origem_do_registo")] for i in ind],
            estilos, [26 * mm, 55 * mm, 24 * mm, 28 * mm, 32 * mm],
        ))
    else:
        e(Paragraph("Nenhum indicador foi observado.", estilos["nota"]))

    e(Paragraph("7. Técnicas MITRE ATT&CK", estilos["seccao"]))
    afirmadas = mitre.get("afirmadas") or []
    hipoteses = mitre.get("hipoteses") or []
    if afirmadas:
        e(Paragraph("<b>Afirmadas</b> — declaradas pela fonte ou confirmadas:",
                    estilos["corpo"]))
        e(_tabela(
            ["Técnica", "Nome", "Confiança"],
            [[t.get("tecnica"), t.get("nome"), t.get("confianca")] for t in afirmadas],
            estilos, [28 * mm, 90 * mm, 47 * mm],
        ))
    if hipoteses:
        e(Spacer(1, 2 * mm))
        e(Paragraph("<b>Hipóteses do motor</b> — não confirmam que a técnica "
                    "ocorreu:", estilos["corpo"]))
        e(_tabela(
            ["Técnica", "Nome", "Confiança"],
            [[t.get("tecnica"), t.get("nome"), t.get("confianca")] for t in hipoteses],
            estilos, [28 * mm, 90 * mm, 47 * mm],
        ))
    if not afirmadas and not hipoteses:
        e(Paragraph("Nenhuma técnica foi associada a este incidente.", estilos["nota"]))

    # --- 8 ---
    e(Paragraph("8. Que decisões foram tomadas", estilos["seccao"]))
    if decisoes:
        e(_tabela(
            ["Instante", "Acção", "Autor", "Descrição"],
            [[d.get("instante"), d.get("accao"), d.get("autor"), d.get("descricao")]
             for d in decisoes],
            estilos, [34 * mm, 30 * mm, 38 * mm, 63 * mm],
        ))
    else:
        e(Paragraph("Nenhuma decisão registada.", estilos["nota"]))

    # --- 9 ---
    e(Paragraph("9. Que acções foram executadas", estilos["seccao"]))
    lista_accoes = accoes.get("accoes") or []
    if lista_accoes:
        e(_tabela(
            ["Acção", "Tipo", "Risco", "Estado", "Executada"],
            [[a.get("referencia"), a.get("tipo"), a.get("risco"), a.get("estado"),
              a.get("executada_em")] for a in lista_accoes],
            estilos, [26 * mm, 42 * mm, 24 * mm, 30 * mm, 43 * mm],
        ))
        # As aprovações são o que prova que a decisão foi humana.
        for a in lista_accoes:
            for ap in a.get("aprovacoes") or []:
                e(Spacer(1, 1 * mm))
                e(Paragraph(
                    f"{_escapar(a.get('referencia'))}: {_escapar(ap.get('decisao'))}"
                    f" — {_escapar(ap.get('justificacao') or 'sem justificação')}",
                    estilos["nota"],
                ))
    else:
        e(Paragraph("Nenhuma acção de resposta foi proposta.", estilos["nota"]))

    playbooks = accoes.get("playbooks") or []
    if playbooks:
        e(Spacer(1, 2 * mm))
        e(_tabela(
            ["Execução", "Playbook", "Estado"],
            [[p.get("referencia"), p.get("playbook"), p.get("estado")] for p in playbooks],
            estilos, [28 * mm, 90 * mm, 47 * mm],
        ))

    # --- 10 ---
    e(Paragraph("10. Qual foi o resultado", estilos["seccao"]))
    tarefas = resultado.get("tarefas", {})
    e(_tabela_de_propriedades([
        ("Estado final", resultado.get("estado_final")),
        ("Acções executadas", resultado.get("accoes_executadas")),
        ("Acções falhadas", resultado.get("accoes_falhadas")),
        ("Acções rejeitadas", resultado.get("accoes_rejeitadas")),
        ("Tarefas", f"{tarefas.get('concluidas', 0)} de {tarefas.get('total', 0)} concluídas"),
    ], estilos))
    for rotulo, chave in (
        ("Resumo da resolução", "resumo_da_resolucao"),
        ("Motivo do falso positivo", "motivo_falso_positivo"),
        ("Lições aprendidas", "licoes_aprendidas"),
    ):
        if texto := resultado.get(chave):
            e(Spacer(1, 2 * mm))
            e(Paragraph(f"<b>{rotulo}</b>", estilos["corpo"]))
            e(Paragraph(_escapar(texto), estilos["corpo"]))
    if nota := resultado.get("nota"):
        e(Paragraph(_escapar(nota), estilos["nota"]))

    return elementos


# -------------------------------------------------------- relatório de período
def _periodo(conteudo: dict, estilos) -> list:
    elementos: list = []
    e = elementos.append

    periodo = conteudo.get("periodo", {})
    totais = conteudo.get("totais", {})
    distribuicao = conteudo.get("distribuicao", {})
    metricas = conteudo.get("metricas_de_resposta", {})
    incidentes = conteudo.get("incidentes") or []

    e(Paragraph("Período", estilos["seccao"]))
    e(_tabela_de_propriedades([
        ("Início", periodo.get("inicio")),
        ("Fim", periodo.get("fim")),
        ("Dias", periodo.get("dias")),
        ("Incidentes", totais.get("incidentes")),
        ("Alertas", totais.get("alertas")),
        ("Acções", totais.get("accoes")),
    ], estilos))

    for titulo, chave in (
        ("Por severidade", "por_severidade"),
        ("Por categoria", "por_categoria"),
        ("Por estado", "por_estado"),
    ):
        dados = distribuicao.get(chave) or {}
        if dados:
            e(Paragraph(titulo, estilos["seccao"]))
            e(_tabela(
                ["Valor", "Incidentes"],
                [[k, v] for k, v in sorted(dados.items(), key=lambda x: -x[1])],
                estilos, [110 * mm, 55 * mm],
            ))

    e(Paragraph("Tempos de resposta", estilos["seccao"]))
    cumprimento = metricas.get("cumprimento_prazo", {})
    e(_tabela_de_propriedades([
        ("Reconhecimento (médio)", metricas.get("tempo_medio_reconhecimento_segundos")),
        ("Reconhecimento (mediano)", metricas.get("tempo_mediano_reconhecimento_segundos")),
        ("Resolução (médio)", metricas.get("tempo_medio_resolucao_segundos")),
        ("Resolução (mediano)", metricas.get("tempo_mediano_resolucao_segundos")),
        ("Dentro do prazo",
         f"{cumprimento.get('dentro_do_prazo', 0)} de {cumprimento.get('avaliados', 0)}"),
    ], estilos))
    if nota := metricas.get("nota"):
        e(Paragraph(_escapar(nota), estilos["nota"]))

    if incidentes:
        e(PageBreak())
        e(Paragraph("Incidentes do período", estilos["seccao"]))
        e(_tabela(
            ["Referência", "Título", "Severidade", "Estado", "Resolução"],
            [[i.get("referencia"), i.get("titulo"), i.get("severidade"),
              i.get("estado"), i.get("tempo_ate_resolucao")] for i in incidentes],
            estilos, [26 * mm, 62 * mm, 24 * mm, 28 * mm, 25 * mm],
        ))

    return elementos


def render_report_pdf(report: Report) -> bytes:
    """Gera o PDF de um relatório persistido."""
    estilos = _estilos()
    buffer = BytesIO()

    documento = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=18 * mm, bottomMargin=22 * mm,
        title=report.title,
        author="SHEISA",
        subject=f"Relatório {report.reference}",
    )

    elementos: list = [
        Paragraph(_escapar(report.title), estilos["titulo"]),
        Paragraph(
            f"{_escapar(report.reference)} · {_escapar(report.kind)} · gerado em "
            f"{report.created_at.strftime('%Y-%m-%d %H:%M UTC')}",
            estilos["subtitulo"],
        ),
    ]

    conteudo = report.content or {}
    tipo = conteudo.get("tipo")

    if tipo == "relatorio_de_incidente":
        elementos += _incidente(conteudo, estilos)
    elif tipo == "relatorio_de_periodo":
        elementos += _periodo(conteudo, estilos)
    else:
        # Tipo desconhecido: em vez de falhar, apresentamos o que existe. Um
        # relatório guardado não deve tornar-se inexportável porque um formato
        # novo ainda não tem apresentação dedicada.
        elementos.append(Paragraph(
            "Este relatório não tem apresentação dedicada em PDF. O conteúdo "
            "integral está disponível em JSON através da API.",
            estilos["nota"],
        ))
        for chave, valor in conteudo.items():
            elementos.append(Paragraph(f"<b>{_escapar(chave)}</b>", estilos["corpo"]))
            elementos.append(Paragraph(_escapar(valor)[:2000], estilos["nota"]))

    elementos.append(Spacer(1, 6 * mm))
    elementos.append(KeepTogether(Paragraph(
        "Documento gerado a partir dos registos da plataforma. Os valores "
        "apresentados provêm da base de dados no momento em que o relatório foi "
        "produzido e não foram recalculados nesta exportação.",
        estilos["nota"],
    )))

    documento.build(elementos, onFirstPage=_rodape, onLaterPages=_rodape)
    return buffer.getvalue()
