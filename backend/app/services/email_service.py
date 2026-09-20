"""Envio e recolha de correio electrónico (§37).

O canal tem duas direcções e as duas estão aqui:

**Enviar** o aviso de recepção a quem comunicou, e avisá-lo quando a sua
comunicação é decidida. Um CSIRT que recebe uma comunicação e nunca responde
perde o constituinte — e a pessoa volta a escrever, o que duplica o trabalho.

**Recolher** as comunicações que chegam à caixa de segurança (`cert@`, `abuse@`)
e transformá-las em comunicações da plataforma, com o canal `EMAIL`.

Duas regras governam este módulo, e ambas vêm do §4.

**Nunca se assume um envio.** `enviar()` só devolve sem erro depois de o servidor
aceitar a mensagem, e `acknowledged_at` só é escrito nesse caso. Sem SMTP
configurado, `enviar()` levanta `EmailNaoConfigurado` em vez de não fazer nada em
silêncio: uma função que finge ter enviado é pior do que uma que falha.

**A mensagem original é preservada.** Como o `raw_payload` de um evento, os
cabeçalhos e o corpo bruto ficam em `channel_metadata` — é o que permite
confrontar o que a plataforma normalizou com o que chegou de facto, e é a
resposta a "como sei que esta comunicação veio mesmo deste endereço?".

Sobre confiar no remetente: **não se confia.** O campo `From` de um email é
trivial de falsificar, e a interface diz que o endereço é declarado e não
verificado. Os cabeçalhos de autenticação que o servidor receptor tenha escrito
(`Authentication-Results`, `Received-SPF`) são preservados para quem tria poder
olhar, mas a plataforma não os interpreta — interpretá-los mal seria pior do que
não os mostrar.
"""

from __future__ import annotations

import email
import email.utils
import logging
import poplib
import smtplib
from dataclasses import dataclass, field
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.message import EmailMessage

from app.core.config import settings

logger = logging.getLogger("sheisa")

#: Tamanho máximo de uma mensagem recolhida.
#:
#: Uma caixa pública recebe anexos grandes e mensagens automáticas enormes. O
#: corpo entra na descrição da comunicação, e sem limite uma única mensagem
#: podia encher a coluna. O que passa do limite é truncado com aviso visível, em
#: vez de a mensagem ser descartada — perder uma comunicação é pior.
MAX_BYTES_DA_MENSAGEM = 256 * 1024

#: Tamanho máximo do corpo aproveitado como descrição.
MAX_CARACTERES_DO_CORPO = 18_000

#: Cabeçalho próprio que marca uma mensagem como gerada pela plataforma.
#:
#: Existe porque a caixa de segurança é normalmente o mesmo endereço que a
#: plataforma usa como remetente, e portanto tudo o que ela envia pode voltar —
#: por devolução, por resposta automática, ou porque o servidor de
#: desenvolvimento entrega tudo na mesma caixa. Sem esta marca, a recolha
#: transformava o próprio aviso de recepção numa comunicação nova, que gerava
#: outro aviso: um ciclo que se alimenta a si mesmo.
#:
#: Mais fiável do que comparar o remetente, porque o `From` de uma devolução é
#: o do servidor que devolveu e não o nosso.
CABECALHO_DE_ORIGEM = "X-SHEISA-Origem"
VALOR_DE_ORIGEM = "plataforma"

#: Cabeçalhos que identificam correio que não é uma comunicação de ninguém.
#:
#: `Auto-Submitted` é o do RFC 3834 e é o que respostas automáticas bem
#: comportadas usam; `Precedence` é a convenção antiga, ainda muito usada. Um
#: `Return-Path` vazio (`<>`) identifica uma devolução.
CABECALHOS_DE_AUTOMATISMO = {
    "auto-submitted": ("auto-replied", "auto-generated", "auto-notified"),
    "precedence": ("bulk", "junk", "auto_reply", "list"),
    "x-autoreply": (),
    "x-autorespond": (),
}

#: Cabeçalhos guardados como prova de origem.
#:
#: Inclui os de autenticação de propósito: não são interpretados pela
#: plataforma, mas são o que um analista olha para decidir se acredita no
#: remetente declarado.
CABECALHOS_PRESERVADOS = (
    "from", "to", "cc", "subject", "date", "message-id", "reply-to",
    "return-path", "received-spf", "authentication-results",
    "dkim-signature", "x-originating-ip", "user-agent", "x-mailer",
    # Preservados para que a decisão de ignorar uma mensagem seja auditável: sem
    # eles, "ignorada por ser automática" não se pode confirmar depois.
    "auto-submitted", "precedence", "content-type", CABECALHO_DE_ORIGEM.lower(),
)


class EmailNaoConfigurado(RuntimeError):
    """Levantado quando se pede um envio ou recolha sem configuração.

    Excepção e não devolução silenciosa: quem chama tem de decidir o que fazer,
    e o caminho de "não configurado" não pode ser indistinguível de "enviado".
    """


@dataclass(slots=True)
class MensagemRecolhida:
    """Uma mensagem lida da caixa, já desmontada mas não interpretada."""

    remetente_nome: str
    remetente_email: str
    assunto: str
    corpo: str
    message_id: str
    cabecalhos: dict[str, str] = field(default_factory=dict)
    #: Nomes dos anexos. **Não** são guardados como evidência automaticamente:
    #: um ficheiro de origem não verificada não entra no repositório de
    #: evidências sem decisão de um analista.
    anexos: list[str] = field(default_factory=list)
    truncada: bool = False
    #: Quando preenchido, a mensagem não é uma comunicação de ninguém e explica
    #: porquê. Um campo em vez de um booleano porque o motivo é registado: sem
    #: ele, "ignorada" seria indistinguível de "perdida".
    motivo_para_ignorar: str = ""


def _texto(valor: str | None) -> str:
    """Descodifica um cabeçalho MIME (`=?utf-8?B?...?=`) para texto legível."""
    if not valor:
        return ""
    try:
        return str(make_header(decode_header(valor))).strip()
    except (HeaderParseError, UnicodeDecodeError, LookupError, ValueError):
        # Um cabeçalho mal formado não pode impedir a recolha: o assunto vem
        # como está, que é melhor do que perder a comunicação.
        #
        # `HeaderParseError` está na lista porque um `=?utf-8?B?...?=` com base64
        # inválido levanta-o — e não é subclasse de `ValueError`. Sem ele, uma
        # mensagem com um assunto mal codificado fazia a desmontagem falhar, o
        # que descartava a comunicação. Encontrado pelo teste que afirma
        # precisamente isto.
        return valor.strip()


# ==================================================================== envio
def _ligar_smtp() -> smtplib.SMTP:
    if not settings.envio_de_email_configurado:
        raise EmailNaoConfigurado(
            "O envio de correio não está configurado: faltam SHEISA_SMTP_HOST "
            "ou SHEISA_MAIL_FROM."
        )
    ligacao = smtplib.SMTP(
        settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_segundos
    )
    if settings.smtp_starttls:
        ligacao.starttls()
    if settings.smtp_user:
        ligacao.login(settings.smtp_user, settings.smtp_password)
    return ligacao


def enviar(*, para: str, assunto: str, corpo: str, responder_a: str = "") -> str:
    """Envia uma mensagem e devolve o `Message-ID` que lhe foi atribuído.

    Levanta se não estiver configurado ou se o servidor recusar. Devolver o
    identificador e não um booleano é deliberado: um `True` não prova nada, e o
    identificador permite encontrar a mensagem no servidor depois.
    """
    mensagem = EmailMessage()
    mensagem["From"] = email.utils.formataddr(
        (settings.mail_from_name, settings.mail_from)
    )
    mensagem["To"] = para
    mensagem["Subject"] = assunto
    mensagem["Date"] = email.utils.formatdate(localtime=True)
    identificador = email.utils.make_msgid(domain=settings.mail_from.split("@")[-1])
    mensagem["Message-ID"] = identificador
    if responder_a:
        mensagem["Reply-To"] = responder_a
    # A marca própria e a declaração do RFC 3834. A segunda pede aos servidores
    # do outro lado que não respondam automaticamente a isto, que é metade da
    # prevenção do ciclo; a primeira garante a outra metade do nosso lado.
    mensagem[CABECALHO_DE_ORIGEM] = VALOR_DE_ORIGEM
    mensagem["Auto-Submitted"] = "auto-generated"
    mensagem.set_content(corpo)

    with _ligar_smtp() as ligacao:
        recusados = ligacao.send_message(mensagem)

    if recusados:
        # `send_message` devolve os destinatários recusados sem levantar. Tratar
        # isso como sucesso marcaria o aviso como enviado a quem não o recebeu.
        raise RuntimeError(
            f"O servidor recusou o destinatário: {sorted(recusados)}"
        )

    logger.info("Mensagem enviada para %s (%s)", para, identificador)
    return identificador


def testar_envio(destino: str) -> str:
    """Envia uma mensagem de verificação. Usado pelo teste de ligação (§26)."""
    return enviar(
        para=destino,
        assunto="SHEISA — verificação do canal de correio electrónico",
        corpo=(
            "Esta mensagem confirma que a plataforma consegue enviar correio "
            "através do servidor configurado.\n\n"
            "Foi gerada por um teste de ligação e não exige qualquer acção."
        ),
    )


# =================================================================== recolha
def _ligar_pop3() -> poplib.POP3:
    if not settings.recolha_de_email_configurada:
        raise EmailNaoConfigurado(
            "A recolha de correio não está configurada: faltam SHEISA_POP3_HOST, "
            "SHEISA_POP3_USER ou SHEISA_POP3_PASSWORD."
        )
    classe = poplib.POP3_SSL if settings.pop3_tls else poplib.POP3
    ligacao = classe(
        settings.pop3_host, settings.pop3_port, timeout=settings.pop3_timeout_segundos
    )
    ligacao.user(settings.pop3_user)
    ligacao.pass_(settings.pop3_password)
    return ligacao


def _extrair_corpo(mensagem: email.message.Message) -> tuple[str, list[str]]:
    """Devolve (texto do corpo, nomes dos anexos).

    Prefere `text/plain` a `text/html`: o objectivo é o que um analista lê, e
    converter HTML para texto aqui introduziria uma interpretação que pode
    perder ou inventar conteúdo. Quando só há HTML, guarda-se como está e a
    interface mostra-o como texto — o bruto fica sempre em `channel_metadata`.
    """
    anexos: list[str] = []
    texto = ""
    alternativa_html = ""

    if not mensagem.is_multipart():
        carga = mensagem.get_payload(decode=True) or b""
        conjunto = mensagem.get_content_charset() or "utf-8"
        return carga.decode(conjunto, errors="replace"), anexos

    for parte in mensagem.walk():
        if parte.get_content_maintype() == "multipart":
            continue
        disposicao = (parte.get("Content-Disposition") or "").lower()
        nome = _texto(parte.get_filename())

        if "attachment" in disposicao or nome:
            if nome:
                anexos.append(nome)
            continue

        carga = parte.get_payload(decode=True) or b""
        conjunto = parte.get_content_charset() or "utf-8"
        conteudo = carga.decode(conjunto, errors="replace")
        if parte.get_content_type() == "text/plain" and not texto:
            texto = conteudo
        elif parte.get_content_type() == "text/html" and not alternativa_html:
            alternativa_html = conteudo

    return (texto or alternativa_html), anexos


def _motivo_para_ignorar(mensagem: email.message.Message) -> str:
    """Diz porque é que esta mensagem não é uma comunicação, ou devolve vazio.

    Três casos, todos reais numa caixa de segurança:

    **A plataforma enviou-a.** A caixa de segurança é normalmente o mesmo
    endereço que a plataforma usa como remetente, pelo que o aviso de recepção
    pode voltar — e, se voltasse a ser tratado como comunicação, gerava outro
    aviso. Um ciclo que se alimenta a si mesmo.

    **É uma resposta automática.** Férias, "recebido", listas de distribuição.
    Criar uma comunicação por cada uma enche a fila de coisas que ninguém
    escreveu.

    **É uma devolução.** `Return-Path: <>` é a convenção; o corpo é um relatório
    de entrega, não um relato.
    """
    if (mensagem.get(CABECALHO_DE_ORIGEM) or "").strip().lower() == VALOR_DE_ORIGEM:
        return "gerada pela própria plataforma"

    for cabecalho, valores in CABECALHOS_DE_AUTOMATISMO.items():
        presente = mensagem.get(cabecalho)
        if presente is None:
            continue
        actual = presente.strip().lower()
        # Sem valores declarados, a simples presença do cabeçalho basta.
        if not valores or any(v in actual for v in valores):
            return f"correio automático ({cabecalho}: {actual})"

    # Uma devolução dá-se por três sinais independentes, porque nenhum é
    # universal.
    #
    # O primeiro é o do RFC 3464 e é o mais fiável: uma notificação de entrega
    # é um `multipart/report` com `report-type=delivery-status`. É estrutura da
    # mensagem, não convenção.
    tipo = (mensagem.get("Content-Type") or "").lower()
    if "multipart/report" in tipo and "delivery-status" in tipo:
        return "notificação de entrega (multipart/report)"

    # O segundo é o `Return-Path` vazio, que um MTA escreve quando o remetente de
    # envelope é nulo. A **ausência** do cabeçalho não conta: é o servidor
    # receptor que o escreve, e muita mensagem legítima chega sem ele — tratar a
    # ausência como devolução descartaria comunicações reais. (O servidor de
    # desenvolvimento não escreve este cabeçalho, pelo que este sinal em
    # particular só se observa contra um MTA a sério.)
    if (mensagem.get("Return-Path") or "").strip() == "<>":
        return "devolução de entrega (Return-Path vazio)"

    # O terceiro é a convenção dos endereços que os servidores usam para
    # devolver. Fica em último porque é o único que se pode falsificar — mas uma
    # pessoa a comunicar um incidente não escreve de `MAILER-DAEMON`.
    _, remetente = email.utils.parseaddr(mensagem.get("From", ""))
    parte_local = remetente.split("@")[0].strip().lower()
    if parte_local in ("mailer-daemon", "postmaster", "bounce", "no-reply", "noreply"):
        return f"remetente de sistema ({parte_local})"

    return ""


def desmontar(bruto: bytes) -> MensagemRecolhida:
    """Desmonta uma mensagem em bruto. Não interpreta nem confia em nada.

    Separada da recolha de propósito: é a parte com regras (codificações,
    multipart, cabeçalhos mal formados) e a que se pode testar sem servidor.
    """
    truncada = len(bruto) > MAX_BYTES_DA_MENSAGEM
    mensagem = email.message_from_bytes(bruto[:MAX_BYTES_DA_MENSAGEM])

    nome, endereco = email.utils.parseaddr(mensagem.get("From", ""))
    corpo, anexos = _extrair_corpo(mensagem)

    if len(corpo) > MAX_CARACTERES_DO_CORPO:
        corpo = corpo[:MAX_CARACTERES_DO_CORPO]
        truncada = True

    cabecalhos = {
        chave: _texto(valor)
        for chave, valor in mensagem.items()
        if chave.lower() in CABECALHOS_PRESERVADOS
    }

    return MensagemRecolhida(
        remetente_nome=_texto(nome) or endereco,
        remetente_email=endereco.strip().lower(),
        assunto=_texto(mensagem.get("Subject")) or "(sem assunto)",
        corpo=corpo.strip(),
        message_id=(mensagem.get("Message-ID") or "").strip(),
        cabecalhos=cabecalhos,
        anexos=anexos,
        truncada=truncada,
        motivo_para_ignorar=_motivo_para_ignorar(mensagem),
    )


def recolher(*, apagar: bool = True) -> list[MensagemRecolhida]:
    """Lê a caixa e devolve as mensagens desmontadas.

    `apagar=True` porque o POP3 não guarda estado de "lida": sem apagar, cada
    recolha traria as mesmas mensagens e criaria comunicações duplicadas a cada
    execução. O apagar acontece **depois** de a mensagem ser desmontada com
    êxito, pelo que uma mensagem que falhe a desmontagem fica na caixa para ser
    olhada — perder uma comunicação é pior do que a recolher duas vezes.

    O `Message-ID` sobrevive em `channel_metadata`, o que permite detectar um
    duplicado caso a mensagem volte a chegar.
    """
    recolhidas: list[MensagemRecolhida] = []
    ligacao = _ligar_pop3()
    try:
        quantas, _ = ligacao.stat()
        limite = min(quantas, settings.pop3_max_por_recolha)
        # De trás para a frente: apagar altera a numeração das seguintes, e
        # começar pelo fim deixa os índices ainda não lidos intactos.
        for indice in range(quantas, quantas - limite, -1):
            try:
                bruto = b"\n".join(ligacao.retr(indice)[1])
                recolhidas.append(desmontar(bruto))
            except Exception:
                logger.exception(
                    "Falhou a desmontagem da mensagem %s; fica na caixa", indice
                )
                continue
            if apagar:
                ligacao.dele(indice)
    finally:
        # `quit()` é o que confirma os apagamentos; um `close()` descarta-os.
        ligacao.quit()

    return recolhidas


# ================================================================== diagnóstico
def estado_do_canal() -> dict:
    """Descreve o estado do canal sem nada inventar (§4 · §26).

    Não contacta o servidor: dizer "activo" sem o provar é exactamente o que se
    proíbe. Diz o que está configurado, e o teste de ligação é que prova.
    """
    em_falta: list[str] = []
    if not settings.smtp_host:
        em_falta.append("SHEISA_SMTP_HOST")
    if not settings.mail_from:
        em_falta.append("SHEISA_MAIL_FROM")
    if not settings.pop3_host:
        em_falta.append("SHEISA_POP3_HOST")
    if not settings.pop3_user:
        em_falta.append("SHEISA_POP3_USER")
    if not settings.pop3_password:
        em_falta.append("SHEISA_POP3_PASSWORD")

    return {
        "envio_configurado": settings.envio_de_email_configurado,
        "recolha_configurada": settings.recolha_de_email_configurada,
        "remetente": settings.mail_from or None,
        "caixa": settings.pop3_user or None,
        "variaveis_em_falta": em_falta,
    }
