"""Canal de correio electrónico (§37).

Divide-se em duas partes, e a divisão é deliberada.

A **desmontagem** de uma mensagem e a **decisão de a ignorar** são funções puras:
recebem bytes, devolvem uma estrutura. Testam-se sem servidor nenhum, e é onde
estão as regras que se podem enganar — codificações, `multipart`, cabeçalhos mal
formados, e o que distingue uma comunicação de uma resposta automática.

O **ciclo completo** exige o servidor de correio do `docker-compose`. Esses testes
saltam-se com uma mensagem clara quando ele não está de pé, em vez de falharem: um
teste vermelho por falta de infraestrutura ensina a ignorar testes vermelhos.

O defeito que estes testes guardam é concreto e foi observado a correr. A caixa de
segurança é normalmente o **mesmo endereço** que a plataforma usa como remetente,
pelo que o aviso de recepção volta e, sem a marca de origem, era recolhido como
comunicação nova — que gerava outro aviso. Um ciclo que se alimenta a si mesmo:
na primeira recolha real, três avisos tornaram-se três comunicações.
"""

from __future__ import annotations

import socket
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

from app.core.config import settings
from app.services import email_service as ems


def _mensagem(**cabecalhos) -> bytes:
    corpo = cabecalhos.pop("corpo", "Conteúdo da mensagem de teste.")
    m = EmailMessage()
    m["From"] = cabecalhos.pop("remetente", "Rosa Malate <rosa@clinica.co.mz>")
    m["To"] = cabecalhos.pop("destino", "cert@sheisa.local")
    m["Subject"] = cabecalhos.pop("assunto", "Assunto de teste")
    for chave, valor in cabecalhos.items():
        m[chave.replace("_", "-")] = valor
    m.set_content(corpo)
    return m.as_bytes()


# ================================================================ desmontagem
def test_desmonta_remetente_assunto_e_corpo():
    m = ems.desmontar(_mensagem(corpo="Um posto apresenta ficheiros cifrados."))

    assert m.remetente_nome == "Rosa Malate"
    assert m.remetente_email == "rosa@clinica.co.mz"
    assert m.assunto == "Assunto de teste"
    assert "ficheiros cifrados" in m.corpo
    assert not m.motivo_para_ignorar


def test_descodifica_cabecalhos_acentuados():
    """`=?utf-8?B?...?=` tem de chegar legível: é o que o analista lê na fila."""
    m = ems.desmontar(
        _mensagem(assunto="Intrusão confirmada — acção urgente",
                  remetente="João Sitoe <joao@empresa.co.mz>")
    )

    assert m.assunto == "Intrusão confirmada — acção urgente"
    assert m.remetente_nome == "João Sitoe"


def test_um_cabecalho_mal_formado_nao_perde_a_mensagem():
    """Perder uma comunicação é pior do que mostrar um assunto estranho."""
    bruto = (
        b"From: alguem@exemplo.local\r\n"
        b"To: cert@sheisa.local\r\n"
        b"Subject: =?utf-8?B?ISSO-NAO-E-BASE64!!?=\r\n"
        b"\r\n"
        b"Corpo legivel.\r\n"
    )
    m = ems.desmontar(bruto)

    assert m.assunto, "o assunto não pode vir vazio"
    assert "Corpo legivel" in m.corpo


def test_sem_assunto_nao_fica_vazio():
    bruto = b"From: a@b.local\r\nTo: cert@sheisa.local\r\n\r\nCorpo.\r\n"
    assert ems.desmontar(bruto).assunto == "(sem assunto)"


def test_prefere_texto_simples_ao_html():
    """Converter HTML aqui introduziria uma interpretação que pode inventar."""
    m = MIMEMultipart("alternative")
    m["From"] = "a@b.local"
    m["To"] = "cert@sheisa.local"
    m["Subject"] = "Com duas versões"
    m.attach(MIMEText("Versão em texto simples.", "plain"))
    m.attach(MIMEText("<p>Versão em <b>HTML</b>.</p>", "html"))

    desmontada = ems.desmontar(m.as_bytes())

    assert "texto simples" in desmontada.corpo
    assert "<b>" not in desmontada.corpo


def test_usa_o_html_quando_nao_ha_texto_simples():
    """Guardar o HTML como está é melhor do que uma comunicação sem corpo."""
    m = MIMEMultipart("alternative")
    m["From"] = "a@b.local"
    m["To"] = "cert@sheisa.local"
    m["Subject"] = "Só HTML"
    m.attach(MIMEText("<p>Conteúdo só em HTML.</p>", "html"))

    assert "só em HTML" in ems.desmontar(m.as_bytes()).corpo


def test_anexos_sao_listados_e_nao_recolhidos():
    """Um ficheiro de origem não verificada não entra nas evidências sozinho."""
    m = MIMEMultipart()
    m["From"] = "a@b.local"
    m["To"] = "cert@sheisa.local"
    m["Subject"] = "Com anexo"
    m.attach(MIMEText("Ver o registo anexo.", "plain"))
    anexo = MIMEText("linha de registo", "plain")
    anexo.add_header("Content-Disposition", "attachment", filename="registo.log")
    m.attach(anexo)

    desmontada = ems.desmontar(m.as_bytes())

    assert desmontada.anexos == ["registo.log"]
    assert "linha de registo" not in desmontada.corpo


def test_mensagem_enorme_e_truncada_e_nao_descartada():
    bruto = _mensagem(corpo="a" * (ems.MAX_CARACTERES_DO_CORPO + 5_000))

    m = ems.desmontar(bruto)

    assert m.truncada is True
    assert len(m.corpo) <= ems.MAX_CARACTERES_DO_CORPO
    assert m.corpo, "truncar não pode deixar o corpo vazio"


# ======================================================= decisão de ignorar
def test_a_propria_mensagem_da_plataforma_e_ignorada():
    """Regressão do ciclo: sem isto, o aviso de recepção gerava outro aviso."""
    bruto = _mensagem(**{ems.CABECALHO_DE_ORIGEM: ems.VALOR_DE_ORIGEM})

    assert "própria plataforma" in ems.desmontar(bruto).motivo_para_ignorar


@pytest.mark.parametrize(
    ("cabecalho", "valor"),
    [
        ("Auto_Submitted", "auto-replied"),
        ("Auto_Submitted", "auto-generated"),
        ("Precedence", "bulk"),
        ("Precedence", "list"),
        ("X_Autoreply", "yes"),
    ],
)
def test_correio_automatico_e_ignorado(cabecalho, valor):
    """Uma comunicação por cada resposta de férias enche a fila de nada."""
    bruto = _mensagem(**{cabecalho: valor})

    assert "automático" in ems.desmontar(bruto).motivo_para_ignorar


def test_notificacao_de_entrega_e_ignorada():
    """RFC 3464: é estrutura da mensagem, o sinal mais fiável dos três."""
    m = MIMEMultipart("report")
    m.set_param("report-type", "delivery-status")
    m["From"] = "Mail Delivery System <MAILER-DAEMON@servidor.local>"
    m["To"] = "cert@sheisa.local"
    m["Subject"] = "Undelivered Mail Returned to Sender"
    m.attach(MIMEText("A mensagem não pôde ser entregue."))

    assert "entrega" in ems.desmontar(m.as_bytes()).motivo_para_ignorar


def test_return_path_vazio_e_ignorado():
    """O sinal que um MTA a sério escreve para um envelope nulo."""
    bruto = _mensagem(Return_Path="<>")

    assert "devolução" in ems.desmontar(bruto).motivo_para_ignorar


def test_a_ausencia_de_return_path_nao_conta_como_devolucao():
    """É o servidor receptor que o escreve; muita mensagem legítima vem sem ele.

    Sem esta distinção, a recolha descartava comunicações reais — e o efeito
    seria invisível, porque uma comunicação descartada não deixa rasto na fila.
    """
    assert not ems.desmontar(_mensagem()).motivo_para_ignorar


@pytest.mark.parametrize(
    "remetente", ["MAILER-DAEMON@x.local", "postmaster@x.local", "no-reply@x.local"]
)
def test_remetentes_de_sistema_sao_ignorados(remetente):
    """Uma pessoa a comunicar um incidente não escreve de `MAILER-DAEMON`."""
    bruto = _mensagem(remetente=remetente)

    assert "sistema" in ems.desmontar(bruto).motivo_para_ignorar


def test_uma_pessoa_a_comunicar_nao_e_ignorada():
    """A verificação que impede os filtros de cortarem o que importa."""
    bruto = _mensagem(
        remetente="Paulo Sitoe <paulo.sitoe@universidade.ac.mz>",
        assunto="Servidor da biblioteca a enviar spam",
        corpo="Suspeitamos de comprometimento. Já isolámos o servidor.",
    )

    assert not ems.desmontar(bruto).motivo_para_ignorar


# ============================================================= configuração
def test_o_estado_do_canal_nao_contacta_o_servidor():
    """§4 · §26: dizer "activo" sem o provar é o que se proíbe.

    A função descreve configuração; o teste de ligação é que prova. Se
    contactasse, não poderia ser chamada a cada leitura da fila.
    """
    estado = ems.estado_do_canal()

    for campo in (
        "envio_configurado", "recolha_configurada", "remetente", "caixa",
        "variaveis_em_falta",
    ):
        assert campo in estado


def test_sem_configuracao_o_envio_levanta(monkeypatch):
    """Não devolve `False`: quem chama tem de saber que não foi enviado."""
    monkeypatch.setattr(settings, "smtp_host", "")

    with pytest.raises(ems.EmailNaoConfigurado):
        ems.enviar(para="a@b.local", assunto="x", corpo="y")


def test_sem_configuracao_a_recolha_levanta(monkeypatch):
    # Fixa o protocolo em vez de depender do .env: com o Gmail configurado por
    # IMAP, limpar só o pop3_host não deixaria a recolha por configurar, e o
    # teste passaria a contactar o servidor real.
    monkeypatch.setattr(settings, "mail_collect_protocol", "POP3")
    monkeypatch.setattr(settings, "pop3_host", "")

    with pytest.raises(ems.EmailNaoConfigurado):
        ems.recolher()


def test_as_variaveis_em_falta_sao_nomeadas(monkeypatch):
    """Quem configura precisa de saber *qual* falta, não que "falta algo"."""
    monkeypatch.setattr(settings, "smtp_host", "")
    monkeypatch.setattr(settings, "pop3_password", "")

    em_falta = ems.estado_do_canal()["variaveis_em_falta"]

    assert "SHEISA_SMTP_HOST" in em_falta
    assert "SHEISA_POP3_PASSWORD" in em_falta


# ========================================= ciclo completo, com servidor real
def _servidor_de_correio_responde() -> bool:
    if not (settings.smtp_host and settings.pop3_host):
        return False
    for porta in (settings.smtp_port, settings.pop3_port):
        try:
            with socket.create_connection((settings.smtp_host, porta), timeout=2):
                pass
        except OSError:
            return False
    return True


exige_servidor = pytest.mark.skipif(
    not _servidor_de_correio_responde(),
    reason=(
        "O servidor de correio não responde. Arranque-o com "
        "`docker compose up -d mail`."
    ),
)


@exige_servidor
def test_o_ciclo_de_envio_e_recolha_funciona():
    """Envia e lê de volta: prova que as duas direcções falam com o servidor.

    Não é um duplo de teste. Um `smtplib` simulado provaria que o código chama a
    biblioteca certa, não que um servidor aceita a mensagem — e foi contra um
    servidor a sério que apareceu o defeito do ciclo.
    """
    # Esvazia a caixa primeiro: outra mensagem pendente tornaria a asserção
    # dependente do que ficou de antes.
    ems.recolher(apagar=True)

    identificador = ems.enviar(
        para=settings.pop3_user,
        assunto="Verificação do ciclo de correio",
        corpo="Mensagem escrita pelo teste do ciclo completo.",
    )
    assert identificador.startswith("<"), identificador

    recolhidas = ems.recolher(apagar=True)

    assert len(recolhidas) == 1, [m.assunto for m in recolhidas]
    mensagem = recolhidas[0]
    assert mensagem.assunto == "Verificação do ciclo de correio"
    # E é ignorada, porque a plataforma foi quem a enviou.
    assert "própria plataforma" in mensagem.motivo_para_ignorar


@exige_servidor
def test_a_recolha_apaga_e_nao_repete():
    """O POP3 não guarda estado de lida: sem apagar, cada recolha duplicava."""
    ems.recolher(apagar=True)
    ems.enviar(para=settings.pop3_user, assunto="Uma só vez", corpo="Corpo.")

    primeira = ems.recolher(apagar=True)
    segunda = ems.recolher(apagar=True)

    assert len(primeira) == 1
    assert segunda == [], "a mensagem voltou a ser lida depois de apagada"


# ============================================================= protocolo IMAP
# O Mailpit não fala IMAP, pelo que a recolha IMAP contra um servidor a sério só
# é exercida quando alguém configura o Gmail. O que se pode — e deve — fixar
# aqui é a lógica de selecção de protocolo: qual servidor conta, o que falta, e
# que `recolher()` despacha para o caminho certo.
def test_config_imap_escolhe_o_servidor_imap(monkeypatch):
    monkeypatch.setattr(settings, "mail_collect_protocol", "IMAP")
    monkeypatch.setattr(settings, "imap_host", "imap.gmail.com")
    monkeypatch.setattr(settings, "pop3_host", "")

    assert settings.usa_imap is True
    assert settings.servidor_de_recolha == "imap.gmail.com"
    # Sem pop3_host, mas com imap_host e credenciais, a recolha está configurada:
    # o servidor que conta é o do protocolo escolhido.
    monkeypatch.setattr(settings, "pop3_user", "cert@gmail.com")
    monkeypatch.setattr(settings, "pop3_password", "app-password")
    assert settings.recolha_de_email_configurada is True


def test_estado_do_canal_nomeia_a_variavel_imap_em_falta(monkeypatch):
    """Com IMAP escolhido e sem imap_host, manda configurar o IMAP, não o POP3."""
    monkeypatch.setattr(settings, "mail_collect_protocol", "IMAP")
    monkeypatch.setattr(settings, "imap_host", "")

    em_falta = ems.estado_do_canal()["variaveis_em_falta"]

    assert "SHEISA_IMAP_HOST" in em_falta
    assert "SHEISA_POP3_HOST" not in em_falta, (
        "com IMAP escolhido, mandar configurar o POP3 aponta a variável errada"
    )
    assert ems.estado_do_canal()["protocolo_de_recolha"] == "IMAP"


def test_recolher_despacha_para_imap(monkeypatch):
    """`recolher()` tem de ir pelo caminho IMAP quando é esse o protocolo."""
    monkeypatch.setattr(settings, "mail_collect_protocol", "IMAP")
    chamados: list[str] = []
    monkeypatch.setattr(ems, "_recolher_imap", lambda **_: chamados.append("imap") or [])
    monkeypatch.setattr(ems, "_recolher_pop3", lambda **_: chamados.append("pop3") or [])

    ems.recolher()

    assert chamados == ["imap"]


def test_recolher_despacha_para_pop3_por_omissao(monkeypatch):
    monkeypatch.setattr(settings, "mail_collect_protocol", "POP3")
    chamados: list[str] = []
    monkeypatch.setattr(ems, "_recolher_imap", lambda **_: chamados.append("imap") or [])
    monkeypatch.setattr(ems, "_recolher_pop3", lambda **_: chamados.append("pop3") or [])

    ems.recolher()

    assert chamados == ["pop3"]


def test_recolha_imap_sem_configuracao_levanta(monkeypatch):
    monkeypatch.setattr(settings, "mail_collect_protocol", "IMAP")
    monkeypatch.setattr(settings, "imap_host", "")

    with pytest.raises(ems.EmailNaoConfigurado):
        ems._recolher_imap(marcar_lida=True)
