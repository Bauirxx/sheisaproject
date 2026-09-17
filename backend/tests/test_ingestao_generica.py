"""Ingestão genérica: `POST /api/ingest/events` e o normalizador de recurso (§8).

É a porta para qualquer ferramenta que saiba fazer um POST, e o plano de recurso
para payloads que nenhum normalizador específico reconhece. Não tem ecrã: só um
teste ou um cliente real a exercitam — o mesmo perfil da rota de chaves de API,
que esteve partida desde que foi escrita sem que nada o revelasse.

Três defeitos foram encontrados ao escrever estes testes:

* **Eventos diferentes eram descartados como duplicados.** Sem identificador no
  payload, o de recurso usava só o instante e a descrição. Duas falhas de
  autenticação no mesmo segundo, de origens diferentes, davam o mesmo
  identificador, e a segunda era ignorada como "já recebida". Além disso a
  parte da descrição vinha de `hash()`, que o Python aleatoriza por processo: o
  mesmo evento reenviado depois de reiniciar a API já não era reconhecido.
* **A conta visada era tratada como a do atacante** (`dstuser` com papel ACTOR).
  É o defeito 4 do `ESTADO.md`, corrigido no normalizador Wazuh e nunca aqui.
* **Normalização parcial sem aviso.** Um instante ilegível era trocado pela hora
  de recepção, e uma severidade não reconhecida por MEDIA, sem nada no registo —
  ao contrário do que o próprio módulo promete.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.enums import IocType, ObservationRole, Severity, SourceKind
from app.ingestion.generic import GenericNormalizer, coerce_severity
from app.ingestion.registry import detect_source, normalize
from app.models.telemetry import Event
from tests.test_ingestao import alerta_wazuh

INSTANTE = "2026-09-17T08:15:30+00:00"


def _normalizar(**payload):
    return GenericNormalizer().normalize(payload, "fonte-de-teste")


def _papeis(evento) -> set[tuple[IocType, str, ObservationRole]]:
    return {(i.ioc_type, i.value, i.role) for i in evento.indicators}


async def _enviar(cliente, chave, corpo):
    resposta = await cliente.post(
        "/api/ingest/events", json=corpo, headers={"X-API-Key": chave}
    )
    assert resposta.status_code == 202, resposta.text
    return resposta.json()


# ---------------------------------------------------------- identidade
async def test_eventos_diferentes_no_mesmo_segundo_nao_se_confundem(
    cliente, sessao, chave_ingestao
):
    """Regressão: a segunda falha de autenticação era ignorada como duplicada."""
    comum = {"timestamp": INSTANTE, "description": "Failed password for admin"}

    corpo = await _enviar(cliente, chave_ingestao, [
        {**comum, "src_ip": "203.0.113.10"},
        {**comum, "src_ip": "198.51.100.23"},
    ])

    estados = [r["estado"] for r in corpo["resultados"]]
    assert "duplicado_ignorado" not in estados, corpo["resultados"]
    origens = set((await sessao.execute(select(Event.source_ip))).scalars())
    assert origens == {"203.0.113.10", "198.51.100.23"}


async def test_o_mesmo_evento_reenviado_e_reconhecido(cliente, chave_ingestao):
    evento = {"timestamp": INSTANTE, "description": "Failed password", "src_ip": "203.0.113.10"}

    await _enviar(cliente, chave_ingestao, evento)
    segundo = await _enviar(cliente, chave_ingestao, evento)

    assert segundo["resultados"][0]["estado"] == "duplicado_ignorado"


def test_o_identificador_do_evento_nao_depende_do_processo():
    """Regressão: `hash()` muda com o processo, e o reenvio deixava de ser reconhecido."""
    codigo = (
        "from app.ingestion.generic import GenericNormalizer;"
        "print(GenericNormalizer().normalize("
        f"{{'timestamp': '{INSTANTE}', 'description': 'Failed password'}}, 'x'"
        ").source_event_id)"
    )
    backend = Path(__file__).resolve().parents[1]
    identificadores = {
        subprocess.run(
            [sys.executable, "-c", codigo],
            cwd=backend, capture_output=True, text=True, check=True,
            env={**os.environ, "PYTHONHASHSEED": semente},
        ).stdout.strip()
        for semente in ("1", "2")
    }
    assert len(identificadores) == 1, identificadores


def test_sem_instante_nem_identificador_cada_envio_conta():
    """Sem nada que o distinga, um reenvio e uma nova ocorrência são iguais.

    Perder uma ocorrência real é pior do que contar um reenvio duas vezes, por
    isso o instante de recepção entra no identificador.
    """
    primeiro = _normalizar(description="Failed password", src_ip="203.0.113.10")
    segundo = _normalizar(description="Failed password", src_ip="203.0.113.10")
    assert primeiro.source_event_id != segundo.source_event_id


def test_identificador_da_fonte_prevalece():
    assert _normalizar(id="evt-42", description="x").source_event_id == "evt-42"


# --------------------------------------------------------------- papéis
def test_a_conta_visada_nao_e_tratada_como_actor():
    """Regressão do defeito 4: `dstuser` é a vítima, não o atacante."""
    evento = _normalizar(
        timestamp=INSTANTE, description="Login", srcuser="intruso", dstuser="admin"
    )
    assert _papeis(evento) >= {
        (IocType.UTILIZADOR, "intruso", ObservationRole.ACTOR),
        (IocType.UTILIZADOR, "admin", ObservationRole.ALVO),
    }
    assert (IocType.UTILIZADOR, "admin", ObservationRole.ACTOR) not in _papeis(evento)


def test_conta_sem_lado_declarado_e_a_conta_envolvida():
    evento = _normalizar(timestamp=INSTANTE, description="Login", user="joana")
    assert (IocType.UTILIZADOR, "joana", ObservationRole.ACTOR) in _papeis(evento)


def test_so_ips_externos_e_hashes_validos_viram_indicadores():
    evento = _normalizar(
        timestamp=INSTANTE, description="Ligação",
        src_ip="10.10.5.21", dst_ip="203.0.113.99",
        sha256="A" * 64, md5="curto",
    )
    papeis = _papeis(evento)
    assert (IocType.IP, "203.0.113.99", ObservationRole.DESTINO) in papeis
    assert not [p for p in papeis if p[1] == "10.10.5.21"], "IP interno tratado como indicador"
    assert (IocType.HASH_SHA256, "a" * 64, ObservationRole.PAYLOAD) in papeis


# --------------------------------------------------- nomes e severidade
async def test_nomes_alternativos_dos_campos_sao_reconhecidos(cliente, sessao, chave_ingestao):
    await _enviar(cliente, chave_ingestao, {
        "@timestamp": INSTANTE, "level": "high", "msg": "SSH scan",
        "src_ip": "203.0.113.10", "dst_port": "22", "hostname": "srv-web-01",
        "sid": 2001219, "groups": "ssh", "techniques": " t1110 ",
    })

    evento = (await sessao.execute(select(Event))).scalar_one()
    assert (evento.severity, evento.description) == (Severity.ALTA, "SSH scan")
    assert (evento.source_ip, evento.destination_port, evento.host) == (
        "203.0.113.10", 22, "srv-web-01"
    )
    assert evento.occurred_at == datetime(2026, 9, 17, 8, 15, 30, tzinfo=UTC)
    assert (evento.rule_id, evento.rule_groups, evento.reported_techniques) == (
        "2001219", ["ssh"], ["T1110"]
    )
    assert "avisos_normalizacao" not in evento.normalized_extra


@pytest.mark.parametrize(
    ("valor", "esperado"),
    [
        (0, Severity.INFO), (1, Severity.BAIXA), (3, Severity.ALTA), (5, Severity.CRITICA),
        (7, Severity.MEDIA), (12, Severity.ALTA), ("12", Severity.ALTA),
        ("critical", Severity.CRITICA), ("Média", Severity.MEDIA),
    ],
)
def test_severidade_em_texto_ou_numero(valor, esperado):
    assert coerce_severity(valor) is esperado


@pytest.mark.parametrize(
    ("payload", "aviso"),
    [
        ({"timestamp": "ontem à tarde", "severity": "high"},
         "instante 'ontem à tarde' não reconhecido"),
        ({"timestamp": INSTANTE, "severity": "12"},
         "severidade numérica interpretada na escala 0-15"),
        ({"timestamp": INSTANTE, "severity": 12},
         "severidade numérica interpretada na escala 0-15"),
        ({"timestamp": INSTANTE, "severity": "urgentíssimo"},
         "severidade 'urgentíssimo' não reconhecida"),
        ({"timestamp": INSTANTE}, "severidade não fornecida"),
    ],
    ids=["instante-ilegivel", "nivel-em-texto", "nivel-numerico", "severidade-desconhecida",
         "sem-severidade"],
)
def test_a_normalizacao_parcial_fica_registada(payload, aviso):
    """Regressão: o valor era substituído sem nada no registo."""
    evento = _normalizar(**payload, description="Evento com um campo problemático")
    avisos = evento.normalized_extra.get("avisos_normalizacao", [])
    assert [a for a in avisos if aviso in a], avisos


# ------------------------------------------------ escolha do normalizador
def test_sem_fonte_declarada_a_forma_do_payload_decide():
    assert detect_source(alerta_wazuh()) is SourceKind.WAZUH
    assert detect_source({"description": "qualquer coisa"}) is SourceKind.API_GENERICA
    assert normalize({"description": "x"}, source_name="f").source_kind is SourceKind.API_GENERICA


def test_payload_que_nao_corresponde_a_fonte_declarada_fica_assinalado():
    evento = normalize(
        {"timestamp": INSTANTE, "description": "não é um alerta Wazuh"},
        source_name="chave-wazuh", source_kind=SourceKind.WAZUH,
    )
    assert evento.source_kind is SourceKind.WAZUH
    assert [
        a for a in evento.normalized_extra["avisos_normalizacao"]
        if "não corresponde ao formato esperado de WAZUH" in a
    ]


# ------------------------------------------------------ instante sem ano
@pytest.mark.parametrize(
    ("texto", "agora", "esperado"),
    [
        ("Sep 17 08:15:30", datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
         datetime(2026, 9, 17, 8, 15, 30, tzinfo=UTC)),
        # Recebido logo a seguir à passagem de ano: pertence ao ano anterior.
        ("Dec 31 23:59:58", datetime(2027, 1, 1, 0, 0, 5, tzinfo=UTC),
         datetime(2026, 12, 31, 23, 59, 58, tzinfo=UTC)),
        # Relógio da fonte ligeiramente adiantado: continua a ser este ano.
        ("Sep 17 10:30:00", datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
         datetime(2026, 9, 17, 10, 30, tzinfo=UTC)),
        # 29 de Fevereiro só existe em anos bissextos: o mais recente.
        ("Feb 29 06:00:00", datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
         datetime(2024, 2, 29, 6, 0, tzinfo=UTC)),
    ],
    ids=["mesmo-ano", "passagem-de-ano", "relogio-adiantado", "dia-bissexto"],
)
def test_instante_syslog_sem_ano_recebe_o_ano_certo(texto, agora, esperado):
    """Regressão: o `strptime` preenchia o ano com 1900.

    O formato do syslog clássico não traz ano. Um evento datado de 1900 fica fora
    de qualquer janela de correlação, e cai no fundo da linha temporal e das
    métricas sem erro nenhum. O 29 de Fevereiro nem sequer era lido: 1900 não é
    bissexto, e o evento ficava com a hora de recepção.
    """
    import warnings

    from app.ingestion.base import parse_timestamp

    with warnings.catch_warnings():
        # O Python 3.13 avisa que este uso do `strptime` vai mudar no 3.15.
        warnings.simplefilter("error")
        assert parse_timestamp(texto, agora=agora) == esperado
