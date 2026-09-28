"""Simulador de laboratório das APIs REST do IBM QRadar e do NetScout.

**Não é o produto do fornecedor.** É um servidor de laboratório que responde nos
mesmos caminhos e com os mesmos formatos que o QRadar e o NetScout expõem, para
que o código real dos conectores da SHEISA (`app/integrations/siem_connectors.py`)
possa ser exercitado ponta a ponta sem uma instância comercial — que não existe
neste ambiente e não se distribui como contentor.

O que é real neste percurso: o conector, o normalizador, a ingestão, a
correlação e o alerta que aparece na plataforma. O que é de laboratório: a fonte
dos dados. A fronteira é a rede, exactamente onde os testes já usam um duplo
HTTP — aqui é persistente, para se poder importar à mão e ver o resultado.

Escolhido `http.server` da biblioteca-padrão de propósito: sem dependências, a
imagem é `python:3.13-slim` sem `pip install`, e não há framework a esconder o
que se está a servir.

Configuração por ambiente:

* ``SIM_VENDOR``  — ``qradar`` ou ``netscout`` (qual API servir);
* ``SIM_TOKEN``   — o token que o conector tem de apresentar; um pedido sem ele,
  ou com outro, recebe 401, tal como o produto real;
* ``SIM_PORT``    — porta de escuta.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

VENDOR = os.environ.get("SIM_VENDOR", "qradar").strip().lower()
TOKEN = os.environ.get("SIM_TOKEN", "")
PORT = int(os.environ.get("SIM_PORT", "8110"))


def _agora_menos(minutos: int) -> datetime:
    return datetime.now(UTC) - timedelta(minutes=minutos)


# --------------------------------------------------------------------- QRadar
# Offenses no formato que `/api/siem/offenses` devolve. Os campos são os que o
# `QRadarConnector._offense_to_event` lê; os valores são de um cenário plausível
# do INCM (tentativas de intrusão a serviços expostos).
def _offenses_qradar() -> list[dict]:
    def ms(minutos: int) -> int:
        return int(_agora_menos(minutos).timestamp() * 1000)

    return [
        {
            "id": 4801,
            "description": "Multiple Failed Logins Followed by Success\n"
            "srv-radius-incm (10.20.1.5)",
            "offense_type_name": "Username",
            "offense_source": "administrador@incm.gov.mz",
            "magnitude": 9,
            "start_time": ms(38),
            "last_updated_time": ms(4),
            "event_count": 214,
            "domain_name": "incm.gov.mz",
            "status": "OPEN",
            "categories": ["Authentication", "Suspicious Activity"],
            "source_address_ids": [3391],
        },
        {
            "id": 4802,
            "description": "Outbound connection to known C2 infrastructure\n"
            "posto-financeiro-02 (10.20.4.31)",
            "offense_type_name": "Destination IP",
            "offense_source": "10.20.4.31",
            "magnitude": 8,
            "start_time": ms(22),
            "last_updated_time": ms(2),
            "event_count": 47,
            "domain_name": "incm.gov.mz",
            "status": "OPEN",
            "categories": ["Malware", "Command and Control"],
            "source_address_ids": [3402],
        },
        {
            "id": 4803,
            "description": "Port scan detected against DMZ web servers",
            "offense_type_name": "Source IP",
            "offense_source": "197.218.0.44",
            "magnitude": 5,
            "start_time": ms(12),
            "last_updated_time": ms(1),
            "event_count": 1330,
            "domain_name": "incm.gov.mz",
            "status": "OPEN",
            "categories": ["Recon", "Suspicious Activity"],
            "source_address_ids": [3410],
        },
    ]


def _about_qradar() -> dict:
    return {
        "release_name": "QRadar 7.5.0 (laboratório SHEISA)",
        "build_version": "2021.6.0.20240115",
        "external_version": "7.5.0",
    }


# ------------------------------------------------------------------- NetScout
# Alertas no formato que `/api/sp/v7/alerts` devolve (JSON:API). Os campos são
# os que o `NetScoutConnector._alert_to_event` lê.
def _alertas_netscout() -> list[dict]:
    def iso(minutos: int) -> str:
        return _agora_menos(minutos).isoformat()

    return [
        {
            "id": "9174",
            "type": "alert",
            "attributes": {
                "alert_class": "dos",
                "alert_type": "dos_host_detection",
                "importance": 2,
                "ongoing": True,
                "start_time": iso(9),
                "subobject": {
                    "host_address": "197.218.10.80",
                    "misuse_types": ["UDP", "DNS Amplification"],
                    "impact_bps": 4_850_000_000,
                    "impact_pps": 3_200_000,
                },
            },
        },
        {
            "id": "9175",
            "type": "alert",
            "attributes": {
                "alert_class": "dos",
                "alert_type": "dos_profiled_router",
                "importance": 1,
                "ongoing": True,
                "start_time": iso(4),
                "subobject": {
                    "host_address": "197.218.10.64/26",
                    "misuse_types": ["TCP SYN"],
                    "impact_bps": 920_000_000,
                    "impact_pps": 610_000,
                },
            },
        },
    ]


# --------------------------------------------------------------- servidor HTTP
class Manipulador(BaseHTTPRequestHandler):
    server_version = f"siem-sim/{VENDOR}"

    def log_message(self, formato: str, *args) -> None:  # noqa: A002 - assinatura da base
        # Uma linha por pedido, para se ver a importação a acontecer nos registos.
        print(f"[{VENDOR}] {self.address_string()} {formato % args}", flush=True)

    def _json(self, codigo: int, corpo) -> None:
        dados = json.dumps(corpo).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(dados)))
        self.end_headers()
        self.wfile.write(dados)

    def _token_valido(self, nome_do_cabecalho: str) -> bool:
        return bool(TOKEN) and self.headers.get(nome_do_cabecalho) == TOKEN

    def _nao_autorizado(self, nome_do_cabecalho: str) -> None:
        self._json(
            401,
            {"erro": f"token ausente ou inválido no cabeçalho {nome_do_cabecalho}"},
        )

    def do_GET(self) -> None:  # noqa: N802 - nome imposto pela base
        caminho = urlparse(self.path).path
        consulta = parse_qs(urlparse(self.path).query)

        if VENDOR == "qradar":
            self._qradar(caminho, consulta)
        elif VENDOR == "netscout":
            self._netscout(caminho, consulta)
        else:
            self._json(500, {"erro": f"SIM_VENDOR desconhecido: {VENDOR}"})

    # -- QRadar: cabeçalho de autenticação `SEC`
    def _qradar(self, caminho: str, consulta: dict) -> None:
        if not self._token_valido("SEC"):
            return self._nao_autorizado("SEC")

        if caminho == "/api/system/about":
            return self._json(200, _about_qradar())

        if caminho == "/api/siem/offenses":
            offenses = _offenses_qradar()
            limite = self._limite_do_range(len(offenses))
            return self._json(200, offenses[:limite])

        self._json(404, {"erro": f"caminho não servido: {caminho}"})

    def _limite_do_range(self, total: int) -> int:
        """Lê `Range: items=0-N`, como o cliente do QRadar o envia."""
        intervalo = self.headers.get("Range", "")
        if intervalo.startswith("items="):
            try:
                fim = int(intervalo.split("=", 1)[1].split("-")[1])
                return min(total, fim + 1)
            except (ValueError, IndexError):
                pass
        return total

    # -- NetScout: cabeçalho de autenticação `X-Arbux-APIToken`
    def _netscout(self, caminho: str, consulta: dict) -> None:
        if not self._token_valido("X-Arbux-APIToken"):
            return self._nao_autorizado("X-Arbux-APIToken")

        if caminho == "/api/sp/v7/alerts":
            alertas = _alertas_netscout()
            por_pagina = consulta.get("perPage", [str(len(alertas))])[0]
            try:
                limite = min(len(alertas), int(por_pagina))
            except ValueError:
                limite = len(alertas)
            return self._json(
                200,
                {
                    "meta": {"available": len(alertas), "limits": {"perPage": limite}},
                    "data": alertas[:limite],
                },
            )

        self._json(404, {"erro": f"caminho não servido: {caminho}"})


def main() -> None:
    if not TOKEN:
        raise SystemExit("SIM_TOKEN tem de estar definido — sem token, tudo daria 401.")
    servidor = ThreadingHTTPServer(("0.0.0.0", PORT), Manipulador)
    print(
        f"Simulador {VENDOR.upper()} de laboratório à escuta em :{PORT} "
        f"(NÃO é o produto do fornecedor).",
        flush=True,
    )
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        servidor.shutdown()


if __name__ == "__main__":
    main()
