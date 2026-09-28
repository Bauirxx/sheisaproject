#!/usr/bin/env python3
"""Integrador do Suricata para a plataforma SHEISA (§26).

O Suricata não invoca um script por evento como o Wazuh faz — escreve um fluxo
contínuo de objectos JSON em `eve.json`. Este integrador **segue** esse ficheiro,
recolhe os registos de tipo `alert` e entrega-os à plataforma em lote.

Quatro decisões que convém não desfazer:

**Só a biblioteca padrão.** Como o integrador do Wazuh: um POST não justifica
arrastar dependências para dentro de um contentor de laboratório. `urllib` chega.

**Só os `alert`.** O `eve.json` traz também `http`, `dns`, `tls`, `flow` — úteis
para contexto, ruído para uma fila de detecção. O normalizador da plataforma
também os ignora, mas filtrar aqui poupa-lhe o trabalho e a rede.

**Idempotente por natureza, com posição guardada por cortesia.** A ingestão
deduplica por `source_event_id` (o Suricata dá `flow_id`+`signature_id`), pelo que
reenviar um alerta não cria um duplicado. Ainda assim guarda-se o deslocamento
já lido, para que um reinício não reenvie o histórico inteiro sem necessidade.

**Segue a rotação do ficheiro.** Se o `eve.json` encolher — porque foi rodado —
recomeça do início, em vez de ficar parado à espera de um ficheiro que já não
cresce.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

EVE = Path(os.environ.get("EVE_PATH", "/var/log/suricata/eve.json"))
HOOK_URL = os.environ.get("SHEISA_HOOK_URL", "")
API_KEY = os.environ.get("SHEISA_API_KEY", "")
#: Onde fica o deslocamento já lido, para sobreviver a um reinício.
POSICAO = Path(os.environ.get("EVE_POSICAO", "/var/lib/suricata-integrador/posicao"))
#: Intervalo entre varreduras do ficheiro.
INTERVALO = float(os.environ.get("INTERVALO_SEGUNDOS", "3"))
#: Máximo de alertas por POST. Um pico de detecções não deve produzir um corpo
#: gigante nem esperar indefinidamente a acumular.
LOTE_MAXIMO = int(os.environ.get("LOTE_MAXIMO", "100"))
TEMPO_LIMITE = float(os.environ.get("TEMPO_LIMITE_SEGUNDOS", "15"))


def registar(mensagem: str) -> None:
    instante = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{instante} suricata-sheisa: {mensagem}", flush=True)


def _contexto_ssl(url: str) -> ssl.SSLContext | None:
    """Só desliga a verificação para destinos locais, como o integrador Wazuh.

    Desligá-la para qualquer destino transformaria isto num canal sem
    autenticação do servidor, e a chave de API viajaria para quem estivesse no
    meio.
    """
    if url.startswith("https://") and any(
        marca in url for marca in ("localhost", "127.0.0.1", "host.docker.internal")
    ):
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        return contexto
    return None


def entregar(alertas: list[dict]) -> bool:
    """Entrega um lote de alertas. Devolve se a plataforma o aceitou."""
    corpo = json.dumps(alertas).encode("utf-8")
    pedido = urllib.request.Request(
        HOOK_URL,
        data=corpo,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "User-Agent": "suricata-integrator/sheisa",
        },
    )
    try:
        with urllib.request.urlopen(
            pedido, timeout=TEMPO_LIMITE, context=_contexto_ssl(HOOK_URL)
        ) as resposta:
            resultado = json.loads(resposta.read() or b"{}")
            registar(
                f"{len(alertas)} alerta(s) entregue(s) "
                f"(HTTP {resposta.status}, processados={resultado.get('processados', '?')})"
            )
            return True
    except urllib.error.HTTPError as erro:
        try:
            detalhe = json.loads(erro.read() or b"{}").get("erro", {})
            registar(
                f"a plataforma recusou o lote: HTTP {erro.code} "
                f"{detalhe.get('codigo', '?')} {detalhe.get('mensagem', '')}"
            )
        except (json.JSONDecodeError, OSError):
            registar(f"a plataforma recusou o lote: HTTP {erro.code}")
    except urllib.error.URLError as erro:
        registar(f"a plataforma não respondeu ({HOOK_URL}): {erro.reason}")
    except Exception as erro:  # noqa: BLE001 - o integrador não pode morrer por um POST
        registar(f"erro inesperado ao entregar o lote: {erro!r}")
    return False


def ler_posicao() -> int:
    try:
        return int(POSICAO.read_text().strip())
    except (OSError, ValueError):
        return 0


def guardar_posicao(offset: int) -> None:
    try:
        POSICAO.parent.mkdir(parents=True, exist_ok=True)
        POSICAO.write_text(str(offset))
    except OSError as erro:
        registar(f"não foi possível guardar a posição: {erro}")


def main() -> int:
    if not HOOK_URL or not API_KEY:
        registar("SHEISA_HOOK_URL e SHEISA_API_KEY têm de estar definidos.")
        return 1

    registar(f"a seguir {EVE}; a entregar em {HOOK_URL}")
    offset = ler_posicao()

    while True:
        try:
            tamanho = EVE.stat().st_size if EVE.exists() else 0
        except OSError:
            tamanho = 0

        # O ficheiro encolheu: foi rodado. Recomeça do início.
        if tamanho < offset:
            registar("o eve.json foi rodado; a recomeçar do início.")
            offset = 0

        if tamanho > offset and EVE.exists():
            lote: list[dict] = []
            with EVE.open("r", encoding="utf-8", errors="replace") as ficheiro:
                ficheiro.seek(offset)
                for linha in ficheiro:
                    # Uma linha incompleta (o Suricata ainda a escrever) fica
                    # para a próxima varredura: só se avança o offset até ao fim
                    # de linhas inteiras.
                    if not linha.endswith("\n"):
                        break
                    offset += len(linha.encode("utf-8"))
                    linha = linha.strip()
                    if not linha:
                        continue
                    try:
                        evento = json.loads(linha)
                    except json.JSONDecodeError:
                        continue
                    if evento.get("event_type") == "alert":
                        lote.append(evento)
                        if len(lote) >= LOTE_MAXIMO:
                            if entregar(lote):
                                guardar_posicao(offset)
                            lote = []

            if lote and entregar(lote):
                guardar_posicao(offset)
            elif not lote:
                # Avançou o offset sobre linhas que não eram alertas.
                guardar_posicao(offset)

        time.sleep(INTERVALO)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
