#!/usr/bin/env python3
"""Integrador do Wazuh para a plataforma SHEISA (§26).

O daemon `integrator` do Wazuh invoca este script assim:

    custom-sheisa <ficheiro-do-alerta> <api_key> <hook_url>

    argv[1]  caminho de um ficheiro temporário com o alerta em JSON
    argv[2]  o valor de <api_key> do bloco <integration> do ossec.conf
    argv[3]  o valor de <hook_url>
    argv[4]  opcional, presente em algumas versões; ignorado

Três decisões que esta implementação toma e que convém não desfazer:

**Só a biblioteca padrão.** O container do gestor Wazuh traz um Python mínimo;
instalar `requests` ali significaria manter uma imagem própria só por causa de
um POST. `urllib` chega e não acrescenta nada ao que já lá está.

**Falha em silêncio para o Wazuh, em voz alta para o log.** O `integrator`
descarta a saída do script e não reage ao código de saída; uma excepção por
propagar não avisa ninguém e pode, em certas versões, interromper o
processamento dos alertas seguintes. Todos os erros vão para
`/var/ossec/logs/integrations.log`, que é onde um administrador de Wazuh os
procura.

**Nunca reescreve o alerta.** O que sai daqui é exactamente o JSON que o Wazuh
escreveu. Normalizar do lado do emissor esconderia do servidor o que a fonte
disse de facto, e é o servidor que tem de guardar o original (§8).
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

#: Onde o administrador do Wazuh procura o que correu mal.
FICHEIRO_DE_LOG = Path("/var/ossec/logs/integrations.log")

#: Tempo máximo à espera da plataforma. Curto de propósito: o `integrator`
#: corre um processo por alerta, e num pico de detecções um tempo-limite longo
#: acumularia processos até esgotar o gestor.
TEMPO_LIMITE_SEGUNDOS = 10


def registar(mensagem: str) -> None:
    """Escreve no log do Wazuh, sem nunca rebentar por causa disso."""
    instante = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")
    linha = f"{instante} custom-sheisa: {mensagem}\n"
    try:
        with FICHEIRO_DE_LOG.open("a", encoding="utf-8") as ficheiro:
            ficheiro.write(linha)
    except OSError:
        # Sem permissão de escrita no log (por exemplo, a correr à mão fora do
        # container): imprime-se, que é melhor do que perder a mensagem.
        sys.stderr.write(linha)


def ler_alerta(caminho: str) -> dict | None:
    try:
        conteudo = Path(caminho).read_text(encoding="utf-8")
    except OSError as erro:
        registar(f"não foi possível ler o ficheiro do alerta {caminho}: {erro}")
        return None

    try:
        alerta = json.loads(conteudo)
    except json.JSONDecodeError as erro:
        registar(f"o ficheiro do alerta não é JSON válido: {erro}")
        return None

    if not isinstance(alerta, dict):
        registar("o alerta não é um objecto JSON; ignorado")
        return None
    return alerta


def enviar(alerta: dict, api_key: str, hook_url: str) -> bool:
    corpo = json.dumps(alerta).encode("utf-8")
    pedido = urllib.request.Request(
        hook_url,
        data=corpo,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "wazuh-integrator/custom-sheisa",
        },
    )

    # Em laboratório o certificado é auto-assinado. A verificação só é
    # desactivada quando o destino é explicitamente local: desligá-la para
    # qualquer destino transformaria o integrador num canal sem autenticação
    # do servidor, e a chave de API viajaria para quem estivesse no meio.
    contexto = None
    if hook_url.startswith("https://") and any(
        marca in hook_url for marca in ("localhost", "127.0.0.1", "host.docker.internal")
    ):
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(
            pedido, timeout=TEMPO_LIMITE_SEGUNDOS, context=contexto
        ) as resposta:
            resultado = json.loads(resposta.read() or b"{}")
            processados = resultado.get("processados", "?")
            detalhes = resultado.get("resultados") or []
            estado = detalhes[0].get("estado") if detalhes else "?"
            registar(
                f"alerta {alerta.get('id', '?')} entregue "
                f"(HTTP {resposta.status}, processados={processados}, estado={estado})"
            )
            return True

    except urllib.error.HTTPError as erro:
        # A plataforma responde sempre no mesmo formato de erro; registar o
        # código é o que permite distinguir "chave inválida" de "servidor em
        # baixo" sem ter de reproduzir o problema.
        try:
            detalhe = json.loads(erro.read() or b"{}").get("erro", {})
            codigo = detalhe.get("codigo", "?")
            mensagem = detalhe.get("mensagem", "")
        except (json.JSONDecodeError, OSError):
            codigo, mensagem = "?", ""
        registar(
            f"a plataforma recusou o alerta {alerta.get('id', '?')}: "
            f"HTTP {erro.code} {codigo} {mensagem}"
        )
    except urllib.error.URLError as erro:
        registar(f"a plataforma não respondeu ({hook_url}): {erro.reason}")
    except TimeoutError:
        registar(f"a plataforma não respondeu em {TEMPO_LIMITE_SEGUNDOS}s ({hook_url})")
    except Exception as erro:  # noqa: BLE001 - nada pode escapar para o integrator
        registar(f"erro inesperado ao entregar o alerta: {erro!r}")

    return False


def main(argumentos: list[str]) -> int:
    if len(argumentos) < 4:
        registar(
            "invocação inválida. Esperado: custom-sheisa <ficheiro> <api_key> "
            f"<hook_url>; recebido {len(argumentos) - 1} argumento(s)."
        )
        return 0

    ficheiro, api_key, hook_url = argumentos[1], argumentos[2], argumentos[3]

    if not api_key:
        registar("api_key vazia no ossec.conf; o alerta não pode ser autenticado")
        return 0
    if not hook_url:
        registar("hook_url vazio no ossec.conf")
        return 0

    alerta = ler_alerta(ficheiro)
    if alerta is None:
        return 0

    enviar(alerta, api_key, hook_url)

    # Sempre 0. O `integrator` não trata códigos de saída, e devolver erro só
    # polui o log do Wazuh com falhas de um processo que ele não vai repetir.
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
