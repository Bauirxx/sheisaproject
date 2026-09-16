"""Extracção do texto de um PDF, para os testes verificarem o conteúdo.

O reportlab escreve os fluxos com `/Filter [/ASCII85Decode /FlateDecode]`:
ASCII85 **antes** do zlib. Tentar só `zlib.decompress` falha em silêncio e
devolve lixo que parece texto — o que faria um teste de conteúdo passar a
dizer "em falta" para tudo, incluindo secções que lá estão.
"""

from __future__ import annotations

import base64
import contextlib
import re
import zlib

_TEXTO = re.compile(rb"\(([^)]*)\)")


def texto_do_pdf(dados: bytes) -> str:
    blocos: list[bytes] = []
    i = 0
    while True:
        inicio = dados.find(b"stream", i)
        if inicio == -1:
            break
        inicio += len(b"stream")
        while dados[inicio : inicio + 1] in (b"\r", b"\n"):
            inicio += 1
        fim = dados.find(b"endstream", inicio)
        if fim == -1:
            break

        bruto = dados[inicio:fim]
        # Nem todos os fluxos usam os dois filtros (ou algum deles): o que
        # falhar a descodificar segue como está, e os que descodificam bem
        # fornecem o texto. Suprimir aqui é deliberado — um fluxo de imagem
        # não é erro, é apenas um fluxo sem texto.
        with contextlib.suppress(Exception):
            limpo = bruto.strip()
            if limpo.endswith(b"~>"):
                limpo = limpo[:-2]
            bruto = base64.a85decode(limpo)
        with contextlib.suppress(Exception):
            bruto = zlib.decompress(bruto)
        blocos.append(bruto)

        # Avançar para depois de "endstream": a palavra contém "stream", e
        # parar antes faria o `find` seguinte apanhar essa cauda como um novo
        # fluxo, deixando as páginas seguintes por descodificar.
        i = fim + len(b"endstream")

    return " ".join(
        m.group(1).decode("latin-1") for bloco in blocos for m in _TEXTO.finditer(bloco)
    )
