#!/bin/sh
# Devolve o nome da interface com um IP real (nao loopback, nao a IP interna
# 10.255.255.254 que a WSL usa para si propria em modo espelhado). Em modo
# espelhado o nome muda entre arranques (eth3, eth4, ...), por isso nunca se
# fixa no ficheiro de configuracao -- descobre-se aqui, a cada arranque.
ip -o -4 addr show \
  | awk '{print $2, $4}' \
  | grep -v '^lo ' \
  | grep -v ' 10\.255\.' \
  | head -1 \
  | cut -d' ' -f1
