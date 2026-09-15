#!/usr/bin/env bash
# Prepara o laboratorio: cria a chave de ingestao e escreve a configuracao.
#
#   ./lab/preparar.sh
#
# Separa-se do arranque de proposito. A chave so pode ser vista uma vez — a
# plataforma guarda apenas o hash — pelo que criar uma chave nova a cada
# `docker compose up` deixaria um rasto de chaves orfas na base de dados.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$RAIZ/lab/config/ossec.conf"
EXEMPLO="$RAIZ/lab/config/ossec.conf.exemplo"
PYTHON="$RAIZ/backend/.venv/Scripts/python.exe"
[ -x "$PYTHON" ] || PYTHON="$RAIZ/backend/.venv/bin/python"

if [ -f "$CONFIG" ]; then
  echo "Ja existe $CONFIG."
  echo "Apague-o se quiser gerar uma chave nova."
  exit 0
fi

echo "A criar a chave de ingestao..."
SAIDA="$(cd "$RAIZ/backend" && "$PYTHON" -m scripts.manage create-api-key \
          --name "Wazuh laboratorio $(date +%Y%m%d-%H%M%S)" --kind WAZUH 2>&1)"
CHAVE="$(printf '%s' "$SAIDA" | grep -oE 'Chave: [A-Za-z0-9_-]+' | cut -d' ' -f2 || true)"

if [ -z "$CHAVE" ]; then
  echo "ERRO: nao foi possivel criar a chave. Saida do comando:" >&2
  printf '%s\n' "$SAIDA" >&2
  echo >&2
  echo "A plataforma esta a correr? (docker compose up -d db)" >&2
  exit 1
fi

sed "s|SUBSTITUIR-PELA-CHAVE-DE-INGESTAO|$CHAVE|" "$EXEMPLO" > "$CONFIG"
echo "Configuracao escrita em lab/config/ossec.conf (ignorado pelo git)."
echo "Prefixo da chave: ${CHAVE:0:8}…"
echo
echo "Agora:"
echo "  docker compose -f lab/docker-compose.lab.yml up -d --build"
