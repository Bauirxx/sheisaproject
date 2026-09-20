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
echo "Prefixo da chave Wazuh: ${CHAVE:0:8}…"

# --- chave do Suricata ---------------------------------------------------
# Cada fonte tem a sua chave, para que a origem de qualquer alerta seja
# atribuivel e revogavel isoladamente. O integrador do Suricata le-a de um
# ficheiro de ambiente que o compose carrega.
ENV_SURICATA="$RAIZ/lab/suricata/ingestao.env"
if [ -f "$ENV_SURICATA" ]; then
  echo "Ja existe lab/suricata/ingestao.env; mantido."
else
  echo "A criar a chave de ingestao do Suricata..."
  SAIDA_S="$(cd "$RAIZ/backend" && "$PYTHON" -m scripts.manage create-api-key               --name "Suricata laboratorio $(date +%Y%m%d-%H%M%S)" --kind SURICATA 2>&1)"
  CHAVE_S="$(printf '%s' "$SAIDA_S" | grep -oE 'Chave: [A-Za-z0-9_-]+' | cut -d' ' -f2 || true)"
  if [ -z "$CHAVE_S" ]; then
    echo "ERRO: nao foi possivel criar a chave do Suricata. Saida:" >&2
    printf '%s
' "$SAIDA_S" >&2
    exit 1
  fi
  printf 'SHEISA_SURICATA_KEY=%s
' "$CHAVE_S" > "$ENV_SURICATA"
  echo "Chave do Suricata escrita em lab/suricata/ingestao.env (ignorado pelo git)."
  echo "Prefixo da chave Suricata: ${CHAVE_S:0:8}…"
fi

echo
echo "Agora:"
echo "  docker compose -f lab/docker-compose.lab.yml up -d --build"
