#!/usr/bin/env bash
# Envia o projecto para o GitHub.
#
# O push falhou no ambiente onde o projecto foi construido porque a rede
# bloqueava github.com (443, SSH 22 e SSH 443, todos sem resposta).
# Tudo o resto ja esta feito: os commits existem, o remoto esta configurado e
# o ramo e `main`. Basta correr isto a partir de uma rede sem esse bloqueio.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "A verificar acesso ao GitHub..."
if ! curl -sS -o /dev/null --max-time 15 https://github.com; then
  echo "github.com continua inacessivel a partir desta rede." >&2
  echo "Tente outra ligacao (outra rede Wi-Fi, ou dados moveis diferentes)." >&2
  exit 1
fi

echo "Acesso confirmado. A enviar..."
git push -u origin main
echo
echo "Concluido: https://github.com/Bauirxx/sheisaproject"
