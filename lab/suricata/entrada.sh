#!/bin/sh
# Arranque do sensor Suricata no laboratório SHEISA (§26).
#
# Faz duas coisas antes de arrancar o motor, e a ordem importa:
#
#   1. Obtém o conjunto Emerging Threats Open com `suricata-update`. É o ruleset
#      que um SOC usa de verdade — dezenas de milhares de assinaturas mantidas.
#      O download é **best-effort**: se não houver rede, o sensor arranca à mesma
#      com as regras locais, e o log di-lo. Um laboratório que não arranca por
#      não ter conseguido descarregar regras seria pior do que um laboratório
#      com menos regras.
#
#   2. Espera pela interface. Como o sensor partilha o stack de rede do alvo
#      (`network_mode: service:alvo`), a interface pode ainda não existir no
#      instante exacto do arranque.
#
# Depois cede o processo ao Suricata com `exec`, para que ele receba os sinais
# do Docker directamente e pare de forma limpa.
set -eu

INTERFACE="${SURICATA_IFACE:-eth0}"

echo "[entrada] a actualizar as regras (Emerging Threats Open)..."
if suricata-update --no-test --quiet 2>/dev/null; then
  echo "[entrada] regras actualizadas."
else
  echo "[entrada] AVISO: suricata-update falhou (sem rede?). Arranco com as regras locais."
  # Garante que o ficheiro que a configuração espera existe, mesmo vazio: sem
  # ele o Suricata recusa arrancar por um rule-file em falta.
  mkdir -p /var/lib/suricata/rules
  [ -f /var/lib/suricata/rules/suricata.rules ] || : > /var/lib/suricata/rules/suricata.rules
fi

echo "[entrada] à espera da interface $INTERFACE..."
tentativas=0
while ! ip link show "$INTERFACE" >/dev/null 2>&1; do
  tentativas=$((tentativas + 1))
  if [ "$tentativas" -gt 30 ]; then
    echo "[entrada] ERRO: a interface $INTERFACE não apareceu." >&2
    exit 1
  fi
  sleep 1
done

echo "[entrada] a arrancar o Suricata em $INTERFACE..."
exec suricata -c /etc/suricata/suricata.yaml -i "$INTERFACE"
