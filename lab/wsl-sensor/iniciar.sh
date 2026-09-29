#!/bin/sh
# Arranca o sensor Suricata na WSL (rede espelhada) + o integrador.
#   ./iniciar.sh        (corre DENTRO da distro Ubuntu-24.04 da WSL, como root)
#
# Pressupoe rede espelhada activa (SHEISA_HOST=0.0.0.0 e .wslconfig com
# networkingMode=mirrored) -- ver README.md.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

[ -f ./sensor.env ] || { echo "ERRO: falta sensor.env (copie sensor.env.exemplo e preencha)."; exit 1; }
set -a; . ./sensor.env; set +a

INTERFACE="$(./detectar_interface.sh)"
[ -n "$INTERFACE" ] || { echo "ERRO: nao encontrei uma interface com IP real."; exit 1; }
echo "[iniciar] interface detectada: $INTERFACE ($(ip -o -4 addr show "$INTERFACE" | awk '{print $4}'))"

# A flag `-i` do Suricata NAO substitui o nome fixo na seccao af-packet: com
# varias threads (cluster-type: cluster_flow), cada worker continua a abrir o
# interface literal do YAML, e falha em silencio ("can't reopen interface") se
# esse nome nao existir -- o motor arranca (threads criadas, "Engine started")
# mas nao captura nada, sem erro fatal que o denuncie. Por isso gera-se uma
# copia do YAML com o nome verdadeiro da interface, a cada arranque -- o nome
# muda entre arranques em modo espelhado (visto eth3, eth4 no mesmo dia).
sed "s/interface: eth0/interface: $INTERFACE/" suricata.yaml > /tmp/suricata-sheisa.yaml

mkdir -p /var/log/suricata /var/lib/suricata-integrador
echo "[iniciar] a actualizar as regras Emerging Threats Open (melhor esforco)..."
suricata-update --no-test --quiet 2>/dev/null || echo "[iniciar] AVISO: suricata-update falhou (sem rede?); sigo com as regras locais."

echo "[iniciar] a arrancar o Suricata em $INTERFACE..."
nohup suricata -c /tmp/suricata-sheisa.yaml -i "$INTERFACE" \
  --pidfile /var/run/suricata-sheisa.pid \
  > /var/log/suricata/stdout.log 2>&1 &
sleep 3
if ! kill -0 "$(cat /var/run/suricata-sheisa.pid 2>/dev/null)" 2>/dev/null; then
  echo "ERRO: o Suricata nao arrancou. Ver /var/log/suricata/stdout.log e /var/log/suricata/suricata.log"; exit 1
fi
if grep -q "can't reopen interface" /var/log/suricata/suricata.log 2>/dev/null; then
  echo "AVISO: o Suricata arrancou mas ainda ha erros de interface -- confirme com:"
  echo "  tail /var/log/suricata/suricata.log"
fi
echo "[iniciar] Suricata a correr, PID $(cat /var/run/suricata-sheisa.pid)."

echo "[iniciar] a arrancar o integrador..."
EVE_PATH=/var/log/suricata/eve.json \
  nohup python3 "$HERE/suricata-sheisa.py" > /var/log/suricata/integrador.log 2>&1 &
echo $! > /var/run/suricata-integrador-sheisa.pid
sleep 1
echo "[iniciar] Integrador a correr, PID $(cat /var/run/suricata-integrador-sheisa.pid)."

echo
echo "Para acompanhar:"
echo "  tail -f /var/log/suricata/fast.log"
echo "  tail -f /var/log/suricata/integrador.log"
echo "Para parar: ./parar.sh"
