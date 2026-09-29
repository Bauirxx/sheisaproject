#!/bin/sh
# Para o sensor Suricata e o integrador.
set -u
for pidfile in /var/run/suricata-sheisa.pid /var/run/suricata-integrador-sheisa.pid; do
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && echo "parado: PID $pid ($pidfile)"
    fi
    rm -f "$pidfile"
  fi
done
