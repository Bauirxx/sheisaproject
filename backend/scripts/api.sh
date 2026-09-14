#!/usr/bin/env bash
# Arranque/paragem do servidor de desenvolvimento.
#   scripts/api.sh start | stop | restart | status
#
# A paragem e feita por PORTA e nao por padrao de linha de comandos: em Windows
# o processo uvicorn aparece apenas como "python3.11" e um pkill por padrao nao
# lhe acerta, deixando uma instancia antiga a servir codigo obsoleto.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${SHEISA_PORT:-8099}"
PIDFILE="$HERE/var/tmp/api.pid"
LOGFILE="$HERE/var/tmp/api.log"
mkdir -p "$HERE/var/tmp"

stop_server() {
  powershell.exe -NoProfile -NonInteractive -Command "
    \$c = Get-NetTCPConnection -LocalPort $PORT -State Listen -ErrorAction SilentlyContinue
    if (\$c) { \$c | Select-Object -ExpandProperty OwningProcess -Unique |
               ForEach-Object { Stop-Process -Id \$_ -Force -ErrorAction SilentlyContinue } }
  " >/dev/null 2>&1
  rm -f "$PIDFILE"
  sleep 2
}

port_busy() {
  powershell.exe -NoProfile -NonInteractive -Command "
    if (Get-NetTCPConnection -LocalPort $PORT -State Listen -ErrorAction SilentlyContinue) {'BUSY'} else {'FREE'}
  " 2>/dev/null | tr -d '\r\n'
}

start_server() {
  cd "$HERE"
  if [ "$(port_busy)" = "BUSY" ]; then
    echo "ERRO: a porta $PORT ja esta ocupada. Use 'stop' primeiro."; return 1
  fi
  nohup ./.venv/Scripts/python.exe -m uvicorn app.main:app \
      --host 127.0.0.1 --port "$PORT" --log-level warning \
      > "$LOGFILE" 2>&1 &
  echo $! > "$PIDFILE"
  for _ in $(seq 1 30); do
    if curl -s --max-time 2 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
      echo "API operacional em http://127.0.0.1:$PORT"
      return 0
    fi
    sleep 1
  done
  echo "A API nao arrancou. Ultimas linhas do log:"; tail -25 "$LOGFILE"; return 1
}

case "${1:-status}" in
  start)   start_server ;;
  stop)    stop_server; echo "API parada (porta $PORT: $(port_busy))." ;;
  restart) stop_server; start_server ;;
  status)  curl -s "http://127.0.0.1:$PORT/api/health" && echo || echo "API inacessivel." ;;
  *) echo "Uso: $0 {start|stop|restart|status}"; exit 2 ;;
esac
