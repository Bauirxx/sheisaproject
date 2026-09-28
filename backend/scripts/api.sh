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
# Interface de escuta. Por omissao 127.0.0.1 (so a propria maquina). Ponha
# SHEISA_HOST=0.0.0.0 para aceitar ligacoes da rede local -- necessario quando
# um sensor Suricata (ou outra fonte) noutro computador entrega na ingestao.
# So numa rede de confianca: e um servidor de desenvolvimento, sem TLS.
HOST="${SHEISA_HOST:-127.0.0.1}"
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

load_env() {
  # Carrega o .env da raiz para o AMBIENTE do processo. O pydantic ja le o .env,
  # mas so para os campos que declara (config.py). Os segredos das integracoes
  # (SHEISA_QRADAR_*, SHEISA_NETSCOUT_*, SHEISA_WAZUH_*) sao lidos direto de
  # os.environ pelos conectores, pelo que TEM de estar no ambiente. Le-se linha
  # a linha, tomando tudo depois do primeiro '=' como valor: assim valores com
  # espacos (ex.: SHEISA_MAIL_FROM_NAME) nao sao reinterpretados pela shell.
  local envfile="$HERE/../.env"
  [ -f "$envfile" ] || return 0
  while IFS= read -r linha || [ -n "$linha" ]; do
    linha="${linha%$'\r'}"
    case "$linha" in ''|\#*) continue ;; esac
    export "${linha%%=*}=${linha#*=}"
  done < "$envfile"
}

start_server() {
  cd "$HERE"
  load_env
  # Recalcular depois do load_env: assim SHEISA_HOST pode vir do .env, e nao so
  # da linha de comando (o valor do topo foi lido antes de o .env ser carregado).
  HOST="${SHEISA_HOST:-$HOST}"
  if [ "$(port_busy)" = "BUSY" ]; then
    echo "ERRO: a porta $PORT ja esta ocupada. Use 'stop' primeiro."; return 1
  fi
  nohup ./.venv/Scripts/python.exe -m uvicorn app.main:app \
      --host "$HOST" --port "$PORT" --log-level warning \
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
