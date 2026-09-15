#!/usr/bin/env bash
# Gerador de actividade para o laboratório (§26).
#
#   ./lab/gerar-alertas.sh forca-bruta      tentativas SSH falhadas
#   ./lab/gerar-alertas.sh acesso-valido    autenticação bem sucedida
#   ./lab/gerar-alertas.sh web              varrimento de um serviço web
#   ./lab/gerar-alertas.sh tudo             os três, com pausas
#
# Escreve linhas de registo **no formato real** que o sshd e o Apache produzem,
# no ficheiro que o colector Wazuh vigia. Não injecta alertas: injecta *logs*.
# A diferença é o ponto todo do laboratório — quem decide que aquilo é um
# alerta, com que nível e que grupos de regra, são as regras do Wazuh, não este
# script. Um gerador que escrevesse alertas já formados saltaria por cima da
# camada que se quer demonstrar.
set -euo pipefail

# O Git Bash do Windows converte caminhos que começam por '/' em caminhos
# Windows antes de os passar ao docker, o que faria '/var/log/lab/...' chegar
# ao contentor como 'C:/Program Files/Git/var/log/...'. Desligar a conversão é
# a forma suportada de o evitar; não tem efeito em Linux ou macOS.
export MSYS_NO_PATHCONV=1

# Onde escrever.
#
# O agente é o destino por omissão porque é a topologia real: os registos vivem
# no anfitrião monitorizado, não no gestor. Sem o agente a correr, usa-se o
# gestor, que vigia uma pasta própria — e assim o laboratório funciona à mesma.
#
# **Cada colector tem a sua pasta.** Se os dois vigiassem o mesmo ficheiro,
# cada linha de log produziria dois alertas — um por colector — e a plataforma
# mostraria tudo em duplicado.
if [ -n "${CONTENTOR:-}" ]; then
  ALVO="$CONTENTOR"
elif docker ps --format '{{.Names}}' | grep -q '^sheisa-wazuh-agent$'; then
  ALVO="sheisa-wazuh-agent"
else
  ALVO="sheisa-wazuh-manager"
fi

if [ "$ALVO" = "sheisa-wazuh-agent" ]; then
  PASTA="/var/log/lab/agente"
else
  PASTA="/var/log/lab/gestor"
fi

REGISTO_AUTH="$PASTA/auth.log"
REGISTO_WEB="$PASTA/web.log"

ATACANTE="${ATACANTE:-203.0.113.212}"
ANFITRIAO="${ANFITRIAO:-srv-web-lab}"

escrever() {
  local ficheiro="$1"
  shift
  docker exec "$ALVO" sh -c "mkdir -p '$PASTA' && printf '%s\n' \"$*\" >> '$ficheiro'"
}

instante() {
  # Formato do syslog: "Sep 15 13:05:09".
  #
  # A hora vem do **contentor**, não do anfitrião.
  #
  # Os contentores correm em UTC e o anfitrião está em CAT (UTC+2). Usar
  # `date` do anfitrião datava cada linha duas horas no futuro em relação ao
  # relógio do Wazuh, e o logcollector descartava-as: os registos apareciam no
  # ficheiro, o colector dizia estar a analisá-lo, a regra correspondia no
  # `wazuh-logtest`, e mesmo assim não nascia alerta nenhum — sem uma única
  # mensagem de erro em lado nenhum. Custou uma hora a diagnosticar.
  #
  # `%e` em vez de `%d` porque o syslog usa dia sem zero à esquerda.
  docker exec "$ALVO" date "+%b %e %H:%M:%S"
}

instante_apache() {
  # Formato do Apache: "15/Sep/2026:13:05:09 +0000". Mesma razao para vir do
  # contentor: ver `instante`.
  docker exec "$ALVO" date "+%d/%b/%Y:%H:%M:%S %z"
}

forca_bruta() {
  echo "A escrever tentativas de autenticação falhadas de $ATACANTE..."
  for i in $(seq 1 8); do
    escrever "$REGISTO_AUTH" \
      "$(instante) $ANFITRIAO sshd[$((4400 + i))]: Failed password for invalid user oracle from $ATACANTE port $((51200 + i)) ssh2"
    sleep 1
  done
  escrever "$REGISTO_AUTH" \
    "$(instante) $ANFITRIAO sshd[4412]: Disconnecting invalid user oracle $ATACANTE port 51299: Too many authentication failures"
  echo "  8 falhas + desconexão escritas."
}

acesso_valido() {
  echo "A escrever uma autenticação bem sucedida de $ATACANTE..."
  escrever "$REGISTO_AUTH" \
    "$(instante) $ANFITRIAO sshd[4500]: Accepted password for backup from $ATACANTE port 51310 ssh2"
  echo "  1 acesso aceite escrito."
}

web() {
  echo "A escrever pedidos web suspeitos de $ATACANTE..."
  local caminhos=(
    "/../../../../etc/passwd"
    "/index.php?id=1%27%20OR%20%271%27=%271"
    "/admin/config.php"
    "/wp-login.php"
    "/.env"
  )
  for caminho in "${caminhos[@]}"; do
    escrever "$REGISTO_WEB" \
      "$ATACANTE - - [$(instante_apache)] \"GET $caminho HTTP/1.1\" 404 162 \"-\" \"sqlmap/1.7\""
    sleep 1
  done
  echo "  ${#caminhos[@]} pedidos escritos."
}

if ! docker ps --format '{{.Names}}' | grep -q "^${ALVO}$"; then
  echo "ERRO: o contentor '$ALVO' não está a correr." >&2
  echo "Arranque o laboratório com:" >&2
  echo "  ./lab/preparar.sh" >&2
  echo "  docker compose -f lab/docker-compose.lab.yml up -d --build" >&2
  exit 1
fi

echo "A escrever em $ALVO ($PASTA)."
echo

case "${1:-tudo}" in
  forca-bruta)   forca_bruta ;;
  acesso-valido) acesso_valido ;;
  web)           web ;;
  tudo)
    forca_bruta
    sleep 3
    acesso_valido
    sleep 3
    web
    ;;
  *)
    echo "Uso: $0 {forca-bruta|acesso-valido|web|tudo}" >&2
    exit 2
    ;;
esac

echo
echo "O gestor demora alguns segundos a analisar. Para acompanhar:"
echo "  docker exec sheisa-wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json"
echo "  docker exec sheisa-wazuh-manager tail -f /var/ossec/logs/integrations.log"
echo
echo "E na plataforma: http://127.0.0.1:5500/alertas"
