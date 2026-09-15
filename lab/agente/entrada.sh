#!/bin/sh
# Arranque do agente Wazuh do laboratorio.
#
# O nome e o gestor vem do ambiente para que o mesmo Dockerfile sirva varios
# agentes sem ser reconstruido. O registo e refeito a cada arranque porque o
# laboratorio e efemero: um agente que assumisse estar ja registado ficaria
# mudo depois de o volume do gestor ser recriado, e o sintoma — alertas que
# deixam de chegar sem nenhum erro visivel — e dificil de diagnosticar.
#
# Tudo aqui e shell POSIX. A imagem base e um Debian slim: nao tem python, e
# depender de um interpretador que nao esta instalado faz o container entrar em
# ciclo de reinicio a dizer "not found", que foi exactamente o que aconteceu na
# primeira versao deste ficheiro.
set -e

GESTOR="${WAZUH_MANAGER:-wazuh-manager}"
NOME="${WAZUH_AGENT_NAME:-$(hostname)}"
CONFIG="/var/ossec/etc/ossec.conf"

sed -i "s|<address>.*</address>|<address>${GESTOR}</address>|" "$CONFIG"

# O agente vigia a pasta **dele**, nao a do gestor.
#
# Se ambos vigiassem o mesmo ficheiro, cada linha de log produziria dois
# alertas — um por colector — e a plataforma mostraria tudo em duplicado. Nao
# seria um problema da plataforma: seria uma configuracao de Wazuh errada.
mkdir -p /var/log/lab/agente
touch /var/log/lab/agente/auth.log /var/log/lab/agente/web.log

if ! grep -q "/var/log/lab/agente/auth.log" "$CONFIG"; then
  # Acrescenta-se um bloco `<ossec_config>` novo no fim, em vez de abrir o que
  # ja la esta.
  #
  # O ossec.conf do agente traz **dois** blocos `<ossec_config>`, e a primeira
  # versao disto removia os fechos todos com `grep -v` para poder inserir antes
  # do ultimo. O resultado eram duas aberturas e um fecho: XML invalido, e o
  # `agent-auth` a recusar-se a arrancar com "Error reading XML file (line 0)".
  #
  # O Wazuh aceita varios blocos e concatena-os, pelo que acrescentar e mais
  # simples e nao mexe no que o pacote instalou.
  cat >> "$CONFIG" <<'FIM'

<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/lab/agente/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/lab/agente/web.log</location>
  </localfile>
</ossec_config>
FIM
  echo "Registos do laboratorio acrescentados a configuracao do agente."
fi

# `-F 1` substitui um agente ja registado com o mesmo nome.
#
# Sem isto, o gestor recusa com "Duplicate agent name" sempre que o contentor e
# recriado — e o laboratorio e para ser levantado e derrubado a vontade. Num
# ambiente real nao se usaria: la, dois agentes com o mesmo nome sao um erro de
# inventario que deve ser visto, nao resolvido em silencio.
echo "A registar o agente '${NOME}' no gestor '${GESTOR}'..."
until /var/ossec/bin/agent-auth -m "${GESTOR}" -A "${NOME}" -F 1 2>&1 | tee /tmp/registo.log | grep -q "Valid key"; do
  echo "  o gestor ainda nao aceita registos; nova tentativa em 10s"
  sleep 10
done

/var/ossec/bin/wazuh-control start
echo "Agente '${NOME}' ligado a '${GESTOR}', a vigiar /var/log/lab/agente/."

# Mantem o container vivo e mostra o log do agente, que e onde se ve se a
# ligacao ao gestor caiu.
touch /var/ossec/logs/ossec.log
exec tail -f /var/ossec/logs/ossec.log
