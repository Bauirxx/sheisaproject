# Agente Wazuh para o laboratorio (§26).
#
# Nao existe imagem oficial `wazuh/wazuh-agent`, pelo que o agente e instalado
# a partir do repositorio de pacotes da Wazuh sobre um Debian slim. E o mesmo
# procedimento que se faria num servidor real, o que torna o laboratorio
# representativo em vez de um atalho.
FROM debian:12-slim

ARG WAZUH_VERSION=4.12.0-1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl ca-certificates gnupg2 procps \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
 && chmod 644 /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && WAZUH_MANAGER="wazuh-manager" apt-get install -y "wazuh-agent=${WAZUH_VERSION}" \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY entrada.sh /entrada.sh
RUN chmod +x /entrada.sh

ENTRYPOINT ["/entrada.sh"]
