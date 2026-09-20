#!/usr/bin/env bash
# Ataques contra o alvo do laboratório, para exercitar o sensor Suricata (§26).
#
#   ./lab/atacar-suricata.sh reconhecimento   scan de portas + fingerprint web
#   ./lab/atacar-suricata.sh exploracao        traversal, SQLi, ficheiros expostos
#   ./lab/atacar-suricata.sh forca-bruta       tentativas repetidas de acesso
#   ./lab/atacar-suricata.sh tudo              os três, com pausas
#
# **Isto é uma conveniência, não a máquina Kali.** O laboratório está desenhado
# para receber ataques de uma VM Kali a sério (ver lab/README.md); este script
# reproduz os mesmos padrões a partir de contentores efémeros, para que a cadeia
# se possa demonstrar e verificar sem depender de uma VM externa. As ferramentas
# são reais (nmap, e os User-Agents e cargas que sqlmap/nikto/hydra enviam); o
# que muda face à Kali é só de onde partem.
#
# O tráfego vai para o alvo pela rede interna do laboratório, o que preserva o
# IP de origem. Uma VM Kali a atacar `host:8080` chega NATeada — as assinaturas
# disparam à mesma, mas o IP de origem aparece como o do gateway (ver README).
set -u

export MSYS_NO_PATHCONV=1

REDE="${REDE:-sheisa-lab_default}"
SERVICO_ALVO="sheisa-lab-alvo"

# O IP do alvo na rede do laboratório. Atacar o IP interno (e não host:8080)
# mantém o endereço de origem real, que é o que se quer ver na plataforma.
ALVO="$(docker inspect "$SERVICO_ALVO" \
  --format "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" 2>/dev/null)"

if [ -z "$ALVO" ]; then
  echo "ERRO: o alvo '$SERVICO_ALVO' não está a correr." >&2
  echo "Arranque o laboratório primeiro:" >&2
  echo "  docker compose -f lab/docker-compose.lab.yml up -d" >&2
  exit 1
fi

echo "Alvo: $ALVO (rede $REDE)"

# curl a partir de um contentor na rede do laboratório.
atacar_web() {
  docker run --rm --network "$REDE" curlimages/curl:latest sh -c "$1" >/dev/null 2>&1 || true
}

reconhecimento() {
  echo "== reconhecimento =="
  echo "  scan de portas (nmap)..."
  # -sT: connect scan; -T4: rápido; --top-ports: as mais comuns. É o que um
  # atacante faz primeiro — e o que dispara as regras de scan.
  docker run --rm --network "$REDE" instrumentisto/nmap:latest \
    -sT -T4 --top-ports 100 "$ALVO" >/dev/null 2>&1 || true
  echo "  fingerprint web (User-Agents de nikto e nmap NSE)..."
  atacar_web "
    curl -s -o /dev/null -A 'Nikto/2.5.0 (Evasions:None)' http://$ALVO/;
    curl -s -o /dev/null -A 'Mozilla/5.0 (compatible; Nmap Scripting Engine)' http://$ALVO/robots.txt;
    curl -s -o /dev/null -A 'gobuster/3.6' http://$ALVO/admin;
    curl -s -o /dev/null -A 'gobuster/3.6' http://$ALVO/backup;
  "
  echo "  feito."
}

exploracao() {
  echo "== exploração =="
  atacar_web "
    curl -s -o /dev/null 'http://$ALVO/../../../../etc/passwd';
    curl -s -o /dev/null 'http://$ALVO/index.php?file=../../../../etc/passwd';
    curl -s -o /dev/null -A 'sqlmap/1.8#stable' \"http://$ALVO/api/clientes?id=1' OR '1'='1\";
    curl -s -o /dev/null -A 'sqlmap/1.8#stable' \"http://$ALVO/api/clientes?id=1 UNION SELECT username,password FROM utilizadores\";
    curl -s -o /dev/null 'http://$ALVO/.env';
    curl -s -o /dev/null 'http://$ALVO/.git/config';
    curl -s -o /dev/null 'http://$ALVO/wp-login.php';
  "
  echo "  cargas de traversal, SQLi e acesso a ficheiros sensíveis enviadas."
}

forca_bruta() {
  echo "== força bruta de autenticação =="
  # 25 tentativas de Basic Auth em sequência: o padrão de hydra contra um realm
  # protegido, que dispara a regra local de contagem.
  atacar_web "
    for i in \$(seq 1 25); do
      curl -s -o /dev/null -u \"admin:senha\$i\" -A 'Mozilla/5.0 (hydra)' http://$ALVO/admin;
    done
  "
  echo "  25 tentativas enviadas."
}

case "${1:-tudo}" in
  reconhecimento) reconhecimento ;;
  exploracao)     exploracao ;;
  forca-bruta)    forca_bruta ;;
  tudo)
    reconhecimento; sleep 2
    exploracao; sleep 2
    forca_bruta
    ;;
  *)
    echo "Uso: $0 {reconhecimento|exploracao|forca-bruta|tudo}" >&2
    exit 2
    ;;
esac

echo
echo "O integrador entrega em segundos. Para acompanhar:"
echo "  docker exec sheisa-lab-suricata tail -f /var/log/suricata/fast.log"
echo "  docker logs -f sheisa-lab-suricata-integrador"
echo
echo "E na plataforma: http://127.0.0.1:5500/alertas  (filtrar por fonte Suricata)"
