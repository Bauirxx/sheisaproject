#!/usr/bin/env bash
# Copia de seguranca e restauro da base de dados (RNF12).
#
#   ./scripts/backup.sh criar              # grava var/backups/sheisa-<instante>.dump
#   ./scripts/backup.sh listar             # mostra o que existe, com tamanho e data
#   ./scripts/backup.sh verificar <ficheiro>   # confirma que o ficheiro e restauravel
#   ./scripts/backup.sh restaurar <ficheiro>   # substitui a base actual
#
# **Porque nao e um `pg_dump` solto num README.** Uma copia de seguranca que
# nunca foi restaurada nao e uma copia de seguranca: e um ficheiro. Por isso o
# comando `verificar` existe e restaura de facto, para uma base temporaria que
# apaga a seguir -- e o `criar` corre-o automaticamente, de modo que um ficheiro
# ilegivel se descobre no momento em que e escrito e nao no dia em que faz falta.
#
# Usa o formato personalizado (`-Fc`), que e comprimido e permite restauro
# selectivo com `pg_restore`. O `pg_dump` corre **dentro do contentor**, pelo que
# nao e preciso ter o cliente PostgreSQL instalado no anfitriao -- e a versao do
# cliente coincide sempre com a do servidor, o que evita o erro
# "server version mismatch" que aparece quando o host tem uma versao diferente.
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DESTINO="$RAIZ/backend/var/backups"
SERVICO="db"

# As credenciais vivem no .env, nunca no codigo (§23).
if [ -f "$RAIZ/.env" ]; then
  set -a; . "$RAIZ/.env"; set +a
fi
UTILIZADOR="${POSTGRES_USER:-sheisa}"
BASE="${POSTGRES_DB:-sheisa}"

no_contentor() {
  docker compose -f "$RAIZ/docker-compose.yml" exec -T "$SERVICO" "$@"
}

exigir_base_de_pe() {
  if ! no_contentor pg_isready -U "$UTILIZADOR" -d "$BASE" >/dev/null 2>&1; then
    echo "ERRO: a base de dados nao responde. Corra 'docker compose up -d db'." >&2
    exit 1
  fi
}

# Restaura para uma base temporaria e confirma que as tabelas essenciais vieram.
# Contar linhas nao serve: uma base vazia tem zero linhas legitimamente. O que se
# afirma e que a estrutura chegou e que a auditoria trouxe o que tinha.
verificar() {
  local ficheiro="$1"
  [ -f "$ficheiro" ] || { echo "ERRO: $ficheiro nao existe." >&2; exit 1; }
  exigir_base_de_pe

  local temporaria="sheisa_verificacao_$$"
  echo "A restaurar para a base temporaria $temporaria..."
  no_contentor psql -U "$UTILIZADOR" -d postgres -q \
    -c "DROP DATABASE IF EXISTS $temporaria" \
    -c "CREATE DATABASE $temporaria"

  local codigo=0
  # `--no-owner` porque a base temporaria nao tem os mesmos papeis; os avisos de
  # pg_restore nao sao fatais, o que conta e a verificacao que vem a seguir.
  no_contentor pg_restore -U "$UTILIZADOR" -d "$temporaria" --no-owner \
    < "$ficheiro" >/dev/null 2>&1 || codigo=$?

  local tabelas
  tabelas=$(no_contentor psql -U "$UTILIZADOR" -d "$temporaria" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" | tr -d '\r')
  local auditoria
  auditoria=$(no_contentor psql -U "$UTILIZADOR" -d "$temporaria" -tAc \
    "SELECT count(*) FROM audit_logs" 2>/dev/null | tr -d '\r' || echo "ausente")
  local versao
  versao=$(no_contentor psql -U "$UTILIZADOR" -d "$temporaria" -tAc \
    "SELECT version_num FROM alembic_version" 2>/dev/null | tr -d '\r' || echo "ausente")

  no_contentor psql -U "$UTILIZADOR" -d postgres -q \
    -c "DROP DATABASE IF EXISTS $temporaria" >/dev/null

  if [ "${tabelas:-0}" -lt 20 ] || [ "$versao" = "ausente" ]; then
    echo "FALHOU: restauro incompleto (tabelas=$tabelas, migracao=$versao, pg_restore=$codigo)" >&2
    exit 1
  fi
  echo "OK: $tabelas tabelas, migracao $versao, $auditoria registos de auditoria."
}

criar() {
  exigir_base_de_pe
  mkdir -p "$DESTINO"
  local instante ficheiro
  instante="$(date -u +%Y%m%dT%H%M%SZ)"
  ficheiro="$DESTINO/sheisa-$instante.dump"

  echo "A gravar $ficheiro..."
  no_contentor pg_dump -U "$UTILIZADOR" -d "$BASE" -Fc > "$ficheiro"

  local tamanho
  tamanho=$(du -h "$ficheiro" | cut -f1)
  echo "Gravado ($tamanho). A verificar que e restauravel..."
  verificar "$ficheiro"
  echo "Copia de seguranca concluida e verificada: $ficheiro"
}

listar() {
  if [ ! -d "$DESTINO" ] || [ -z "$(ls -A "$DESTINO" 2>/dev/null)" ]; then
    echo "Nao existe nenhuma copia de seguranca em $DESTINO."
    return 0
  fi
  ls -lh "$DESTINO" | tail -n +2
}

# O restauro e destrutivo e por isso pede confirmacao explicita: e a unica
# operacao aqui que pode perder dados, e perde-los sem recurso.
restaurar() {
  local ficheiro="$1"
  [ -f "$ficheiro" ] || { echo "ERRO: $ficheiro nao existe." >&2; exit 1; }
  exigir_base_de_pe

  echo "Isto substitui a base '$BASE' pelo conteudo de $ficheiro."
  echo "Os dados actuais sao perdidos. Escreva 'restaurar' para confirmar:"
  read -r resposta
  [ "$resposta" = "restaurar" ] || { echo "Cancelado."; exit 1; }

  no_contentor psql -U "$UTILIZADOR" -d postgres -q \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$BASE' AND pid <> pg_backend_pid()" \
    -c "DROP DATABASE IF EXISTS $BASE" \
    -c "CREATE DATABASE $BASE"
  no_contentor pg_restore -U "$UTILIZADOR" -d "$BASE" --no-owner < "$ficheiro"
  echo "Restaurado. Reinicie a API: ./scripts/api.sh restart"
}

case "${1:-}" in
  criar)     criar ;;
  listar)    listar ;;
  verificar) verificar "${2:?indique o ficheiro}" ;;
  restaurar) restaurar "${2:?indique o ficheiro}" ;;
  *)
    echo "Uso: $0 {criar|listar|verificar <ficheiro>|restaurar <ficheiro>}" >&2
    exit 2
    ;;
esac
