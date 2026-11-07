#!/usr/bin/env bash
# Crée un fichier .env avec des secrets aléatoires pour une installation self-hosted.
# Usage : ./scripts/selfhost-init.sh
# N'écrase jamais un .env existant.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  echo "Un fichier .env existe déjà : rien n'a été modifié." >&2
  exit 1
fi

rand() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

umask 077
while IFS= read -r line; do
  case "$line" in
    AGENTGUARD_API_KEY=__GENERATE__) echo "AGENTGUARD_API_KEY=ag-$(rand)" ;;
    *=__GENERATE__) echo "${line%%=*}=$(rand)" ;;
    *) echo "$line" ;;
  esac
done < .env.selfhost.example > .env

echo "✅ .env créé (permissions 600)."
echo
echo "Étapes suivantes :"
echo "  1. docker compose up -d --build"
echo "  2. docker compose exec collector python -m collector.cli create-admin --email vous@entreprise.com"
echo "  3. Ouvrir ${AGENTGUARD_PUBLIC_URL:-http://localhost:8080}/login et se connecter avec l'email et le mot de passe choisis"
echo
echo "Chiffrer aussi la liaison PostgreSQL : ajouter  -f docker-compose.yml -f docker-compose.tls.yml  aux commandes docker compose."
