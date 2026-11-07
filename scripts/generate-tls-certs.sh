#!/bin/bash
# Script de génération de certificats auto-signés pour le chiffrement PostgreSQL local
# Usage: ./scripts/generate-tls-certs.sh

set -e

CERTS_DIR="certs"
echo "🔒 Génération des certificats TLS dans le dossier '$CERTS_DIR'..."

mkdir -p "$CERTS_DIR"

# 1. Générer une clé privée et un certificat auto-signé (valide 1 an)
# Le CN (Common Name) doit correspondre au nom d'hôte utilisé dans DATABASE_URL ('postgres')
openssl req -new -x509 -days 365 -nodes -text \
    -out "$CERTS_DIR/server.crt" \
    -keyout "$CERTS_DIR/server.key" \
    -subj "/CN=postgres/O=AgentGuard/C=FR"

# 2. Sécuriser les permissions de la clé privée (PostgreSQL refuse de démarrer si la clé est lisible par tous)
chmod 600 "$CERTS_DIR/server.key"

# 3. Copier le certificat public pour qu'il serve de CA de confiance pour le client (collector)
cp "$CERTS_DIR/server.crt" "$CERTS_DIR/ca.crt"

echo "✅ Certificats générés avec succès !"
echo "   - Certificat serveur : $CERTS_DIR/server.crt"
echo "   - Clé privée         : $CERTS_DIR/server.key (permissions 600)"
echo "   - CA de confiance    : $CERTS_DIR/ca.crt"
echo ""
echo "💡 Avec Docker Compose, ce script n'est plus nécessaire : docker-compose.tls.yml génère les certificats au premier démarrage."
echo "   Utilisez-le seulement pour un PostgreSQL hors Docker (sslmode=verify-full&sslrootcert=<chemin>/ca.crt dans DATABASE_URL)."
