#!/bin/bash
# ============================================================================
# AgentGuard Deployment Script v6.0 (Production-Ready + Rollback)
# ============================================================================
# Usage:
#   ./deploy.sh              # Déploiement standard (rollback auto si échec)
#   ./deploy.sh --no-backup  # Sans backup DB
#   ./deploy.sh --dry-run    # Simulation uniquement
#   ./deploy.sh rollback     # Rollback manuel vers le dernier état sain
# ============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_NAME="agentguard"
readonly HEALTH_TIMEOUT=60      # secondes max pour health check
readonly HEALTH_RETRY_INTERVAL=3
readonly BACKUP_DIR="${SCRIPT_DIR}/backups"
readonly STATE_FILE="${BACKUP_DIR}/last_good_image.txt"   # image ID du dernier état sain
readonly ROLLBACK_TAG="agentguard-rollback:previous"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Flags
DRY_RUN=false
NO_BACKUP=false
IN_DEPLOY=false   # true pendant la fenêtre critique build->health check

# ── Fonctions utilitaires ─────────────────────────────────────────────────────
log() { echo -e "${BLUE}[INFO]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC}   $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC}  $*" >&2; }
die() { err "$*"; exit 1; }

usage() {
    cat <<EOF
AgentGuard Deployment Script

Usage: $0 [OPTIONS|rollback]

Options:
  rollback       Restore le dernier déploiement sain connu
  --no-backup    Skip database backup before deployment
  --dry-run      Simulate deployment without making changes
  -h, --help     Show this help

Examples:
  $0                    # Deploy avec backup + rollback auto si échec
  $0 --no-backup        # Quick deploy sans backup DB
  $0 --dry-run          # Show what would be done
  $0 rollback           # Rollback manuel vers le dernier état sain
EOF
    exit 0
}

# ── Parse arguments ───────────────────────────────────────────────────────────
MODE="deploy"
while [[ $# -gt 0 ]]; do
    case $1 in
        rollback)    MODE="rollback"; shift ;;
        --no-backup) NO_BACKUP=true; shift ;;
        --dry-run)   DRY_RUN=true; shift ;;
        -h|--help)   usage ;;
        *)           die "Option inconnue: $1 (voir --help)" ;;
    esac
done

# ── Vérification des prérequis ────────────────────────────────────────────────
check_prereqs() {
    log "Vérification des prérequis..."
    local missing=()
    
    command -v docker >/dev/null || missing+=("docker")
    command -v python3 >/dev/null || missing+=("python3")
    
    # Vérifie docker compose (v2 plugin) ou docker-compose (v1 standalone)
    if ! docker compose version >/dev/null 2>&1; then
        if ! command -v docker-compose >/dev/null; then
            missing+=("docker compose")
        fi
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Outils manquants: ${missing[*]}"
    fi
    
    # Vérifie que docker daemon tourne
    if ! docker info >/dev/null 2>&1; then
        die "Le daemon Docker n'est pas accessible"
    fi
    
    ok "Prérequis OK"
}

# ── Chargement et validation du .env ──────────────────────────────────────────
load_env() {
    log "Chargement de l'environnement..."
    
    if [[ ! -f "${SCRIPT_DIR}/.env" ]]; then
        if [[ -f "${SCRIPT_DIR}/env.example" ]]; then
            warn ".env manquant — copie de env.example"
            cp "${SCRIPT_DIR}/env.example" "${SCRIPT_DIR}/.env"
            die "Configure ${SCRIPT_DIR}/.env puis relance le script"
        else
            die "Fichier .env introuvable"
        fi
    fi
    
    # Charge .env
    set -a
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env"
    set +a
    
    # Validation des variables critiques
    local errors=0
    
    if [[ -z "${AGENTGUARD_API_KEY:-}" ]]; then
        err "AGENTGUARD_API_KEY non définie dans .env"
        err "Génère-la avec : python3 -c \"import secrets; print('ag-' + secrets.token_urlsafe(32))\""
        errors=1
    fi
    
    if [[ -z "${AGENTGUARD_FLASK_SECRET:-}" ]]; then
        warn "AGENTGUARD_FLASK_SECRET non définie — sessions invalidées à chaque restart"
    fi
    
    if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
        warn "POSTGRES_PASSWORD non définie — utilise une valeur par défaut non sécurisée"
    fi
    
    if [[ "${AGENTGUARD_DB_TYPE:-sqlite}" == "postgres" && -z "${DATABASE_URL:-}" ]]; then
        err "DB_TYPE=postgres mais DATABASE_URL non défini"
        errors=1
    fi
    
    [[ $errors -eq 1 ]] && die "Variables d'environnement invalides"
    
    ok "Environnement chargé"
}

# ── Backup DB ─────────────────────────────────────────────────────────────────
backup_database() {
    if [[ "$NO_BACKUP" == "true" ]]; then
        warn "Backup ignoré (--no-backup)"
        return
    fi
    
    if [[ "${AGENTGUARD_DB_TYPE:-sqlite}" != "postgres" ]]; then
        log "DB SQLite — backup via volume (pas de dump nécessaire)"
        return
    fi
    
    log "Backup de la base PostgreSQL..."
    mkdir -p "$BACKUP_DIR"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${BACKUP_DIR}/agentguard_${timestamp}.sql.gz"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Commande qui serait exécutée :"
        log "  docker compose exec -T postgres pg_dump -U agentguard agentguard | gzip > ${backup_file}"
        return
    fi
    
    # Attend que postgres soit up
    if ! docker compose ps postgres | grep -q "Up"; then
        warn "Postgres pas encore up — premier déploiement ?"
        return
    fi
    
    if docker compose exec -T postgres pg_dump -U "${POSTGRES_USER:-agentguard}" "${POSTGRES_DB:-agentguard}" \
        | gzip > "$backup_file"; then
        ok "Backup créé: ${backup_file} ($(du -h "$backup_file" | cut -f1))"
        
        # Nettoyage des anciens backups (garde les 10 derniers)
        (cd "$BACKUP_DIR" && ls -t agentguard_*.sql.gz 2>/dev/null | tail -n +11 | xargs -r rm -f)
    else
        warn "Backup échoué — déploiement continue quand même"
        rm -f "$backup_file"
    fi
}

# ── Snapshot de l'image courante (prérequis du rollback) ───────────────────────
snapshot_current_image() {
    mkdir -p "$BACKUP_DIR"
    
    local current_image
    current_image=$(docker compose images -q collector 2>/dev/null || true)
    
    if [[ -z "$current_image" ]]; then
        warn "Aucune image existante pour 'collector' — premier déploiement, pas de rollback possible"
        return
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Snapshot de l'image courante: ${current_image:0:12}"
        return
    fi
    
    # On tagge l'image courante ET on sauve son ID dans le state file.
    # docker compose up recrée le conteneur depuis l'image du tag, pas
    # depuis un ID orphelin -> on utilise le tag pour le rollback.
    if docker tag "$current_image" "$ROLLBACK_TAG" 2>/dev/null; then
        echo "$current_image" > "$STATE_FILE"
        ok "Snapshot rollback: ${current_image:0:12} (tag ${ROLLBACK_TAG})"
    else
        warn "Impossible de tagger l'image courante — rollback indisponible pour ce déploiement"
    fi
}

# ── Rollback ──────────────────────────────────────────────────────────────────
do_rollback() {
    echo -e "${YELLOW}🔄 ROLLBACK vers le dernier état sain connu...${NC}"
    
    if [[ ! -f "$STATE_FILE" ]]; then
        die "Aucun état sain connu (${STATE_FILE} introuvable) — impossible de rollback"
    fi
    
    local good_image
    good_image=$(cat "$STATE_FILE")
    
    if ! docker image inspect "$good_image" >/dev/null 2>&1; then
        die "L'image sauvegardée (${good_image:0:12}) n'existe plus localement — rollback impossible"
    fi
    
    log "Restauration de l'image ${good_image:0:12}..."
    
    # docker compose up recrée le conteneur depuis le tag de rollback.
    # On force compose à utiliser le tag rollback via le service tagué.
    docker tag "$good_image" "$ROLLBACK_TAG"
    docker tag "$ROLLBACK_TAG" "${PROJECT_NAME}-collector:latest" 2>/dev/null || true
    
    docker compose up -d --no-build
    
    # Re-vérifie la santé après rollback
    if wait_for_health_quiet; then
        ok "Rollback terminé — service de nouveau sain sur l'image ${good_image:0:12}"
    else
        err "Le service n'est toujours pas sain après rollback"
        err "Logs du conteneur :"
        docker compose logs --tail=50 collector || true
        die "Rollback incomplet — intervention manuelle requise"
    fi
}

# ── Build & Deploy ────────────────────────────────────────────────────────────
deploy() {
    log "Build de l'image Docker..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] docker compose build"
    else
        docker compose build
        ok "Image buildée"
    fi
    
    log "Démarrage des services..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] docker compose up -d"
        return
    fi
    
    docker compose up -d
    ok "Services démarrés"
}

# ── Health Check avec retry ───────────────────────────────────────────────────
# Retourne 0 si sain, 1 sinon. N'appelle PAS die (utilisé par le rollback).
_health_loop() {
    local quiet="${1:-false}"
    
    log "Attente du health check (max ${HEALTH_TIMEOUT}s)..."
    local start=$SECONDS
    local attempt=0
    
    while (( SECONDS - start < HEALTH_TIMEOUT )); do
        attempt=$((attempt + 1))
        
        # Check Docker health status
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' "${PROJECT_NAME}-collector-1" 2>/dev/null || echo "unknown")
        
        if [[ "$health" == "healthy" ]]; then
            [[ "$quiet" == "true" ]] || ok "Service healthy après ${attempt} tentatives ($((SECONDS - start))s)"
            return 0
        fi
        
        # Check HTTP health si pas de healthcheck docker
        if [[ "$health" == "unknown" ]]; then
            if curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; then
                [[ "$quiet" == "true" ]] || ok "Service répond après ${attempt} tentatives ($((SECONDS - start))s)"
                return 0
            fi
        fi
        
        printf "."
        sleep "$HEALTH_RETRY_INTERVAL"
    done
    
    echo ""
    return 1
}

wait_for_health() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Attente health check... (considéré OK)"
        return 0
    fi
    
    if ! _health_loop false; then
        err "Timeout: le service n'est pas healthy après ${HEALTH_TIMEOUT}s"
        err "Logs du conteneur :"
        docker compose logs --tail=50 collector || true
        
        # ── ROLLBACK AUTOMATIQUE ──
        if [[ -f "$STATE_FILE" ]]; then
            err "Déclenchement du ROLLBACK AUTOMATIQUE..."
            do_rollback
            die "Déploiement échoué — rollback effectué vers le dernier état sain" 2
        else
            die "Déploiement échoué — aucun état sain connu pour rollback (premier déploiement ?)"
        fi
    fi
    
    # Déploiement sain : on enregistre l'image nouvelle comme référence
    local new_image
    new_image=$(docker compose images -q collector 2>/dev/null || true)
    if [[ -n "$new_image" ]]; then
        echo "$new_image" > "$STATE_FILE"
        ok "Nouvel état sain enregistré (${new_image:0:12}) — référence de rollback mise à jour"
    fi
}

wait_for_health_quiet() {
    _health_loop true
}

# ── Post-deploy ───────────────────────────────────────────────────────────────
post_deploy() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Déploiement AgentGuard terminé avec succès !${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "🌐 ${GREEN}Dashboard${NC}:  http://localhost:8080"
    echo -e "   → Utilise ta clé API (${YELLOW}AGENTGUARD_API_KEY${NC}) pour te connecter"
    echo -e "   → ${RED}Ne mets JAMAIS la clé dans l'URL${NC} (fuite dans les logs)"
    echo ""
    echo -e "📡 ${GREEN}Health${NC}:    http://localhost:8080/healthz"
    echo -e "📚 ${GREEN}Logs${NC}:      docker compose logs -f"
    echo -e "🛑 ${GREEN}Stop${NC}:      docker compose down"
    echo -e "🔄 ${GREEN}Restart${NC}:   docker compose restart"
    echo -e "⏪ ${GREEN}Rollback${NC}:  $0 rollback"
    echo ""
    
    # Affiche un résumé des services
    echo -e "${CYAN}Statut des services :${NC}"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null \
        || docker compose ps
}

# ── Trap : rollback si on est en pleine fenêtre critique ──────────────────────
on_error() {
    local exit_code=$?
    err "Déploiement interrompu (exit ${exit_code})"
    if [[ "$IN_DEPLOY" == "true" && "$DRY_RUN" != "true" && -f "$STATE_FILE" ]]; then
        err "Fenêtre critique — tentative de ROLLBACK..."
        do_rollback || err "Rollback échoué — intervention manuelle requise"
        exit 2
    fi
    docker compose ps 2>/dev/null || true
    exit "$exit_code"
}
trap on_error ERR

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║ 🛡️  cerbere-AgentGuard Deployment Script v6.0 (rollback)  ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    cd "$SCRIPT_DIR"
    
    check_prereqs
    load_env
    
    if [[ "$MODE" == "rollback" ]]; then
        do_rollback
        post_deploy
        exit 0
    fi
    
    backup_database
    snapshot_current_image
    IN_DEPLOY=true
    deploy
    wait_for_health
    IN_DEPLOY=false
    post_deploy
}

main "$@"