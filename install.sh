#!/usr/bin/env bash
# ============================================================================
# install.sh — cyber-news-bot v2
# Usage : sudo bash install.sh
# Workflow : git clone <repo> quelque_part && cd quelque_part && sudo bash install.sh
# ============================================================================
set -euo pipefail

BOT_USER="alx-ops"
BOT_GROUP="alx-ops"
INSTALL_DIR="/opt/cyber-news-bot"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_NAME="cyber-news-bot"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ "$EUID" -ne 0 ]] && err "Lancez en root : sudo bash install.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Python ──────────────────────────────────────────────────────────────────
log "Recherche de Python 3.11+..."
PYTHON_BIN=""
for bin in python3.13 python3.12 python3.11; do
    command -v "$bin" &>/dev/null && { PYTHON_BIN="$bin"; break; }
done

if [[ -z "$PYTHON_BIN" ]]; then
    log "Installation de Python 3.11..."
    apt-get update -qq
    apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
    PYTHON_BIN="python3.11"
fi
log "Python : $PYTHON_BIN ($("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'))"

# ── Dépendances système ──────────────────────────────────────────────────────
log "Dépendances système..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl git sqlite3 libxml2-dev libxslt1-dev \
    build-essential ca-certificates openssl

# ── Utilisateur service ──────────────────────────────────────────────────────
if ! id "$BOT_USER" &>/dev/null; then
    log "Création de l'utilisateur ${BOT_USER}..."
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --comment "Cyber News Bot" "$BOT_USER"
else
    log "Utilisateur ${BOT_USER} existe déjà."
fi

# ── Dossiers ─────────────────────────────────────────────────────────────────
log "Structure ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"

# ── Copie des fichiers (si on n'est pas déjà dans INSTALL_DIR) ───────────────
if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" ]]; then
    log "Copie depuis ${SCRIPT_DIR} → ${INSTALL_DIR}..."
    rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
          --exclude='.env' --exclude='venv' --exclude='data/*.sqlite' \
          "${SCRIPT_DIR}/" "${INSTALL_DIR}/"
else
    log "Dossier source = INSTALL_DIR — copie ignorée."
fi

# ── Virtualenv Python ────────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    log "Création du virtualenv..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

log "Installation des dépendances Python..."
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet
log "Dépendances Python installées."

# ── Fichier .env ─────────────────────────────────────────────────────────────
if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    log "Création du .env depuis .env.example..."
    cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
    warn "⚠️  Editez ${INSTALL_DIR}/.env avant de démarrer :"
    warn "   TELEGRAM_BOT_TOKEN=..."
    warn "   TELEGRAM_CHAT_ID=..."
else
    log ".env déjà présent — non écrasé."
fi

# ── Permissions ──────────────────────────────────────────────────────────────
log "Permissions..."
chown -R "${BOT_USER}:${BOT_GROUP}" "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 640 "${INSTALL_DIR}/.env"
chmod 750 "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"

# ── Systemd ──────────────────────────────────────────────────────────────────
log "Service systemd ${SERVICE_NAME}..."
cp "${INSTALL_DIR}/cyber-news-bot.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
log "Service activé (démarrage auto au boot)."

# ── Résumé ───────────────────────────────────────────────────────────────────
PYTHON="${VENV_DIR}/bin/python"
MAIN="${INSTALL_DIR}/app/main.py"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✅  Installation terminée — cyber-news-bot v2"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "── Étapes suivantes ──────────────────────────────────────"
echo ""
echo "1) Configurez vos credentials Telegram :"
echo "   nano ${INSTALL_DIR}/.env"
echo "   → TELEGRAM_BOT_TOKEN=..."
echo "   → TELEGRAM_CHAT_ID=..."
echo ""
echo "2) Testez la connexion Telegram :"
echo "   sudo -u ${BOT_USER} ${PYTHON} -m app.main test-telegram"
echo ""
echo "3) Backfill initial (60 jours d'historique) :"
echo "   sudo -u ${BOT_USER} ${PYTHON} -m app.main backfill 60"
echo "   (peut prendre 10-20 min selon le volume NVD)"
echo ""
echo "4) Démarrez le bot :"
echo "   systemctl start ${SERVICE_NAME}"
echo "   systemctl status ${SERVICE_NAME}"
echo ""
echo "5) Logs en direct :"
echo "   journalctl -u ${SERVICE_NAME} -f"
echo "   tail -f ${INSTALL_DIR}/logs/bot.log"
echo ""
echo "── Commandes utiles ──────────────────────────────────────"
echo "   Stats 7j  : sudo -u ${BOT_USER} ${PYTHON} -m app.main stats 7"
echo "   Run once  : sudo -u ${BOT_USER} ${PYTHON} -m app.main run-once"
echo "   Enrich    : sudo -u ${BOT_USER} ${PYTHON} -m app.main enrich 50"
echo ""
