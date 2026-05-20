#!/usr/bin/env bash
# ============================================================================
# install.sh — Installation du bot de veille cybersécurité
# Testé sur Debian 12 / Ubuntu 24.04 LTS
# À lancer en root : sudo bash install.sh
# ============================================================================
set -euo pipefail

#  Variables 
BOT_USER="alx-ops"
BOT_GROUP="alx-ops"
INSTALL_DIR="/opt/cyber-news-bot"
VENV_DIR="${INSTALL_DIR}/venv"
SERVICE_NAME="cyber-news-bot"
PYTHON_MIN="3.11"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

#  Vérification root 
[[ "$EUID" -ne 0 ]] && err "Ce script doit être exécuté en root (sudo bash install.sh)"

#  Vérification Python 
log "Vérification de Python ${PYTHON_MIN}+..."
PYTHON_BIN=""
for bin in python3.13 python3.12 python3.11; do
    if command -v "$bin" &>/dev/null; then
        PYTHON_BIN="$bin"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    log "Installation de Python 3.11 depuis les dépôts..."
    apt-get update -qq
    apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
    PYTHON_BIN="python3.11"
fi

PYTHON_VERSION=$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
log "Python détecté : $PYTHON_BIN (${PYTHON_VERSION})"

#  Dépendances système 
log "Installation des dépendances système..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    curl \
    git \
    sqlite3 \
    libxml2-dev \
    libxslt1-dev \
    build-essential \
    ca-certificates \
    openssl

#  Création de l'utilisateur 
if ! id "$BOT_USER" &>/dev/null; then
    log "Création de l'utilisateur ${BOT_USER}..."
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --comment "Cyber News Bot service account" \
            "$BOT_USER"
else
    log "Utilisateur ${BOT_USER} existe déjà."
fi

#  Structure des dossiers 
log "Création de la structure ${INSTALL_DIR}..."
mkdir -p \
    "${INSTALL_DIR}/app/sources" \
    "${INSTALL_DIR}/app/reports" \
    "${INSTALL_DIR}/data" \
    "${INSTALL_DIR}/logs"

#  Copie des fichiers 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log "Copie des fichiers depuis ${SCRIPT_DIR}..."
rsync -av --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
      --exclude='.env' --exclude='venv' --exclude='data/*.sqlite' \
      "${SCRIPT_DIR}/" "${INSTALL_DIR}/"

#  Environnement virtuel Python 
if [[ ! -d "$VENV_DIR" ]]; then
    log "Création de l'environnement virtuel Python..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

log "Installation des dépendances Python..."
"${VENV_DIR}/bin/pip" install --upgrade pip --quiet
"${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" --quiet

#  Fichier .env 
if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    log "Création du fichier .env depuis .env.example..."
    cp "${INSTALL_DIR}/.env.example" "${INSTALL_DIR}/.env"
    warn "⚠️  IMPORTANT : Éditez ${INSTALL_DIR}/.env et renseignez :"
    warn "   TELEGRAM_BOT_TOKEN=votre_token"
    warn "   TELEGRAM_CHAT_ID=votre_chat_id (après --get-chat-id)"
else
    log "Fichier .env déjà présent — non modifié."
fi

#  Permissions 
log "Application des permissions..."
chown -R "${BOT_USER}:${BOT_GROUP}" "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 640 "${INSTALL_DIR}/.env"
chmod 750 "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"
chmod +x "${INSTALL_DIR}/install.sh" 2>/dev/null || true

#  Service systemd 
log "Installation du service systemd..."
cp "${INSTALL_DIR}/cyber-news-bot.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"

#  Résumé 
echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅  Installation terminée !"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Étapes suivantes :"
echo ""
echo "1. Configurez votre token Telegram :"
echo "   nano ${INSTALL_DIR}/.env"
echo ""
echo "2. Récupérez votre chat_id :"
echo "   sudo -u ${BOT_USER} ${VENV_DIR}/bin/python ${INSTALL_DIR}/app/main.py --get-chat-id"
echo ""
echo "3. Testez la notification :"
echo "   sudo -u ${BOT_USER} ${VENV_DIR}/bin/python ${INSTALL_DIR}/app/main.py --test-telegram"
echo ""
echo "4. Lancez le backfill initial (60 jours) :"
echo "   sudo -u ${BOT_USER} ${VENV_DIR}/bin/python ${INSTALL_DIR}/app/main.py --backfill 60"
echo ""
echo "5. Démarrez le service :"
echo "   systemctl start ${SERVICE_NAME}"
echo "   systemctl status ${SERVICE_NAME}"
echo ""
echo "6. Consultez les logs :"
echo "   tail -f ${INSTALL_DIR}/logs/bot.log"
echo "   journalctl -u ${SERVICE_NAME} -f"
echo ""
