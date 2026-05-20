"""
Module Telegram — toutes les interactions avec l'API Bot Telegram.
Utilise requests + tenacity pour les retries.
Jamais de token écrit en dur ici.
"""

import sqlite3
import time
from typing import Optional

import requests
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app import config, database as db
from app.logger import log
from app.models import Severity


#  Client de base 

_BASE_URL = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}"

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": config.HTTP_USER_AGENT})
if config.PROXIES:
    _SESSION.proxies.update(config.PROXIES)


def _api(method: str, **params) -> dict:
    url = f"{_BASE_URL}/{method}"
    try:
        resp = _SESSION.post(url, json=params, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("ok"):
            raise RuntimeError(f"Telegram API error: {data.get('description')}")
        return data
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 429:
            retry_after = int(exc.response.headers.get("Retry-After", 5))
            log.warning("Rate limit Telegram — attente %s s", retry_after)
            time.sleep(retry_after)
            raise
        raise


#  Envoi de messages 

@retry(
    retry=retry_if_exception_type((requests.exceptions.ConnectionError,
                                   requests.exceptions.Timeout,
                                   RuntimeError)),
    stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
    wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=2, max=30),
    reraise=True,
)
def send_message(text: str, chat_id: Optional[str] = None, parse_mode: str = "HTML") -> Optional[int]:
    """
    Envoie un message Telegram.
    Retourne le message_id si succès, None si chat_id absent.
    """
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        log.warning("TELEGRAM_CHAT_ID absent — message non envoyé.")
        return None

    # Telegram limite à 4096 caractères
    if len(text) > 4096:
        text = text[:4090] + "\n…"

    data = _api("sendMessage", chat_id=cid, text=text, parse_mode=parse_mode)
    msg_id = data.get("result", {}).get("message_id")
    log.debug("Message envoyé (id=%s) à chat_id=%s", msg_id, cid)
    return msg_id


#  Formatage des alertes 

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH:     "🔴",
    Severity.MEDIUM:   "🟠",
    Severity.INFO:     "🔵",
}

_SEVERITY_LABEL = {
    Severity.CRITICAL: "ALERTE CYBER CRITIQUE",
    Severity.HIGH:     "ALERTE CYBER ÉLEVÉE",
    Severity.MEDIUM:   "ALERTE CYBER MODÉRÉE",
    Severity.INFO:     "INFO CYBER",
}


def _bool_fr(value: bool) -> str:
    return "Oui" if value else "Non"


def _format_alert(row: sqlite3.Row) -> str:
    """Génère le message Telegram formaté HTML pour un item."""
    import json

    severity = row["severity"]
    emoji = _SEVERITY_EMOJI.get(severity, "⚠️")
    label = _SEVERITY_LABEL.get(severity, "ALERTE")

    lines = [f"{emoji} <b>{label}</b>\n"]

    if row["external_id"]:
        lines.append(f"🔖 <b>CVE :</b> <code>{row['external_id']}</code>")

    if row["product"]:
        lines.append(f"📦 <b>Produit :</b> {row['product']}")
    if row["vendor"]:
        lines.append(f"🏢 <b>Éditeur :</b> {row['vendor']}")

    if row["cvss_score"] is not None:
        lines.append(f"📊 <b>Score CVSS :</b> {row['cvss_score']:.1f}")

    lines.append(f"💥 <b>Exploitation active :</b> {_bool_fr(bool(row['is_actively_exploited']))}")
    lines.append(f"🗂 <b>CISA KEV :</b> {_bool_fr(bool(row['is_kev']))}")
    lines.append(f"🧨 <b>Exploit public :</b> {_bool_fr(bool(row['has_public_exploit']))}")

    # Type de vulnérabilité
    vuln_types = []
    if row["is_rce"]:
        vuln_types.append("RCE")
    if row["is_auth_bypass"]:
        vuln_types.append("Auth Bypass")
    if row["is_privilege_escalation"]:
        vuln_types.append("Privilege Escalation")
    if row["mentions_ransomware"]:
        vuln_types.append("Ransomware")
    if vuln_types:
        lines.append(f"🔧 <b>Type :</b> {' / '.join(vuln_types)}")

    # Résumé
    summary = (row["summary"] or "").strip()
    if summary:
        lines.append(f"\n📝 <b>Résumé :</b>\n{summary[:600]}")

    # Recommandations
    lines.append("\n✅ <b>Actions recommandées :</b>")
    lines.append("1. Vérifier si le produit est utilisé dans votre périmètre.")
    if row["patch_available"]:
        lines.append("2. Appliquer le correctif de sécurité disponible.")
    else:
        lines.append("2. ⚠️ Aucun correctif disponible — appliquer des mesures de contournement.")
    lines.append("3. Réduire l'exposition Internet du service concerné.")
    lines.append("4. Surveiller les logs et les accès suspects.")
    lines.append("5. Ajouter des règles de détection (IDS/SIEM) si possible.")

    # Sources
    urls = []
    if row["url"]:
        urls.append(row["url"])
    try:
        extra = json.loads(row["extra_urls"] or "[]")
        urls.extend(extra)
    except Exception:
        pass

    if urls:
        lines.append("\n🔗 <b>Sources :</b>")
        for u in urls[:3]:
            lines.append(f"• {u}")

    return "\n".join(lines)


def send_critical_alert(row: sqlite3.Row, chat_id: Optional[str] = None) -> Optional[int]:
    """Envoie une alerte formatée et enregistre l'envoi en base."""
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        log.warning("Chat ID absent — alerte non envoyée pour item_id=%s", row["id"])
        return None

    if db.alert_already_sent(row["id"], cid):
        log.debug("Alerte déjà envoyée pour item_id=%s", row["id"])
        return None

    text = _format_alert(row)
    try:
        msg_id = send_message(text, chat_id=cid)
        if msg_id:
            db.mark_alert_sent(row["id"], cid, msg_id)
        return msg_id
    except Exception as exc:
        log.error("Échec envoi alerte item_id=%s : %s", row["id"], exc)
        return None


#  Résumés 

def send_daily_summary(stats: dict, chat_id: Optional[str] = None) -> None:
    from datetime import datetime
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        return

    total = stats.get("total", 0)
    by_sev = stats.get("by_severity", {})
    kev = stats.get("kev_count", 0)
    exploit = stats.get("exploit_count", 0)

    lines = [
        f"📋 <b>Résumé quotidien — {datetime.utcnow().strftime('%d/%m/%Y')}</b>\n",
        f"📊 <b>Total items collectés :</b> {total}",
        f"🚨 Critiques : {by_sev.get('CRITICAL', 0)}",
        f"🔴 Élevés : {by_sev.get('HIGH', 0)}",
        f"🟠 Modérés : {by_sev.get('MEDIUM', 0)}",
        f"🔵 Infos : {by_sev.get('INFO', 0)}",
        f"\n🗂 <b>CISA KEV :</b> {kev} nouvelles entrées",
        f"🧨 <b>Exploits publics :</b> {exploit}",
        "\n🤖 <i>Bot de veille cybersécurité — cyber-news-bot</i>",
    ]
    try:
        send_message("\n".join(lines), chat_id=cid)
    except Exception as exc:
        log.error("Échec envoi résumé quotidien : %s", exc)


def send_weekly_summary(stats: dict, top_items: list, chat_id: Optional[str] = None) -> None:
    from datetime import datetime
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        return

    total = stats.get("total", 0)
    by_sev = stats.get("by_severity", {})

    lines = [
        f"📅 <b>Résumé hebdomadaire — semaine du {datetime.utcnow().strftime('%d/%m/%Y')}</b>\n",
        f"📊 <b>Total :</b> {total} items | "
        f"🚨 {by_sev.get('CRITICAL', 0)} critiques | "
        f"🔴 {by_sev.get('HIGH', 0)} élevés",
        "",
        "<b>Top menaces de la semaine :</b>",
    ]
    for i, row in enumerate(top_items[:5], 1):
        cve = f"[{row['external_id']}] " if row["external_id"] else ""
        lines.append(f"{i}. {cve}{row['title'][:80]}")

    lines.append("\n🤖 <i>Bot de veille cybersécurité — cyber-news-bot</i>")
    try:
        send_message("\n".join(lines), chat_id=cid)
    except Exception as exc:
        log.error("Échec envoi résumé hebdomadaire : %s", exc)


#  Détection du chat_id 

def get_chat_id_from_updates() -> list[dict]:
    """
    Appelle getUpdates et retourne la liste des chats détectés.
    Affiche aussi dans les logs.
    """
    try:
        data = _api("getUpdates", limit=100, timeout=10)
    except Exception as exc:
        log.error("Impossible de récupérer getUpdates : %s", exc)
        return []

    results = data.get("result", [])
    chats: dict[int, dict] = {}

    for update in results:
        msg = update.get("message") or update.get("channel_post") or {}
        chat = msg.get("chat", {})
        if not chat:
            continue
        chat_id = chat.get("id")
        if chat_id:
            name = (
                chat.get("title")
                or f"{chat.get('first_name','')} {chat.get('last_name','')}".strip()
                or chat.get("username", "inconnu")
            )
            chats[chat_id] = {"id": chat_id, "name": name, "type": chat.get("type")}

    found = list(chats.values())
    if found:
        log.info("=== Chat IDs détectés ===")
        for c in found:
            log.info("  chat_id=%s  nom=%s  type=%s", c["id"], c["name"], c["type"])
        log.info("Ajoutez TELEGRAM_CHAT_ID=<id> dans votre .env")
    else:
        log.warning(
            "Aucun chat trouvé. Envoyez un message /start au bot puis relancez --get-chat-id."
        )
    return found


#  Commandes bot 

def handle_commands(chat_id: Optional[str] = None) -> None:
    """
    Lit les nouvelles mises à jour et répond aux commandes /start et /id.
    À appeler périodiquement si le bot doit répondre aux commandes.
    """
    try:
        data = _api("getUpdates", limit=50, timeout=5)
    except Exception as exc:
        log.debug("getUpdates impossible : %s", exc)
        return

    for update in data.get("result", []):
        msg = update.get("message", {})
        text = msg.get("text", "")
        cid = msg.get("chat", {}).get("id")
        if not cid or not text:
            continue
        if text.startswith("/start") or text.startswith("/id"):
            _reply_id(cid)

    # Acknowledge updates pour ne pas les retraiter (offset)
    # Pour un bot simple sans polling permanent, on ne gère pas l'offset ici.


def _reply_id(chat_id: int) -> None:
    msg = (
        f"👋 Bonjour ! Voici votre <b>chat_id</b> :\n\n"
        f"<code>{chat_id}</code>\n\n"
        f"Ajoutez cette valeur dans votre fichier <code>.env</code> :\n"
        f"<code>TELEGRAM_CHAT_ID={chat_id}</code>"
    )
    try:
        send_message(msg, chat_id=str(chat_id))
    except Exception as exc:
        log.error("Impossible de répondre au chat %s : %s", chat_id, exc)


#  Test 

def test_notification(chat_id: Optional[str] = None) -> bool:
    """Envoie un message de test. Retourne True si succès."""
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        log.error("TELEGRAM_CHAT_ID absent dans .env — impossible d'envoyer un test.")
        return False
    try:
        send_message(
            "✅ <b>Test de notification — cyber-news-bot</b>\n"
            "Le bot Telegram fonctionne correctement.",
            chat_id=cid,
        )
        log.info("Message de test envoyé avec succès au chat %s", cid)
        return True
    except Exception as exc:
        log.error("Échec du test de notification : %s", exc)
        return False
