"""
Module Telegram v2.
Formatage enrichi : EPSS, CVSS vector, watchlist badge, sources multiples.
Retry automatique avec tenacity.
"""

from __future__ import annotations

import json
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
from app.sources.epss import epss_label


#  Session HTTP 

_BASE = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}"

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": config.HTTP_USER_AGENT})
if config.PROXIES:
    _SESSION.proxies.update(config.PROXIES)


def _api(method: str, **params) -> dict:
    url = f"{_BASE}/{method}"
    try:
        resp = _SESSION.post(url, json=params, timeout=config.HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if not data.get("ok"):
            raise RuntimeError(f"Telegram API error : {data.get('description')}")
        return data
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 429:
            wait = int(exc.response.headers.get("Retry-After", 5))
            log.warning("Rate limit Telegram — attente %ds", wait)
            time.sleep(wait)
            raise
        raise


#  Envoi 

@retry(
    retry=retry_if_exception_type((
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        RuntimeError,
    )),
    stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
    wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=2, max=30),
    reraise=True,
)
def send_message(
    text: str,
    chat_id: Optional[str] = None,
    parse_mode: str = "HTML",
    disable_web_page_preview: bool = True,
) -> Optional[int]:
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        log.warning("TELEGRAM_CHAT_ID absent — message non envoyé.")
        return None
    if len(text) > 4096:
        text = text[:4090] + "\n…"
    data = _api(
        "sendMessage",
        chat_id=cid,
        text=text,
        parse_mode=parse_mode,
        disable_web_page_preview=disable_web_page_preview,
    )
    return data.get("result", {}).get("message_id")


#  Formatage d'une alerte 

_SEV_EMOJI = {
    "CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "INFO": "🔵",
}
_SEV_LABEL = {
    "CRITICAL": "ALERTE CYBER CRITIQUE",
    "HIGH":     "ALERTE CYBER ÉLEVÉE",
    "MEDIUM":   "ALERTE CYBER MODÉRÉE",
    "INFO":     "INFO CYBER",
}


def _yn(v: int | bool) -> str:
    return "✅ Oui" if v else "Non"


def format_alert(row: sqlite3.Row) -> str:
    sev   = row["severity"]
    emoji = _SEV_EMOJI.get(sev, "⚠️")
    label = _SEV_LABEL.get(sev, "ALERTE")

    lines: list[str] = []

    #  En-tête 
    header = f"{emoji} <b>{label}</b>"
    if row["on_watchlist"]:
        header += " 👁 <b>[WATCHLIST]</b>"
    lines.append(header)
    lines.append("")

    #  Identité 
    if row["external_id"]:
        lines.append(f"🔖 <b>CVE :</b> <code>{row['external_id']}</code>")
    if row["product"]:
        lines.append(f"📦 <b>Produit :</b> {row['product']}")
    if row["vendor"]:
        lines.append(f"🏢 <b>Éditeur :</b> {row['vendor']}")
    if row["affected_versions"]:
        lines.append(f"📌 <b>Versions affectées :</b> {row['affected_versions']}")
    if row["fixed_versions"]:
        lines.append(f"✅ <b>Correctif :</b> {row['fixed_versions']}")

    #  Scores 
    lines.append("")
    if row["cvss_score"] is not None:
        lines.append(f"📊 <b>CVSS :</b> {row['cvss_score']:.1f}")
        if row["cvss_vector"]:
            lines.append(f"   <code>{row['cvss_vector']}</code>")
    if row["epss_score"] is not None:
        lines.append(f"🎯 <b>EPSS :</b> {epss_label(row['epss_score'])}")
    lines.append(f"⚡ <b>Score interne :</b> {row['internal_score']:.0f}")

    #  Flags criticité 
    lines.append("")
    lines.append(f"💥 <b>Exploitation active :</b> {_yn(row['is_actively_exploited'])}")
    lines.append(f"🗂 <b>CISA KEV :</b> {_yn(row['is_kev'])}")
    lines.append(f"🧨 <b>Exploit public :</b> {_yn(row['has_public_exploit'])}")

    vuln_types = []
    if row["is_rce"]:               vuln_types.append("RCE")
    if row["is_auth_bypass"]:       vuln_types.append("Auth Bypass")
    if row["is_privilege_escalation"]: vuln_types.append("PrivEsc")
    if row["is_sqli"]:              vuln_types.append("SQLi")
    if row["is_ssrf"]:              vuln_types.append("SSRF")
    if row["is_xxe"]:               vuln_types.append("XXE")
    if row["mentions_ransomware"]:  vuln_types.append("Ransomware")
    if vuln_types:
        lines.append(f"🔧 <b>Type :</b> {' / '.join(vuln_types)}")

    #  Résumé 
    summary = (row["summary"] or "").strip()
    if summary:
        lines.append("")
        lines.append(f"📝 <b>Résumé :</b>")
        lines.append(summary[:500])

    #  Recommandations 
    lines.append("")
    lines.append("✅ <b>Actions recommandées :</b>")
    lines.append("1. Vérifier si le produit est présent dans votre périmètre.")
    if row["patch_available"]:
        lines.append("2. Appliquer le correctif de sécurité disponible.")
    elif row["workaround_available"]:
        lines.append("2. ⚠️ Pas de patch — appliquer les mesures de contournement.")
    else:
        lines.append("2. 🚫 Aucun correctif — isoler le service exposé.")
    lines.append("3. Réduire l'exposition Internet du service concerné.")
    lines.append("4. Surveiller les logs et les IOCs associés.")
    lines.append("5. Déployer des règles de détection (IDS/SIEM/EDR).")

    #  Sources 
    try:
        source_names = json.loads(row["source_names"] or "[]")
        extra_urls   = json.loads(row["extra_urls"] or "[]")
    except Exception:
        source_names, extra_urls = [], []

    if source_names:
        lines.append(f"\n📡 <b>Via :</b> {', '.join(source_names[:4])}")

    urls = []
    if row["url"]:
        urls.append(row["url"])
    urls.extend(extra_urls)
    if urls:
        lines.append("🔗 <b>Références :</b>")
        for u in urls[:3]:
            lines.append(f"   • {u}")

    return "\n".join(lines)


def send_critical_alert(row: sqlite3.Row, chat_id: Optional[str] = None) -> Optional[int]:
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        return None

    if db.alert_already_sent(row["id"], cid):
        return None

    text = format_alert(row)
    try:
        msg_id = send_message(text, chat_id=cid)
        if msg_id:
            db.mark_alert_sent(row["id"], cid, msg_id)
        return msg_id
    except Exception as exc:
        log.error("Échec alerte item_id=%s : %s", row["id"], exc)
        return None


#  Résumés 

def send_daily_summary(stats: dict, chat_id: Optional[str] = None) -> None:
    from datetime import datetime
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        return

    s   = stats
    sev = s.get("by_severity", {})
    lines = [
        f"📋 <b>Résumé quotidien — {datetime.utcnow().strftime('%d/%m/%Y')}</b>\n",
        f"📦 <b>Total collecté :</b> {s.get('total', 0)} items",
        f"🚨 CRITICAL : {sev.get('CRITICAL', 0)}",
        f"🔴 HIGH     : {sev.get('HIGH', 0)}",
        f"🟠 MEDIUM   : {sev.get('MEDIUM', 0)}",
        f"🔵 INFO     : {sev.get('INFO', 0)}\n",
        f"🗂 CISA KEV : {s.get('kev_count', 0)}",
        f"🧨 Exploits publics : {s.get('exploit_count', 0)}",
        f"🎯 Watchlist touchée : {s.get('watchlist_count', 0)}",
        f"🔥 EPSS ≥ 50% : {s.get('epss_high_count', 0)}\n",
        "🤖 <i>cyber-news-bot v2</i>",
    ]
    try:
        send_message("\n".join(lines), chat_id=cid)
    except Exception as exc:
        log.error("Échec résumé quotidien : %s", exc)


def send_weekly_summary(stats: dict, top_items: list, chat_id: Optional[str] = None) -> None:
    from datetime import datetime
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        return

    sev = stats.get("by_severity", {})
    lines = [
        f"📅 <b>Résumé hebdomadaire — {datetime.utcnow().strftime('%d/%m/%Y')}</b>\n",
        f"📦 Total : <b>{stats.get('total', 0)}</b> | "
        f"🚨 {sev.get('CRITICAL', 0)} critiques | "
        f"🔴 {sev.get('HIGH', 0)} élevés\n",
        "<b>Top menaces de la semaine :</b>",
    ]
    for i, row in enumerate(top_items[:5], 1):
        cve  = f"[{row['external_id']}] " if row["external_id"] else ""
        cvss = f" CVSS {row['cvss_score']:.1f}" if row["cvss_score"] else ""
        epss = f" | EPSS {row['epss_score']*100:.1f}%" if row["epss_score"] else ""
        lines.append(f"{i}. {cve}{row['title'][:70]}{cvss}{epss}")

    lines.append("\n🤖 <i>cyber-news-bot v2</i>")
    try:
        send_message("\n".join(lines), chat_id=cid)
    except Exception as exc:
        log.error("Échec résumé hebdomadaire : %s", exc)


#  Détection chat_id 

def get_chat_id_from_updates() -> list[dict]:
    try:
        data = _api("getUpdates", limit=100, timeout=10)
    except Exception as exc:
        log.error("getUpdates impossible : %s", exc)
        return []

    chats: dict[int, dict] = {}
    for update in data.get("result", []):
        msg  = update.get("message") or update.get("channel_post") or {}
        chat = msg.get("chat", {})
        cid  = chat.get("id")
        if cid:
            name = (
                chat.get("title")
                or f"{chat.get('first_name','')} {chat.get('last_name','')}".strip()
                or chat.get("username", "inconnu")
            )
            chats[cid] = {"id": cid, "name": name, "type": chat.get("type")}

    found = list(chats.values())
    if found:
        log.info("=== Chat IDs détectés ===")
        for c in found:
            log.info("  chat_id=%-15s  nom=%-25s  type=%s", c["id"], c["name"], c["type"])
        log.info("→ Ajoutez TELEGRAM_CHAT_ID=<id> dans votre .env")
    else:
        log.warning("Aucun chat trouvé. Envoyez /start au bot puis relancez.")
    return found


def test_notification(chat_id: Optional[str] = None) -> bool:
    cid = chat_id or config.TELEGRAM_CHAT_ID
    if not cid:
        log.error("TELEGRAM_CHAT_ID absent — test impossible.")
        return False
    try:
        send_message(
            "✅ <b>cyber-news-bot v2 — Test OK</b>\n"
            "Le bot Telegram fonctionne correctement.\n\n"
            "Commandes disponibles : /help",
            chat_id=cid,
        )
        log.info("Test Telegram OK → chat %s", cid)
        return True
    except Exception as exc:
        log.error("Test Telegram ÉCHEC : %s", exc)
        return False
