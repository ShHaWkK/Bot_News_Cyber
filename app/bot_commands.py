"""
Gestionnaire de commandes Telegram interactives.

Commandes disponibles :
  /help              Liste des commandes
  /status            État du bot (dernière collecte, nb items, mute)
  /stats [7|30]      Statistiques sur N jours (défaut 7)
  /top [5]           Top N menaces récentes par score
  /cve CVE-XXXX-XXXX Détail complet d'un CVE depuis la BDD
  /search <terme>    Recherche plein texte (FTS5)
  /mute [60]         Silence les alertes pendant N minutes (défaut 60)
  /unmute            Réactive les alertes
  /id                Affiche le chat_id courant

Fonctionnement : polling getUpdates avec offset persisté en BDD.
Le scheduler appelle handle_updates() toutes les minutes.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Optional

from app import config, database as db
from app.logger import log
from app.sources.epss import epss_label


#  API Telegram (import local pour éviter la circularité) 

def _send(chat_id: str | int, text: str) -> None:
    from app.telegram_notifier import send_message
    try:
        send_message(text, chat_id=str(chat_id))
    except Exception as exc:
        log.error("[BotCmd] Échec envoi réponse : %s", exc)


#  Formatage des rows SQLite 

def _fmt_severity(sev: str) -> str:
    return {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟠", "INFO": "🔵"}.get(sev, "❓")


def _fmt_item_line(row, n: int = 0) -> str:
    prefix = f"{n}. " if n else "• "
    cve  = f"[{row['external_id']}] " if row["external_id"] else ""
    cvss = f" CVSS {row['cvss_score']:.1f}" if row["cvss_score"] else ""
    epss = f" | EPSS {row['epss_score']*100:.1f}%" if row["epss_score"] else ""
    sev  = _fmt_severity(row["severity"])
    return f"{prefix}{sev} {cve}<b>{row['title'][:65]}</b>{cvss}{epss}"


#  Handlers 

def cmd_help(chat_id: str) -> None:
    text = (
        "🤖 <b>cyber-news-bot — Commandes</b>\n\n"
        "/status — État du bot et dernière collecte\n"
        "/stats [7|30] — Statistiques sur N jours\n"
        "/top [5] — Top N menaces par score\n"
        "/cve CVE-XXXX-XXXX — Détails d'un CVE\n"
        "/search &lt;terme&gt; — Recherche plein texte\n"
        "/mute [60] — Silence pendant N minutes\n"
        "/unmute — Réactiver les alertes\n"
        "/id — Votre chat_id\n"
        "/help — Cette aide"
    )
    _send(chat_id, text)


def cmd_id(chat_id: str) -> None:
    _send(
        chat_id,
        f"🪪 Votre <b>chat_id</b> : <code>{chat_id}</code>\n\n"
        f"Ajoutez dans <code>.env</code> :\n"
        f"<code>TELEGRAM_CHAT_ID={chat_id}</code>",
    )


def cmd_status(chat_id: str) -> None:
    since_1h  = datetime.utcnow() - timedelta(hours=1)
    since_24h = datetime.utcnow() - timedelta(hours=24)
    stats_24h = db.get_stats_since(since_24h)

    # Dernière collecte
    with db.get_conn() as conn:
        last_run = conn.execute(
            "SELECT started_at, new_items, errors FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        queue_count = conn.execute(
            "SELECT COUNT(*) FROM alert_queue WHERE sent=0 AND chat_id=?", (chat_id,)
        ).fetchone()[0]
        total_items = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]

    muted = db.is_muted(chat_id)
    mute_info = ""
    if muted:
        until = db.mute_until(chat_id)
        mute_info = f"\n🔇 <b>Mute actif</b> jusqu'à {until.strftime('%H:%M') if until else '?'}"

    last_run_str = ""
    if last_run:
        last_run_str = (
            f"\n⏱ Dernière collecte : {last_run['started_at']}"
            f" ({last_run['new_items']} nouveaux, {last_run['errors']} erreurs)"
        )

    lines = [
        "📊 <b>Statut du bot</b>\n",
        f"🗃 Total items en BDD : <b>{total_items}</b>",
        f"📥 Dernières 24h : <b>{stats_24h['total']}</b> items",
        f"🚨 CRITICAL : {stats_24h['by_severity'].get('CRITICAL', 0)}",
        f"🔴 HIGH : {stats_24h['by_severity'].get('HIGH', 0)}",
        f"🗂 CISA KEV (24h) : {stats_24h['kev_count']}",
        f"🧨 Exploits publics (24h) : {stats_24h['exploit_count']}",
        f"📬 Alertes en queue : {queue_count}",
        last_run_str,
        mute_info,
        f"\n⚙️ Intervalle collecte : {config.CHECK_INTERVAL_MINUTES} min",
        f"📡 Sources actives : {len(config.RSS_FEEDS) + 4}",
    ]
    _send(chat_id, "\n".join(l for l in lines if l))


def cmd_stats(chat_id: str, days: int = 7) -> None:
    days = max(1, min(days, 90))
    since = datetime.utcnow() - timedelta(days=days)
    s = db.get_stats_since(since)

    by_type = s.get("by_type", {})
    lines = [
        f"📈 <b>Statistiques — {days} derniers jours</b>\n",
        f"📦 Total : <b>{s['total']}</b> items collectés\n",
        "<b>Par sévérité :</b>",
        f"  🚨 CRITICAL : {s['by_severity'].get('CRITICAL', 0)}",
        f"  🔴 HIGH     : {s['by_severity'].get('HIGH', 0)}",
        f"  🟠 MEDIUM   : {s['by_severity'].get('MEDIUM', 0)}",
        f"  🔵 INFO     : {s['by_severity'].get('INFO', 0)}\n",
        "<b>Par type :</b>",
        f"  🗂 KEV      : {by_type.get('KEV', 0)}",
        f"  🔖 CVE      : {by_type.get('CVE', 0)}",
        f"  🛡 CERT     : {by_type.get('CERT', 0)}",
        f"  💥 EXPLOIT  : {by_type.get('EXPLOIT', 0)}",
        f"  📰 NEWS     : {by_type.get('NEWS', 0)}\n",
        f"🗂 CISA KEV : <b>{s['kev_count']}</b>",
        f"🧨 Exploits publics : <b>{s['exploit_count']}</b>",
        f"🎯 Watchlist touchée : <b>{s['watchlist_count']}</b>",
        f"🔥 EPSS ≥ 50% : <b>{s['epss_high_count']}</b>",
    ]
    _send(chat_id, "\n".join(lines))


def cmd_top(chat_id: str, n: int = 5) -> None:
    n = max(1, min(n, 10))
    since = datetime.utcnow() - timedelta(days=7)
    rows = db.get_top_items(since, n=n)

    if not rows:
        _send(chat_id, "Aucun item récent trouvé.")
        return

    lines = [f"🏆 <b>Top {n} menaces — 7 derniers jours</b>\n"]
    for i, row in enumerate(rows, 1):
        lines.append(_fmt_item_line(row, i))
        if row["vendor"] or row["product"]:
            lines.append(f"   📦 {row['vendor']} {row['product']}".strip())
        lines.append("")

    _send(chat_id, "\n".join(lines))


def cmd_cve(chat_id: str, cve_id: str) -> None:
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        _send(chat_id, "❌ Format invalide. Exemple : /cve CVE-2024-1234")
        return

    row = db.get_item_by_cve(cve_id)
    if not row:
        _send(chat_id, f"❌ <code>{cve_id}</code> non trouvé dans la base.\n"
              "Il sera collecté lors du prochain cycle NVD.")
        return

    sev    = _fmt_severity(row["severity"])
    cvss   = f"{row['cvss_score']:.1f}" if row["cvss_score"] else "N/A"
    vector = f"\n<code>{row['cvss_vector']}</code>" if row["cvss_vector"] else ""
    epss   = epss_label(row["epss_score"]) if row["epss_score"] else "Non disponible"
    sources = json.loads(row["source_names"] or "[]")
    extra  = json.loads(row["extra_urls"] or "[]")

    flags = []
    if row["is_kev"]:             flags.append("🗂 CISA KEV")
    if row["is_actively_exploited"]: flags.append("💥 Exploitation active")
    if row["has_public_exploit"]: flags.append("🧨 Exploit public")
    if row["is_rce"]:             flags.append("🔴 RCE")
    if row["is_auth_bypass"]:     flags.append("🔐 Auth Bypass")
    if row["is_privilege_escalation"]: flags.append("⬆️ PrivEsc")
    if row["is_sqli"]:            flags.append("💉 SQLi")
    if row["mentions_ransomware"]: flags.append("💀 Ransomware")
    if row["on_watchlist"]:       flags.append("👁 Watchlist")

    lines = [
        f"{sev} <b>{cve_id}</b>",
        "",
        f"📦 Produit : {row['product'] or 'N/A'}  |  🏢 Éditeur : {row['vendor'] or 'N/A'}",
        f"📊 CVSS {cvss}{vector}",
        f"🎯 EPSS : {epss}",
        f"⚡ Score interne : {row['internal_score']:.0f}",
        "",
    ]
    if flags:
        lines.append("🏷 " + "  ".join(flags))
        lines.append("")
    if row["affected_versions"]:
        lines.append(f"📌 Versions affectées : {row['affected_versions']}")
    if row["fixed_versions"]:
        lines.append(f"✅ Correctif : {row['fixed_versions']}")
    if row["summary"]:
        lines.append(f"\n📝 {row['summary'][:400]}")
    if sources:
        lines.append(f"\n📡 Sources : {', '.join(sources[:4])}")
    if extra:
        lines.append("\n🔗 Références :")
        for url in extra[:3]:
            lines.append(f"  • {url}")

    _send(chat_id, "\n".join(lines))


def cmd_search(chat_id: str, query: str) -> None:
    query = query.strip()
    if len(query) < 2:
        _send(chat_id, "❌ Terme trop court (minimum 2 caractères).")
        return

    rows = db.search_items(query, limit=8)
    if not rows:
        _send(chat_id, f"🔍 Aucun résultat pour « {query} ».")
        return

    lines = [f"🔍 <b>Résultats pour « {query} »</b> ({len(rows)} items)\n"]
    for row in rows:
        lines.append(_fmt_item_line(row))
        if row["published_at"]:
            try:
                dt = datetime.fromisoformat(str(row["published_at"]))
                lines.append(f"   📅 {dt.strftime('%d/%m/%Y')}")
            except Exception:
                pass
        lines.append("")

    _send(chat_id, "\n".join(lines))


def cmd_mute(chat_id: str, minutes: int = 60) -> None:
    minutes = max(5, min(minutes, 1440))  # 5 min à 24h
    db.mute_chat(chat_id, minutes)
    until = datetime.utcnow() + timedelta(minutes=minutes)
    _send(
        chat_id,
        f"🔇 Alertes silencieuses pendant <b>{minutes} min</b>.\n"
        f"Reprise à <b>{until.strftime('%H:%M')}</b>.\n"
        f"Utilisez /unmute pour réactiver.",
    )


def cmd_unmute(chat_id: str) -> None:
    db.unmute_chat(chat_id)
    _send(chat_id, "🔔 Alertes réactivées.")


#  Polling getUpdates 

def handle_updates() -> None:
    """
    Appelle getUpdates avec l'offset persisté en BDD.
    Traite les commandes et met à jour l'offset.
    Doit être appelé périodiquement (toutes les minutes par le scheduler).
    """
    import requests

    offset = int(db.get_setting("tg_update_offset", "0"))
    token  = config.TELEGRAM_BOT_TOKEN
    url    = f"https://api.telegram.org/bot{token}/getUpdates"

    try:
        resp = requests.get(
            url,
            params={"offset": offset, "timeout": 5, "limit": 50},
            headers={"User-Agent": config.HTTP_USER_AGENT},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.debug("[BotCmd] getUpdates erreur : %s", exc)
        return

    updates = data.get("result", [])
    if not updates:
        return

    new_offset = offset
    for update in updates:
        update_id = update.get("update_id", 0)
        new_offset = max(new_offset, update_id + 1)

        msg = update.get("message") or update.get("edited_message", {})
        if not msg:
            continue

        text    = (msg.get("text") or "").strip()
        chat_id = str(msg.get("chat", {}).get("id", ""))
        if not text or not chat_id or not text.startswith("/"):
            continue

        # Parse commande et arguments
        parts = text.split(maxsplit=1)
        cmd   = parts[0].split("@")[0].lower()  # /cmd@botname → /cmd
        args  = parts[1].strip() if len(parts) > 1 else ""

        log.info("[BotCmd] Commande %s de chat=%s", cmd, chat_id)
        _dispatch(cmd, args, chat_id)

    if new_offset != offset:
        db.set_setting("tg_update_offset", str(new_offset))


def _dispatch(cmd: str, args: str, chat_id: str) -> None:
    try:
        if cmd in ("/start", "/help"):
            cmd_help(chat_id)
        elif cmd == "/id":
            cmd_id(chat_id)
        elif cmd == "/status":
            cmd_status(chat_id)
        elif cmd == "/stats":
            days = int(args) if args.isdigit() else 7
            cmd_stats(chat_id, days)
        elif cmd == "/top":
            n = int(args) if args.isdigit() else 5
            cmd_top(chat_id, n)
        elif cmd == "/cve":
            if args:
                cmd_cve(chat_id, args)
            else:
                _send(chat_id, "Usage : /cve CVE-2024-1234")
        elif cmd == "/search":
            if args:
                cmd_search(chat_id, args)
            else:
                _send(chat_id, "Usage : /search <terme>")
        elif cmd == "/mute":
            minutes = int(args) if args.isdigit() else 60
            cmd_mute(chat_id, minutes)
        elif cmd == "/unmute":
            cmd_unmute(chat_id)
        else:
            _send(chat_id, f"❓ Commande inconnue : {cmd}\nTapez /help pour la liste.")
    except Exception as exc:
        log.error("[BotCmd] Erreur dispatch %s : %s", cmd, exc)
        _send(chat_id, f"❌ Erreur interne : {exc}")
