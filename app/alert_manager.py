"""
Gestionnaire d'alertes v2.

Logique de throttling :
  CRITICAL  → envoi immédiat, pas de limite
  HIGH      → max MAX_HIGH_ALERTS_PER_HOUR par heure, sinon différé
  MEDIUM    → digest quotidien uniquement (pas d'alerte individuelle)
  INFO      → jamais envoyé individuellement

Mute : silence temporaire configurable via /mute <minutes>
Queue persistante en SQLite : aucune perte si Telegram est HS.
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional

from app import config, database as db
from app.logger import log


#  Compteur d'alertes HIGH dans la fenêtre glissante 

def _count_high_sent_last_hour(chat_id: str) -> int:
    """Compte les alertes HIGH envoyées dans la dernière heure."""
    since = datetime.utcnow() - timedelta(hours=1)
    with db.get_conn() as conn:
        return conn.execute(
            """SELECT COUNT(*) FROM alerts_sent a
               JOIN items i ON a.item_id = i.id
               WHERE a.chat_id=? AND a.sent_at>=? AND i.severity IN ('HIGH','CRITICAL')""",
            (chat_id, since),
        ).fetchone()[0]


#  Enqueue 

def queue_item(item_id: int, severity: str, chat_id: str) -> None:
    """
    Décide quand l'alerte doit partir et l'insère dans la queue.
    CRITICAL → maintenant
    HIGH     → maintenant si quota non atteint, sinon dans ALERT_BATCH_WAIT_MINUTES
    MEDIUM   → ignoré (digest quotidien)
    """
    if severity == "INFO" or severity == "MEDIUM":
        return
    if not chat_id:
        return

    # Ne pas re-queuer si déjà dans la queue
    if db.alert_already_sent(item_id, chat_id):
        return

    now = datetime.utcnow()

    if severity == "CRITICAL":
        send_after = now
    else:  # HIGH
        high_count = _count_high_sent_last_hour(chat_id)
        if high_count >= config.MAX_HIGH_ALERTS_PER_HOUR:
            send_after = now + timedelta(minutes=config.ALERT_BATCH_WAIT_MINUTES)
            log.debug("[AlertMgr] HIGH throttled (quota %d/h) → envoi dans %d min",
                      config.MAX_HIGH_ALERTS_PER_HOUR, config.ALERT_BATCH_WAIT_MINUTES)
        else:
            send_after = now

    db.enqueue_alert(item_id, chat_id, severity, send_after)


#  Drain de la queue 

def drain_queue(chat_id: str, notifier) -> int:
    """
    Envoie les alertes en attente dans la queue.
    `notifier` est le module telegram_notifier.
    Retourne le nombre d'alertes envoyées.
    """
    if not chat_id:
        return 0

    if db.is_muted(chat_id):
        until = db.mute_until(chat_id)
        log.debug("[AlertMgr] Chat %s en mute jusqu'à %s", chat_id,
                  until.strftime("%H:%M") if until else "?")
        return 0

    pending = db.get_pending_alerts(chat_id, limit=20)
    if not pending:
        return 0

    sent = 0
    for row in pending:
        # Sécurité : éviter les doublons si déjà marqué envoyé
        if db.alert_already_sent(row["item_id"], chat_id):
            db.mark_queue_sent(row["queue_id"])
            continue

        try:
            msg_id = notifier.send_critical_alert(row, chat_id=chat_id)
            if msg_id is not None:
                db.mark_queue_sent(row["queue_id"], msg_id)
                db.mark_alert_sent(row["item_id"], chat_id, msg_id)
                sent += 1
                time.sleep(1.2)  # anti rate-limit Telegram (max ~1 msg/s)
            else:
                db.increment_queue_attempt(row["queue_id"])
        except Exception as exc:
            log.error("[AlertMgr] Échec envoi item_id=%s : %s", row["item_id"], exc)
            db.increment_queue_attempt(row["queue_id"])

    if sent:
        log.info("[AlertMgr] %d alertes envoyées depuis la queue", sent)
    return sent


#  Digest MEDIUM 

def send_medium_digest(chat_id: str, notifier) -> int:
    """
    Envoie un digest des alertes MEDIUM de la dernière heure non encore envoyées.
    Appelé toutes les heures par le scheduler si des items MEDIUM non envoyés existent.
    """
    if not chat_id or db.is_muted(chat_id):
        return 0

    since = datetime.utcnow() - timedelta(hours=1)
    with db.get_conn() as conn:
        rows = conn.execute(
            """SELECT i.* FROM items i
               WHERE i.severity='MEDIUM'
                 AND i.fetched_at>=?
                 AND i.id NOT IN (SELECT item_id FROM alerts_sent WHERE chat_id=?)
               ORDER BY i.internal_score DESC
               LIMIT 10""",
            (since, chat_id),
        ).fetchall()

    if not rows:
        return 0

    lines = [f"🟠 <b>Digest Alertes MEDIUM — {len(rows)} nouvelles</b>\n"]
    for row in rows:
        cve = f"[{row['external_id']}] " if row["external_id"] else ""
        epss = f" | EPSS {row['epss_score']*100:.1f}%" if row["epss_score"] else ""
        cvss = f" | CVSS {row['cvss_score']:.1f}" if row["cvss_score"] else ""
        lines.append(
            f"• {cve}{row['title'][:70]}{cvss}{epss}"
        )
        db.mark_alert_sent(row["id"], chat_id)

    try:
        notifier.send_message("\n".join(lines), chat_id=chat_id)
        log.info("[AlertMgr] Digest MEDIUM envoyé (%d items)", len(rows))
        return len(rows)
    except Exception as exc:
        log.error("[AlertMgr] Échec digest MEDIUM : %s", exc)
        return 0


#  Convenience : traiter une liste d'items nouveaux 

def process_new_items(item_ids_severities: list[tuple[int, str]], chat_id: str) -> None:
    """
    Pour chaque (item_id, severity) nouvel item, enqueuer si nécessaire.
    """
    for item_id, severity in item_ids_severities:
        queue_item(item_id, severity, chat_id)
