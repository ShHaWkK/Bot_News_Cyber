"""
Rapport hebdomadaire : résumé des 7 derniers jours.
"""

from datetime import datetime, timedelta

from app import database as db
from app.logger import log
from app.telegram_notifier import send_weekly_summary


def send(chat_id: str = "") -> None:
    since = datetime.utcnow() - timedelta(days=7)
    stats = db.get_stats_since(since)
    top_items = db.get_items_since(since, severity="CRITICAL")[:10]
    log.info("[Weekly] Envoi résumé hebdomadaire — %d items", stats.get("total", 0))
    send_weekly_summary(stats, top_items, chat_id=chat_id or None)
