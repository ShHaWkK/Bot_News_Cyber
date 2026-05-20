"""
Rapport quotidien : résumé des dernières 24h.
"""

from datetime import datetime, timedelta

from app import database as db
from app.logger import log
from app.telegram_notifier import send_daily_summary


def send(chat_id: str = "") -> None:
    since = datetime.utcnow() - timedelta(hours=24)
    stats = db.get_stats_since(since)
    log.info("[Daily] Envoi résumé quotidien — %d items", stats.get("total", 0))
    send_daily_summary(stats, chat_id=chat_id or None)
