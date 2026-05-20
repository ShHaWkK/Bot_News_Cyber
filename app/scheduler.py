"""
Planificateur APScheduler.
- Toutes les N minutes : cycle de récupération + alertes
- Tous les jours à 08h : résumé quotidien
- Toutes les semaines (lundi 08h) : résumé hebdomadaire
"""

import time
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app import config, database as db
from app.logger import log
from app.reports import daily, weekly


def _run_fetch_cycle() -> None:
    """Un cycle complet : récupère les sources, score, envoie les alertes non encore envoyées."""
    from app.sources import cisa_kev, nvd, certfr, rss_feeds, github_advisories, exploitdb
    from app import telegram_notifier as tg
    from datetime import timedelta

    run_id = db.start_run(mode="scheduled")
    new_items = 0
    alerts_sent_count = 0
    errors = 0
    since = datetime.utcnow() - timedelta(hours=config.CHECK_INTERVAL_MINUTES / 60 * 2)

    sources = [
        ("CISA-KEV",    lambda: cisa_kev.fetch(since=since)),
        ("CERT-FR",     lambda: certfr.fetch(since=since)),
        ("RSS",         lambda: rss_feeds.fetch(since=since)),
        ("Exploit-DB",  lambda: exploitdb.fetch(since=since)),
        ("NVD",         lambda: nvd.fetch(since=since, days=1)),
        ("GitHub-GHSA", lambda: github_advisories.fetch(since=since)),
    ]

    for source_name, fetcher in sources:
        try:
            items = fetcher()
            for item in items:
                item_id = db.insert_item(item)
                if item_id:
                    new_items += 1
            db.touch_source(source_name, len(items))
        except Exception as exc:
            log.error("[Scheduler] Erreur source %s : %s", source_name, exc)
            errors += 1

    # Envoi des alertes non envoyées (HIGH + CRITICAL)
    if config.TELEGRAM_CHAT_ID:
        unsent = db.get_unsent_alerts(config.TELEGRAM_CHAT_ID, min_severity="HIGH")
        for row in unsent:
            msg_id = tg.send_critical_alert(row)
            if msg_id:
                alerts_sent_count += 1
            time.sleep(1)  # Anti rate-limit Telegram

    db.finish_run(run_id, new_items, alerts_sent_count, errors)
    log.info(
        "[Scheduler] Cycle terminé — %d nouveaux items, %d alertes envoyées, %d erreurs",
        new_items, alerts_sent_count, errors,
    )


def _run_daily() -> None:
    log.info("[Scheduler] Déclenchement résumé quotidien")
    try:
        daily.send(chat_id=config.TELEGRAM_CHAT_ID)
    except Exception as exc:
        log.error("[Scheduler] Erreur résumé quotidien : %s", exc)


def _run_weekly() -> None:
    log.info("[Scheduler] Déclenchement résumé hebdomadaire")
    try:
        weekly.send(chat_id=config.TELEGRAM_CHAT_ID)
    except Exception as exc:
        log.error("[Scheduler] Erreur résumé hebdomadaire : %s", exc)


def build_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="Europe/Paris")

    # Cycle de récupération
    scheduler.add_job(
        _run_fetch_cycle,
        trigger=IntervalTrigger(minutes=config.CHECK_INTERVAL_MINUTES),
        id="fetch_cycle",
        name="Cycle de récupération cyber",
        replace_existing=True,
        max_instances=1,
    )

    # Résumé quotidien
    hour, minute = config.DAILY_SUMMARY_HOUR.split(":") if ":" in config.DAILY_SUMMARY_HOUR else ("8", "0")
    scheduler.add_job(
        _run_daily,
        trigger=CronTrigger(hour=int(hour), minute=int(minute)),
        id="daily_summary",
        name="Résumé quotidien",
        replace_existing=True,
    )

    # Résumé hebdomadaire (lundi matin)
    scheduler.add_job(
        _run_weekly,
        trigger=CronTrigger(day_of_week="mon", hour=int(hour), minute=int(minute)),
        id="weekly_summary",
        name="Résumé hebdomadaire",
        replace_existing=True,
    )

    return scheduler
