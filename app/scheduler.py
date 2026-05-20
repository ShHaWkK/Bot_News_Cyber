"""
Planificateur APScheduler v2.

Jobs :
  - fetch_cycle       : toutes les N minutes — collecte + enrichissement + queue alertes
  - drain_alerts      : toutes les 2 min — vide la queue d'alertes
  - enrich_pending    : toutes les 10 min — enrichit les CVEs sans CVSS/EPSS en BDD
  - handle_commands   : toutes les minutes — répond aux commandes Telegram
  - medium_digest     : toutes les heures — digest MEDIUM
  - daily_summary     : tous les jours à DAILY_SUMMARY_HOUR
  - weekly_summary    : tous les lundis à DAILY_SUMMARY_HOUR
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app import config, database as db
from app.logger import log


#  Cycle principal 

def _run_fetch_cycle() -> None:
    from app.sources import cisa_kev, certfr, rss_feeds, exploitdb
    from app.sources import nvd, github_advisories
    from app import alert_manager as am
    from app import telegram_notifier as tg
    from app.enricher import run_pipeline
    from app.dedup import assign_hash

    since = datetime.utcnow() - timedelta(minutes=config.CHECK_INTERVAL_MINUTES * 2)
    run_id = db.start_run(mode="scheduled")
    new_items_total = 0
    enriched_total  = 0
    errors          = 0

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
            raw_items = fetcher()
            if not raw_items:
                continue

            # Pipeline d'enrichissement AVANT insert
            enriched_items = run_pipeline(raw_items)
            enriched_total += sum(1 for i in enriched_items if i.enriched)

            new_ids_severities: list[tuple[int, str]] = []
            for item in enriched_items:
                if not item.dedup_hash:
                    item = assign_hash(item)

                # Cross-source dedup : si même CVE existe déjà, merger
                if item.external_id and item.external_id.startswith("CVE-"):
                    existing = db.get_item_by_cve(item.external_id)
                    if existing:
                        db.merge_source_into_item(existing["id"], source_name, item.url)
                        db.update_item_enrichment(existing["id"], item)
                        continue

                item_id = db.insert_item(item)
                if item_id:
                    new_items_total += 1
                    new_ids_severities.append((item_id, item.severity))

            # Enqueue les alertes nouvelles
            if config.TELEGRAM_CHAT_ID:
                am.process_new_items(new_ids_severities, config.TELEGRAM_CHAT_ID)

            db.touch_source(source_name, len(raw_items))

        except Exception as exc:
            log.error("[Scheduler] Erreur source %s : %s", source_name, exc)
            errors += 1

    # Drain immédiat des CRITICAL
    alerts_sent = 0
    if config.TELEGRAM_CHAT_ID:
        alerts_sent = am.drain_queue(config.TELEGRAM_CHAT_ID, tg)

    db.finish_run(run_id, new_items_total, enriched_total, alerts_sent, errors)
    log.info(
        "[Scheduler] Cycle — %d nouveaux, %d enrichis, %d alertes, %d erreurs",
        new_items_total, enriched_total, alerts_sent, errors,
    )


def _drain_alerts() -> None:
    """Vide la queue d'alertes (CRITICAL + HIGH)."""
    if not config.TELEGRAM_CHAT_ID:
        return
    from app import alert_manager as am
    from app import telegram_notifier as tg
    am.drain_queue(config.TELEGRAM_CHAT_ID, tg)


def _enrich_pending() -> None:
    """Enrichit les CVEs en BDD sans CVSS/EPSS."""
    from app.enricher import enrich_pending_in_db
    try:
        enrich_pending_in_db(limit=20)
    except Exception as exc:
        log.error("[Scheduler] Erreur enrichissement pending : %s", exc)


def _handle_commands() -> None:
    """Répond aux commandes Telegram."""
    from app.bot_commands import handle_updates
    try:
        handle_updates()
    except Exception as exc:
        log.error("[Scheduler] Erreur handle_commands : %s", exc)


def _medium_digest() -> None:
    if not config.TELEGRAM_CHAT_ID:
        return
    from app import alert_manager as am
    from app import telegram_notifier as tg
    try:
        am.send_medium_digest(config.TELEGRAM_CHAT_ID, tg)
    except Exception as exc:
        log.error("[Scheduler] Erreur digest MEDIUM : %s", exc)


def _daily_summary() -> None:
    if not config.TELEGRAM_CHAT_ID:
        return
    from app import telegram_notifier as tg
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(hours=24)
    stats = db.get_stats_since(since)
    try:
        tg.send_daily_summary(stats, chat_id=config.TELEGRAM_CHAT_ID)
    except Exception as exc:
        log.error("[Scheduler] Erreur résumé quotidien : %s", exc)


def _weekly_summary() -> None:
    if not config.TELEGRAM_CHAT_ID:
        return
    from app import telegram_notifier as tg
    since = datetime.utcnow() - timedelta(days=7)
    stats    = db.get_stats_since(since)
    top_rows = db.get_top_items(since, n=5)
    try:
        tg.send_weekly_summary(stats, top_rows, chat_id=config.TELEGRAM_CHAT_ID)
    except Exception as exc:
        log.error("[Scheduler] Erreur résumé hebdomadaire : %s", exc)


#  Construction 

def build_scheduler() -> BackgroundScheduler:
    tz = "Europe/Paris"
    scheduler = BackgroundScheduler(timezone=tz)

    # Collecte principale
    scheduler.add_job(
        _run_fetch_cycle,
        trigger=IntervalTrigger(minutes=config.CHECK_INTERVAL_MINUTES),
        id="fetch_cycle", name="Collecte cyber",
        replace_existing=True, max_instances=1,
    )

    # Drain alertes (toutes les 2 min)
    scheduler.add_job(
        _drain_alerts,
        trigger=IntervalTrigger(minutes=2),
        id="drain_alerts", name="Drain alertes Telegram",
        replace_existing=True, max_instances=1,
    )

    # Enrichissement différé (toutes les 10 min)
    scheduler.add_job(
        _enrich_pending,
        trigger=IntervalTrigger(minutes=10),
        id="enrich_pending", name="Enrichissement CVE/EPSS",
        replace_existing=True, max_instances=1,
    )

    # Commandes Telegram (toutes les 15 secondes)
    scheduler.add_job(
        _handle_commands,
        trigger=IntervalTrigger(seconds=15),
        id="bot_commands", name="Commandes Telegram",
        replace_existing=True, max_instances=1,
    )

    # Digest MEDIUM (toutes les heures)
    scheduler.add_job(
        _medium_digest,
        trigger=IntervalTrigger(hours=1),
        id="medium_digest", name="Digest MEDIUM",
        replace_existing=True, max_instances=1,
    )

    # Résumé quotidien
    hour, minute = (config.DAILY_SUMMARY_HOUR.split(":")
                    if ":" in config.DAILY_SUMMARY_HOUR else ("8", "0"))
    scheduler.add_job(
        _daily_summary,
        trigger=CronTrigger(hour=int(hour), minute=int(minute), timezone=tz),
        id="daily_summary", name="Résumé quotidien",
        replace_existing=True,
    )

    # Résumé hebdomadaire (lundi)
    scheduler.add_job(
        _weekly_summary,
        trigger=CronTrigger(day_of_week="mon", hour=int(hour), minute=int(minute), timezone=tz),
        id="weekly_summary", name="Résumé hebdomadaire",
        replace_existing=True,
    )

    return scheduler
