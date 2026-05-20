"""
Point d'entrée principal — cyber-news-bot v2.

Usage :
  python -m app.main daemon           # Lance en mode service (APScheduler)
  python -m app.main run-once         # Un seul cycle de récupération
  python -m app.main backfill [DAYS]  # Backfill des N derniers jours (défaut 60)
  python -m app.main enrich [LIMIT]   # Enrichit les CVEs en BDD sans CVSS/EPSS
  python -m app.main drain            # Vide manuellement la queue d'alertes
  python -m app.main stats [DAYS]     # Affiche les statistiques (défaut 7j)
  python -m app.main test-telegram    # Envoie un message de test
  python -m app.main get-chat-id      # Détecte le chat_id depuis getUpdates
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone

import click

from app.logger import log
from app import database as db
from app import config


def _init() -> None:
    db.init_db()
    db.upsert_source("CISA-KEV",    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    db.upsert_source("NVD",         "https://nvd.nist.gov/")
    db.upsert_source("CERT-FR",     "https://www.cert.ssi.gouv.fr/")
    db.upsert_source("Exploit-DB",  "https://www.exploit-db.com/")
    db.upsert_source("GitHub-GHSA", "https://github.com/advisories")
    for feed in config.RSS_FEEDS:
        db.upsert_source(feed["name"], feed["url"])


#  CLI

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """cyber-news-bot v2 — Veille cybersécurité automatisée"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("daemon")
def cmd_daemon():
    """Lance le bot en mode service continu (APScheduler)."""
    log.info("=== cyber-news-bot v2 — démarrage daemon ===")
    _init()

    if not config.TELEGRAM_CHAT_ID:
        log.warning(
            "TELEGRAM_CHAT_ID absent — lancez 'get-chat-id' puis ajoutez-le dans .env."
        )

    from app.scheduler import build_scheduler, _run_fetch_cycle

    scheduler = build_scheduler()
    scheduler.start()
    log.info(
        "Planificateur démarré — cycle toutes les %d min | résumé à %s",
        config.CHECK_INTERVAL_MINUTES,
        config.DAILY_SUMMARY_HOUR,
    )

    log.info("Premier cycle immédiat...")
    _run_fetch_cycle()

    try:
        while True:
            time.sleep(30)
    except (KeyboardInterrupt, SystemExit):
        log.info("Arrêt propre (SIGINT/SIGTERM)")
        scheduler.shutdown()


@cli.command("run-once")
def cmd_run_once():
    """Exécute un seul cycle complet (fetch + enrichissement + alertes) puis quitte."""
    log.info("=== Mode run-once ===")
    _init()
    from app.scheduler import _run_fetch_cycle
    _run_fetch_cycle()
    log.info("Cycle terminé.")


@cli.command("backfill")
@click.argument("days", type=int, default=60)
@click.option("--no-enrich", is_flag=True, default=False,
              help="Désactive l'enrichissement NVD/EPSS pendant le backfill.")
def cmd_backfill(days: int, no_enrich: bool):
    """
    Remplit la BDD avec les données des N derniers jours (défaut : 60).

    BACKFILL_MODE=summary → envoie un rapport de synthèse sur Telegram.
    BACKFILL_MODE=silent  → BDD uniquement, aucun spam Telegram.
    """
    from app.sources import cisa_kev, nvd, certfr, rss_feeds, github_advisories, exploitdb
    from app.enricher import run_pipeline
    from app.dedup import assign_hash
    from app import telegram_notifier as tg

    log.info("=== Backfill %d jours (mode=%s, enrich=%s) ===",
             days, config.BACKFILL_MODE, not no_enrich)
    _init()

    since = datetime.utcnow() - timedelta(days=days)
    run_id = db.start_run(mode=f"backfill-{days}d")
    total_new = 0
    total_enriched = 0
    errors = 0

    sources = [
        ("CISA-KEV",    lambda: cisa_kev.fetch(since=since)),
        ("CERT-FR",     lambda: certfr.fetch(since=since)),
        ("RSS",         lambda: rss_feeds.fetch(since=since)),
        ("Exploit-DB",  lambda: exploitdb.fetch(since=since)),
        ("NVD",         lambda: nvd.fetch(since=since, days=days)),
        ("GitHub-GHSA", lambda: github_advisories.fetch(since=since)),
    ]

    for source_name, fetcher in sources:
        try:
            log.info("[Backfill] Collecte : %s...", source_name)
            raw_items = fetcher()
            if not raw_items:
                log.info("[Backfill] %s : aucun item", source_name)
                continue

            # Enrichissement (sauf si --no-enrich)
            if not no_enrich:
                items = run_pipeline(raw_items)
                total_enriched += sum(1 for i in items if i.enriched)
            else:
                items = raw_items

            new = 0
            for item in items:
                if not item.dedup_hash:
                    item = assign_hash(item)

                # Cross-source dedup
                if item.external_id and item.external_id.startswith("CVE-"):
                    existing = db.get_item_by_cve(item.external_id)
                    if existing:
                        db.merge_source_into_item(existing["id"], source_name, item.url)
                        db.update_item_enrichment(existing["id"], item)
                        continue

                item_id = db.insert_item(item)
                if item_id:
                    new += 1

            total_new += new
            db.touch_source(source_name, len(raw_items))
            log.info("[Backfill] %s : %d/%d items insérés", source_name, new, len(raw_items))

        except Exception as exc:
            log.error("[Backfill] Erreur source %s : %s", source_name, exc)
            errors += 1

    db.finish_run(run_id, total_new, total_enriched, 0, errors)
    log.info("[Backfill] Terminé — %d items insérés, %d enrichis", total_new, total_enriched)

    if config.BACKFILL_MODE == "summary" and config.TELEGRAM_CHAT_ID:
        stats = db.get_stats_since(since)
        tg.send_daily_summary(stats, chat_id=config.TELEGRAM_CHAT_ID)
        log.info("[Backfill] Rapport de synthèse envoyé sur Telegram.")
    elif config.BACKFILL_MODE == "silent":
        log.info("[Backfill] Mode silencieux — aucun message Telegram.")


@cli.command("enrich")
@click.argument("limit", type=int, default=50)
def cmd_enrich(limit: int):
    """Enrichit les CVEs en BDD sans CVSS/EPSS (NVD + EPSS batch)."""
    log.info("=== Enrichissement différé (limit=%d) ===", limit)
    _init()
    from app.enricher import enrich_pending_in_db
    enriched = enrich_pending_in_db(limit=limit)
    click.echo(f"Enrichissement terminé : {enriched} items mis à jour.")


@cli.command("drain")
def cmd_drain():
    """Vide manuellement la queue d'alertes en attente."""
    _init()
    if not config.TELEGRAM_CHAT_ID:
        click.echo("TELEGRAM_CHAT_ID absent — impossible de drainer.", err=True)
        sys.exit(1)
    from app import alert_manager as am
    from app import telegram_notifier as tg
    sent = am.drain_queue(config.TELEGRAM_CHAT_ID, tg)
    click.echo(f"{sent} alerte(s) envoyée(s).")


@cli.command("stats")
@click.argument("days", type=int, default=7)
def cmd_stats(days: int):
    """Affiche les statistiques des N derniers jours (défaut 7)."""
    _init()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    s = db.get_stats_since(since)
    sev = s.get("by_severity", {})
    by_type = s.get("by_type", {})

    click.echo(f"\n{'='*40}")
    click.echo(f"  Statistiques — {days} derniers jours")
    click.echo(f"{'='*40}")
    click.echo(f"  Total items    : {s.get('total', 0)}")
    click.echo(f"  CRITICAL       : {sev.get('CRITICAL', 0)}")
    click.echo(f"  HIGH           : {sev.get('HIGH', 0)}")
    click.echo(f"  MEDIUM         : {sev.get('MEDIUM', 0)}")
    click.echo(f"  INFO           : {sev.get('INFO', 0)}")
    click.echo(f"---")
    click.echo(f"  CISA KEV       : {s.get('kev_count', 0)}")
    click.echo(f"  Exploits pub.  : {s.get('exploit_count', 0)}")
    click.echo(f"  Watchlist      : {s.get('watchlist_count', 0)}")
    click.echo(f"  EPSS >= 50%    : {s.get('epss_high_count', 0)}")
    click.echo(f"---")
    click.echo(f"  KEV            : {by_type.get('KEV', 0)}")
    click.echo(f"  CVE            : {by_type.get('CVE', 0)}")
    click.echo(f"  CERT-FR        : {by_type.get('CERT', 0)}")
    click.echo(f"  Exploit        : {by_type.get('EXPLOIT', 0)}")
    click.echo(f"  News           : {by_type.get('NEWS', 0)}")
    click.echo()


@cli.command("test-telegram")
def cmd_test_telegram():
    """Envoie un message de test sur Telegram."""
    from app import telegram_notifier as tg
    ok = tg.test_notification()
    sys.exit(0 if ok else 1)


@cli.command("get-chat-id")
def cmd_get_chat_id():
    """
    Détecte les chat_id via getUpdates.
    Envoyez /start au bot depuis Telegram avant de lancer cette commande.
    """
    from app import telegram_notifier as tg
    found = tg.get_chat_id_from_updates()
    if found:
        click.echo("\n=== Chat IDs détectés ===")
        for c in found:
            click.echo(f"  chat_id={c['id']}  nom={c['name']}  type={c['type']}")
        click.echo(f"\nAjoutez dans .env :\n  TELEGRAM_CHAT_ID={found[0]['id']}")
    else:
        click.echo("Aucun chat trouvé. Envoyez /start au bot puis relancez.")
        sys.exit(1)


#  Compat args legacy (--daemon, --backfill N, etc.)

def _legacy_args() -> None:
    args = sys.argv[1:]
    if not args:
        return

    mapping = {
        "--daemon":        ["daemon"],
        "--run-once":      ["run-once"],
        "--test-telegram": ["test-telegram"],
        "--get-chat-id":   ["get-chat-id"],
        "--enrich":        ["enrich"],
        "--drain":         ["drain"],
        "--stats":         ["stats"],
    }

    for flag, replacement in mapping.items():
        if flag in args:
            sys.argv = [sys.argv[0]] + replacement
            return

    if "--backfill" in args:
        idx = args.index("--backfill")
        days = args[idx + 1] if idx + 1 < len(args) and args[idx + 1].isdigit() else "60"
        sys.argv = [sys.argv[0], "backfill", days]


if __name__ == "__main__":
    _legacy_args()
    cli()
