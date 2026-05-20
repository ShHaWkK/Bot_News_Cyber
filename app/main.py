"""
Point d'entrée principal du bot de veille cybersécurité.

Usage :
  python app/main.py --daemon          # Lance en mode service (APScheduler)
  python app/main.py --run-once        # Un seul cycle de récupération
  python app/main.py --backfill 60     # Backfill des 60 derniers jours
  python app/main.py --test-telegram   # Envoie un message de test
  python app/main.py --get-chat-id     # Détecte le chat_id depuis getUpdates
"""

import sys
import time

import click

# Initialisation précoce du logger et de la BDD
from app.logger import log
from app import database as db
from app import config


def _init() -> None:
    """Initialisation commune à tous les modes."""
    db.init_db()
    # Enregistrement des sources en base
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
    """Bot de veille cybersécurité — cyber-news-bot"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command("daemon")
def cmd_daemon():
    """Lance le bot en mode service (tourne indéfiniment)."""
    log.info("=== cyber-news-bot démarrage en mode daemon ===")
    _init()

    if not config.TELEGRAM_CHAT_ID:
        log.warning(
            "TELEGRAM_CHAT_ID absent dans .env. "
            "Lancez '--get-chat-id' pour le récupérer, puis relancez."
        )

    from app.scheduler import build_scheduler, _run_fetch_cycle

    scheduler = build_scheduler()
    scheduler.start()
    log.info(
        "Planificateur démarré — cycle toutes les %d min, résumé quotidien à %s",
        config.CHECK_INTERVAL_MINUTES,
        config.DAILY_SUMMARY_HOUR,
    )

    # Premier cycle immédiat
    log.info("Premier cycle de récupération immédiat...")
    _run_fetch_cycle()

    try:
        while True:
            time.sleep(30)
    except (KeyboardInterrupt, SystemExit):
        log.info("Arrêt du bot (SIGINT/SIGTERM)")
        scheduler.shutdown()


@cli.command("run-once")
def cmd_run_once():
    """Exécute un seul cycle de récupération et quitte."""
    log.info("=== Mode run-once ===")
    _init()
    from app.scheduler import _run_fetch_cycle
    _run_fetch_cycle()
    log.info("Cycle terminé.")


@cli.command("backfill")
@click.argument("days", type=int, default=60)
def cmd_backfill(days: int):
    """
    Remplit la base de données avec les données des N derniers jours.

    MODE BACKFILL_MODE=summary → envoie un rapport de synthèse initial.
    MODE BACKFILL_MODE=silent  → remplit la BDD sans spammer Telegram.
    """
    from datetime import datetime, timedelta
    from app.sources import cisa_kev, nvd, certfr, rss_feeds, github_advisories, exploitdb
    from app import telegram_notifier as tg

    log.info("=== Backfill sur %d jours (mode=%s) ===", days, config.BACKFILL_MODE)
    _init()

    since = datetime.utcnow() - timedelta(days=days)
    run_id = db.start_run(mode=f"backfill-{days}d")
    total_new = 0
    errors = 0

    sources = [
        ("CISA-KEV",    lambda: cisa_kev.fetch(since=since)),
        ("CERT-FR",     lambda: certfr.fetch(since=since)),
        ("RSS",         lambda: rss_feeds.fetch(since=since)),
        ("Exploit-DB",  lambda: exploitdb.fetch(since=since, use_csv=False)),
        ("NVD",         lambda: nvd.fetch(since=since, days=days)),
        ("GitHub-GHSA", lambda: github_advisories.fetch(since=since)),
    ]

    for source_name, fetcher in sources:
        try:
            log.info("[Backfill] Source : %s...", source_name)
            items = fetcher()
            new = 0
            for item in items:
                item_id = db.insert_item(item)
                if item_id:
                    new += 1
            total_new += new
            db.touch_source(source_name, len(items))
            log.info("[Backfill] %s : %d items insérés", source_name, new)
        except Exception as exc:
            log.error("[Backfill] Erreur source %s : %s", source_name, exc)
            errors += 1

    db.finish_run(run_id, total_new, 0, errors)
    log.info("[Backfill] Terminé — %d nouveaux items insérés", total_new)

    # Rapport de synthèse si mode summary
    if config.BACKFILL_MODE == "summary" and config.TELEGRAM_CHAT_ID:
        stats = db.get_stats_since(since)
        tg.send_daily_summary(stats)
        log.info("[Backfill] Rapport de synthèse envoyé sur Telegram.")
    elif config.BACKFILL_MODE == "silent":
        log.info("[Backfill] Mode silencieux — aucun message Telegram envoyé.")


@cli.command("test-telegram")
def cmd_test_telegram():
    """Envoie un message de test sur Telegram."""
    from app import telegram_notifier as tg
    ok = tg.test_notification()
    sys.exit(0 if ok else 1)


@cli.command("get-chat-id")
def cmd_get_chat_id():
    """
    Affiche les chat_id disponibles via getUpdates.
    Envoyez d'abord /start au bot depuis votre client Telegram.
    """
    from app import telegram_notifier as tg
    found = tg.get_chat_id_from_updates()
    if found:
        click.echo("\n=== Chat IDs détectés ===")
        for c in found:
            click.echo(f"  chat_id={c['id']}  nom={c['name']}  type={c['type']}")
        click.echo("\nAjoutez dans .env :")
        click.echo(f"  TELEGRAM_CHAT_ID={found[0]['id']}")
    else:
        click.echo("Aucun chat trouvé. Envoyez /start au bot puis relancez cette commande.")
        sys.exit(1)


#  Compat args legacy (--daemon, --backfill N, etc.) 

def _legacy_args() -> None:
    """Convertit les arguments style --flag en sous-commandes click."""
    import sys as _sys
    args = _sys.argv[1:]
    if not args:
        return

    mapping = {
        "--daemon":       ["daemon"],
        "--run-once":     ["run-once"],
        "--test-telegram":["test-telegram"],
        "--get-chat-id":  ["get-chat-id"],
    }

    for flag, replacement in mapping.items():
        if flag in args:
            _sys.argv = [_sys.argv[0]] + replacement
            return

    if "--backfill" in args:
        idx = args.index("--backfill")
        days = args[idx + 1] if idx + 1 < len(args) else "60"
        _sys.argv = [_sys.argv[0], "backfill", days]


if __name__ == "__main__":
    _legacy_args()
    cli()
