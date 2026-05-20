"""
Configuration centrale — lit les variables depuis .env via python-dotenv.
Toutes les valeurs sensibles (token, chat_id) sont lues ici, jamais écrites en dur.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Cherche .env dans /opt/cyber-news-bot puis dans le répertoire courant
_ENV_PATHS = [
    Path("/opt/cyber-news-bot/.env"),
    Path(__file__).resolve().parent.parent / ".env",
]

for _p in _ENV_PATHS:
    if _p.exists():
        load_dotenv(dotenv_path=_p, override=False)
        break
else:
    load_dotenv(override=False)


def _require(key: str) -> str:
    val = os.getenv(key, "").strip()
    if not val:
        raise EnvironmentError(
            f"Variable d'environnement obligatoire manquante : {key}\n"
            f"Vérifiez votre fichier .env."
        )
    return val


def _optional(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def _float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


def _int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


#  Telegram 
TELEGRAM_BOT_TOKEN: str = _require("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID: str = _optional("TELEGRAM_CHAT_ID")  # peut être vide au départ

#  Base de données 
DB_PATH: Path = Path(_optional("DB_PATH", "/opt/cyber-news-bot/data/cybernews.sqlite"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

#  Planification 
CHECK_INTERVAL_MINUTES: int = _int("CHECK_INTERVAL_MINUTES", 30)
BACKFILL_DAYS: int = _int("BACKFILL_DAYS", 60)
BACKFILL_MODE: str = _optional("BACKFILL_MODE", "silent")  # silent | summary

#  Scoring 
MIN_CVSS_ALERT: float = _float("MIN_CVSS_ALERT", 7.0)

#  Langue 
LANG: str = _optional("LANG", "fr")

#  Logs 
LOG_LEVEL: str = _optional("LOG_LEVEL", "INFO").upper()
LOG_DIR: Path = Path(_optional("LOG_DIR", "/opt/cyber-news-bot/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

#  Résumé quotidien 
DAILY_SUMMARY_HOUR: str = _optional("DAILY_SUMMARY_HOUR", "08:00")

#  APIs externes 
NVD_API_KEY: str = _optional("NVD_API_KEY")
GITHUB_TOKEN: str = _optional("GITHUB_TOKEN")

#  HTTP 
HTTP_TIMEOUT: int = 30
HTTP_USER_AGENT: str = (
    "CyberNewsBot/1.0 (+https://github.com/alx-ops/cyber-news-bot)"
)
HTTP_MAX_RETRIES: int = 3
HTTP_RETRY_BACKOFF: float = 2.0  # secondes

#  Proxy 
HTTP_PROXY: str = _optional("HTTP_PROXY")
HTTPS_PROXY: str = _optional("HTTPS_PROXY")

PROXIES: dict = {}
if HTTP_PROXY:
    PROXIES["http"] = HTTP_PROXY
if HTTPS_PROXY:
    PROXIES["https"] = HTTPS_PROXY

#  Sources RSS 
RSS_FEEDS: list[dict] = [
    {"name": "The Hacker News",      "url": "https://feeds.feedburner.com/TheHackersNews",             "lang": "en"},
    {"name": "BleepingComputer",     "url": "https://www.bleepingcomputer.com/feed/",                   "lang": "en"},
    {"name": "SecurityWeek",         "url": "https://feeds.feedburner.com/Securityweek",                "lang": "en"},
    {"name": "Dark Reading",         "url": "https://www.darkreading.com/rss.xml",                      "lang": "en"},
    {"name": "KrebsOnSecurity",      "url": "https://krebsonsecurity.com/feed/",                        "lang": "en"},
    {"name": "CERT-FR Alertes",      "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",               "lang": "fr"},
    {"name": "CERT-FR Avis",         "url": "https://www.cert.ssi.gouv.fr/avis/feed/",                 "lang": "fr"},
    {"name": "ANSSI",                "url": "https://www.cert.ssi.gouv.fr/feed/",                       "lang": "fr"},
    {"name": "Cisco Talos",          "url": "https://blog.talosintelligence.com/rss/",                  "lang": "en"},
    {"name": "Microsoft MSRC",       "url": "https://api.msrc.microsoft.com/update-guide/rss",         "lang": "en"},
    {"name": "Fortinet PSIRT",       "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",    "lang": "en"},
    {"name": "Palo Alto Unit42",     "url": "https://unit42.paloaltonetworks.com/feed/",               "lang": "en"},
    {"name": "VMware Security",      "url": "https://blogs.vmware.com/security/feed/",                 "lang": "en"},
    {"name": "Ubuntu Security",      "url": "https://ubuntu.com/security/notices/rss.xml",             "lang": "en"},
    {"name": "Debian Security",      "url": "https://www.debian.org/security/dsa-long.en.rdf",         "lang": "en"},
    {"name": "SANS Internet Storm",  "url": "https://isc.sans.edu/rssfeed_full.xml",                   "lang": "en"},
]

#  Produits sensibles (scoring) 
SENSITIVE_PRODUCTS: list[str] = [
    "fortinet", "fortigate", "fortios", "forticlient",
    "cisco", "ios xe", "asa", "anyconnect",
    "palo alto", "pan-os", "globalprotect",
    "vmware", "esxi", "vcenter", "vsphere", "broadcom",
    "microsoft", "exchange", "windows", "active directory", "sharepoint",
    "linux kernel",
    "openssh",
    "openvpn",
    "kubernetes", "k8s",
    "docker",
    "apache", "httpd", "log4j", "struts",
    "nginx",
    "wordpress",
    "citrix", "netscaler",
    "ivanti", "pulse secure",
    "atlassian", "confluence", "jira",
    "gitlab",
    "jenkins",
    "f5", "big-ip",
    "juniper",
    "solarwinds",
    "zimbra",
    "veeam",
    "moveit",
    "barracuda",
]
