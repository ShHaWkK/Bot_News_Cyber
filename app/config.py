"""
Configuration centrale — lit les variables depuis .env via python-dotenv.
Toutes les valeurs sensibles sont lues ici, jamais écrites en dur.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

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

def _opt(key: str, default: str = "") -> str:
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

def _list(key: str, default: str = "") -> list[str]:
    raw = os.getenv(key, default).strip()
    if not raw:
        return []
    return [x.strip().lower() for x in raw.split(",") if x.strip()]

def _bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).strip().lower() in ("1", "true", "yes", "oui")


#  Telegram 
TELEGRAM_BOT_TOKEN: str = _require("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID: str   = _opt("TELEGRAM_CHAT_ID")

#  Base de données 
DB_PATH: Path = Path(_opt("DB_PATH", "/opt/cyber-news-bot/data/cybernews.sqlite"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

#  Planification 
CHECK_INTERVAL_MINUTES: int  = _int("CHECK_INTERVAL_MINUTES", 30)
BACKFILL_DAYS: int           = _int("BACKFILL_DAYS", 60)
BACKFILL_MODE: str           = _opt("BACKFILL_MODE", "silent")   # silent | summary
DAILY_SUMMARY_HOUR: str      = _opt("DAILY_SUMMARY_HOUR", "08:00")

#  Scoring 
MIN_CVSS_ALERT: float   = _float("MIN_CVSS_ALERT", 7.0)
MIN_EPSS_ALERT: float   = _float("MIN_EPSS_ALERT", 0.10)   # prob. exploitation > 10 %
MIN_SCORE_ALERT: float  = _float("MIN_SCORE_ALERT", 35.0)  # score interne minimum pour alerter

#  Throttling Telegram 
# CRITICAL → immédiat, sans limite
# HIGH     → max N par heure, sinon dans le digest haute priorité
# MEDIUM   → digest quotidien uniquement
MAX_HIGH_ALERTS_PER_HOUR: int   = _int("MAX_HIGH_ALERTS_PER_HOUR", 5)
ALERT_BATCH_WAIT_MINUTES: int   = _int("ALERT_BATCH_WAIT_MINUTES", 15)  # délai avant envoi batch

#  Watchlist personnalisée 
# Vendors/produits à surveiller en priorité → bonus de +25 pts de score
# Exemple : WATCH_VENDORS=fortinet,cisco,palo alto
WATCH_VENDORS: list[str]   = _list("WATCH_VENDORS", "")
WATCH_PRODUCTS: list[str]  = _list("WATCH_PRODUCTS", "")
WATCHLIST_SCORE_BOOST: float = _float("WATCHLIST_SCORE_BOOST", 25.0)

#  Enrichissement CVE 
ENRICH_CVE: bool = _bool("ENRICH_CVE", True)   # auto-fetch NVD pour CVEs trouvés dans RSS
ENRICH_EPSS: bool = _bool("ENRICH_EPSS", True) # fetch EPSS pour tous les CVEs

#  Langue 
LANG: str = _opt("LANG", "fr")

#  Logs 
LOG_LEVEL: str = _opt("LOG_LEVEL", "INFO").upper()
LOG_DIR: Path  = Path(_opt("LOG_DIR", "/opt/cyber-news-bot/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

#  APIs externes 
NVD_API_KEY: str   = _opt("NVD_API_KEY")
GITHUB_TOKEN: str  = _opt("GITHUB_TOKEN")

#  HTTP 
HTTP_TIMEOUT: int       = 30
HTTP_USER_AGENT: str    = "CyberNewsBot/2.0 (+https://github.com/alx-ops/cyber-news-bot)"
HTTP_MAX_RETRIES: int   = 3
HTTP_RETRY_BACKOFF: float = 2.0

HTTP_PROXY: str   = _opt("HTTP_PROXY")
HTTPS_PROXY: str  = _opt("HTTPS_PROXY")
PROXIES: dict     = {}
if HTTP_PROXY:
    PROXIES["http"] = HTTP_PROXY
if HTTPS_PROXY:
    PROXIES["https"] = HTTPS_PROXY

#  Sources RSS 
RSS_FEEDS: list[dict] = [
    {"name": "The Hacker News",    "url": "https://feeds.feedburner.com/TheHackersNews",                  "lang": "en"},
    {"name": "BleepingComputer",   "url": "https://www.bleepingcomputer.com/feed/",                       "lang": "en"},
    {"name": "SecurityWeek",       "url": "https://feeds.feedburner.com/Securityweek",                    "lang": "en"},
    {"name": "Dark Reading",       "url": "https://www.darkreading.com/rss.xml",                          "lang": "en"},
    {"name": "KrebsOnSecurity",    "url": "https://krebsonsecurity.com/feed/",                            "lang": "en"},
    {"name": "CERT-FR Alertes",    "url": "https://www.cert.ssi.gouv.fr/alerte/feed/",                   "lang": "fr"},
    {"name": "CERT-FR Avis",       "url": "https://www.cert.ssi.gouv.fr/avis/feed/",                     "lang": "fr"},
    {"name": "ANSSI",              "url": "https://www.cert.ssi.gouv.fr/feed/",                           "lang": "fr"},
    {"name": "Microsoft MSRC",     "url": "https://api.msrc.microsoft.com/update-guide/rss",              "lang": "en"},
    {"name": "Palo Alto Unit42",   "url": "https://unit42.paloaltonetworks.com/feed/",                   "lang": "en"},
    {"name": "Ubuntu Security",    "url": "https://ubuntu.com/security/notices/rss.xml",                  "lang": "en"},
    {"name": "SANS Internet Storm","url": "https://isc.sans.edu/rssfeed_full.xml",                        "lang": "en"},
    {"name": "Recorded Future",    "url": "https://www.recordedfuture.com/feed",                          "lang": "en"},
    {"name": "Rapid7 Blog",        "url": "https://www.rapid7.com/blog/feed/",                            "lang": "en"},
    {"name": "Qualys Blog",        "url": "https://blog.qualys.com/feed",                                 "lang": "en"},
    {"name": "Tenable Blog",       "url": "https://www.tenable.com/blog/feed",                            "lang": "en"},
]

#  Produits sensibles pour le scoring 
SENSITIVE_PRODUCTS: list[str] = [
    "fortinet", "fortigate", "fortios", "forticlient", "fortiweb", "fortiproxy",
    "cisco", "ios xe", "asa", "anyconnect", "firepower", "meraki",
    "palo alto", "pan-os", "globalprotect", "cortex",
    "vmware", "esxi", "vcenter", "vsphere", "horizon", "aria",
    "microsoft", "exchange", "windows", "active directory", "sharepoint", "teams",
    "azure", "office 365", "m365", "iis", "rdp", "smb",
    "linux kernel",
    "openssh",
    "openvpn", "wireguard",
    "kubernetes", "k8s", "helm",
    "docker", "containerd",
    "apache", "httpd", "log4j", "struts", "tomcat", "solr",
    "nginx",
    "wordpress", "woocommerce",
    "citrix", "netscaler", "xenserver",
    "ivanti", "pulse secure", "connect secure",
    "atlassian", "confluence", "jira", "bitbucket",
    "gitlab",
    "jenkins",
    "f5", "big-ip", "nginx plus",
    "juniper", "junos",
    "solarwinds",
    "zimbra",
    "veeam",
    "moveit",
    "barracuda",
    "progress", "whatsup gold",
    "telerik",
    "sap",
    "oracle", "weblogic",
    "spring", "spring framework",
    "node.js", "nodejs",
    "php",
    "openssl",
    "curl", "libcurl",
    "zabbix",
    "nagios",
    "splunk",
    "elasticsearch",
    "redis",
    "mongodb",
    "postgresql",
    "mysql", "mariadb",
]
