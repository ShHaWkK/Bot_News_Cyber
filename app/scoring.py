"""
Moteur de scoring cyber v2.
Intègre CVSS, EPSS, KEV, flags techniques, watchlist et contexte.
"""

from __future__ import annotations

import re
from app import config
from app.models import CyberItem, Severity

#  Mots-clés 

_RCE = [
    "remote code execution", "rce", "code execution", "arbitrary code",
    "command injection", "command execution", "os command", "shell injection",
    "exécution de code", "exécution à distance", "execute arbitrary",
]
_AUTH_BYPASS = [
    "authentication bypass", "auth bypass", "bypass authentication",
    "unauthenticated", "without authentication", "no authentication",
    "improper authentication", "bypass d'authentification",
    "sans authentification", "pre-auth",
]
_PRIVESC = [
    "privilege escalation", "local privilege", "elevation of privilege",
    "privesc", "root access", "gain root", "gain admin",
    "élévation de privilèges", "escalade de privilèges",
]
_SQLI = [
    "sql injection", "sqli", "sql inj", "inject sql",
    "injection sql", "database injection",
]
_SSRF = [
    "server-side request forgery", "ssrf",
    "falsification de requête côté serveur",
]
_XXE = [
    "xml external entity", "xxe", "xml injection",
]
_EXPLOIT_ACTIVE = [
    "actively exploited", "exploitation active", "exploited in the wild",
    "exploitée activement", "wild exploitation", "known exploited",
    "under active exploitation",
]
_EXPLOIT_PUBLIC = [
    "proof of concept", "poc", "metasploit", "weaponized",
    "public exploit", "exploit available", "exploit public",
    "exploit disponible", "0-day", "zero-day", "0day",
]
_RANSOMWARE = [
    "ransomware", "ransom", "lockbit", "blackcat", "alphv",
    "clop", "cl0p", "hive", "blackbasta", "play ransomware",
    "akira", "rhysida", "medusa", "dark angels",
]
_PATCH = [
    "patch", "security update", "hotfix", "fix available",
    "mise à jour", "correctif", "advisory",
]
_WORKAROUND = [
    "workaround", "mitigation", "contournement", "mitigate",
]
_INTERNET = [
    "internet-facing", "internet exposed", "publicly accessible",
    "exposed to internet", "publicly reachable", "exposed online",
    "exposé sur internet", "accès internet", "remote attack",
]


def _hit(corpus: str, kws: list[str]) -> bool:
    return any(k in corpus for k in kws)


def _sensitive(corpus: str) -> bool:
    return any(p in corpus for p in config.SENSITIVE_PRODUCTS)


#  Détection des flags 

def detect_flags(item: CyberItem) -> CyberItem:
    corpus = f"{item.title} {item.summary} {item.vendor} {item.product}".lower()

    item.is_rce                  = _hit(corpus, _RCE)
    item.is_auth_bypass          = _hit(corpus, _AUTH_BYPASS)
    item.is_privilege_escalation = _hit(corpus, _PRIVESC)
    item.is_sqli                 = _hit(corpus, _SQLI)
    item.is_ssrf                 = _hit(corpus, _SSRF)
    item.is_xxe                  = _hit(corpus, _XXE)
    item.mentions_ransomware     = _hit(corpus, _RANSOMWARE)
    item.is_actively_exploited   = item.is_actively_exploited or _hit(corpus, _EXPLOIT_ACTIVE)
    item.has_public_exploit      = item.has_public_exploit    or _hit(corpus, _EXPLOIT_PUBLIC)
    item.patch_available         = item.patch_available       or _hit(corpus, _PATCH)
    item.workaround_available    = _hit(corpus, _WORKAROUND)
    item.internet_exposed        = _hit(corpus, _INTERNET)

    return item


#  Scoring 
#
# Barème v2 :
#   CVSS base                    → +score (0–10)
#   EPSS ≥ 0.9                   → +35 pts (quasi-certain)
#   EPSS ≥ 0.5                   → +25 pts (très probable)
#   EPSS ≥ 0.1                   → +10 pts (possible)
#   CISA KEV                     → +30 pts
#   Exploitation active          → +25 pts
#   Exploit public               → +20 pts
#   RCE                          → +20 pts
#   Auth bypass                  → +15 pts
#   Privilege escalation         → +10 pts
#   SQLi / SSRF / XXE            → +8 pts
#   Ransomware                   → +15 pts
#   Produit sensible             → +10 pts
#   Watchlist                    → +boost config (défaut +25)
#   Internet exposé              → +5 pts
#   Pas de patch                 → +5 pts

def compute_score(item: CyberItem) -> CyberItem:
    score = 0.0

    # CVSS
    if item.cvss_score is not None:
        score += float(item.cvss_score)

    # EPSS
    if item.epss_score is not None:
        e = item.epss_score
        if e >= 0.90:
            score += 35
        elif e >= 0.50:
            score += 25
        elif e >= 0.20:
            score += 15
        elif e >= 0.10:
            score += 10

    # KEV / exploitation
    if item.is_kev:
        score += 30
    if item.is_actively_exploited:
        score += 25
    if item.has_public_exploit:
        score += 20

    # Type de vulnérabilité
    if item.is_rce:
        score += 20
    if item.is_auth_bypass:
        score += 15
    if item.is_privilege_escalation:
        score += 10
    if item.is_sqli:
        score += 8
    if item.is_ssrf:
        score += 8
    if item.is_xxe:
        score += 8

    # Contexte
    if item.mentions_ransomware:
        score += 15

    corpus = f"{item.title} {item.summary} {item.vendor} {item.product}"
    if _sensitive(corpus.lower()):
        score += 10

    # Watchlist : boost personnalisé
    if item.on_watchlist:
        score += config.WATCHLIST_SCORE_BOOST

    # Exposition / patch
    if item.internet_exposed:
        score += 5
    if not item.patch_available:
        score += 5

    item.internal_score = round(score, 2)
    item.severity = _classify(item)
    return item


def _classify(item: CyberItem) -> str:
    s    = item.internal_score
    cvss = item.cvss_score or 0.0
    epss = item.epss_score or 0.0

    # CRITICAL
    if (
        s >= 60
        or item.is_kev
        or (cvss >= 9.0 and item.is_actively_exploited)
        or (item.is_rce and item.is_actively_exploited)
        or (epss >= 0.90 and cvss >= 7.0)
        or (item.on_watchlist and s >= 50)
    ):
        return Severity.CRITICAL

    # HIGH
    if (
        s >= 40
        or cvss >= 9.0
        or (cvss >= 7.0 and item.has_public_exploit)
        or (cvss >= 7.0 and item.is_actively_exploited)
        or (epss >= 0.50 and cvss >= 6.0)
        or item.is_rce
        or item.is_auth_bypass
        or (item.on_watchlist and cvss >= 7.0)
    ):
        return Severity.HIGH

    # MEDIUM
    if (
        s >= 20
        or cvss >= config.MIN_CVSS_ALERT
        or (epss is not None and epss >= config.MIN_EPSS_ALERT)
        or (item.on_watchlist and s >= 15)
    ):
        return Severity.MEDIUM

    return Severity.INFO


def score_item(item: CyberItem) -> CyberItem:
    item = detect_flags(item)
    item = compute_score(item)
    return item
