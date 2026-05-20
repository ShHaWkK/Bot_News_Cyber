"""
Moteur de scoring cyber.
Attribue un score interne et une sévérité (CRITICAL/HIGH/MEDIUM/INFO) à chaque item.
"""

import re
from app import config
from app.models import CyberItem, Severity


#  Mots-clés de détection 

_RCE_KEYWORDS = [
    "remote code execution", "rce", "code execution",
    "exécution de code", "exécution à distance",
    "arbitrary code", "command injection", "command execution",
    "os command", "shell injection",
]

_AUTH_BYPASS_KEYWORDS = [
    "authentication bypass", "auth bypass", "bypass authentication",
    "unauthenticated", "sans authentification",
    "improper authentication", "broken authentication",
    "bypass d'authentification",
]

_PRIVESC_KEYWORDS = [
    "privilege escalation", "local privilege", "elevation of privilege",
    "élévation de privilèges", "escalade de privilèges",
    "privesc", "root access", "admin access",
]

_EXPLOIT_KEYWORDS = [
    "exploit", "exploited", "actively exploited", "exploitation",
    "proof of concept", "poc", "metasploit", "weaponized",
    "exploit public", "exploit disponible",
    "0-day", "zero-day", "0day",
]

_RANSOMWARE_KEYWORDS = [
    "ransomware", "ransom", "lockbit", "blackcat", "alphv",
    "clop", "hive", "blackbasta", "play ransomware",
    "cl0p", "akira", "rhysida",
]

_PATCH_KEYWORDS = [
    "patch", "update", "fix", "hotfix", "security update",
    "mise à jour", "correctif", "advisory", "bulletin",
]

_INTERNET_EXPOSED_KEYWORDS = [
    "internet-facing", "internet exposed", "publicly accessible",
    "exposed to internet", "publicly reachable", "exposed online",
    "accès internet", "exposé sur internet",
]


def _contains(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _mentions_sensitive_product(text: str) -> bool:
    text_lower = text.lower()
    return any(p in text_lower for p in config.SENSITIVE_PRODUCTS)


#  Analyse des flags 

def detect_flags(item: CyberItem) -> CyberItem:
    """Détecte et remplit les booléens de criticité depuis le titre et le résumé."""
    corpus = f"{item.title} {item.summary}".lower()

    item.is_rce = _contains(corpus, _RCE_KEYWORDS)
    item.is_auth_bypass = _contains(corpus, _AUTH_BYPASS_KEYWORDS)
    item.is_privilege_escalation = _contains(corpus, _PRIVESC_KEYWORDS)
    item.has_public_exploit = (
        item.has_public_exploit or _contains(corpus, _EXPLOIT_KEYWORDS)
    )
    item.is_actively_exploited = (
        item.is_actively_exploited
        or "actively exploited" in corpus
        or "exploitation active" in corpus
        or "exploited in the wild" in corpus
        or "exploitée activement" in corpus
    )
    item.mentions_ransomware = _contains(corpus, _RANSOMWARE_KEYWORDS)
    item.patch_available = _contains(corpus, _PATCH_KEYWORDS)

    return item


#  Calcul du score 

def compute_score(item: CyberItem) -> CyberItem:
    """
    Calcule internal_score et attribue la sévérité.

    Barème :
      CVSS base                     → jusqu'à 10 pts
      CISA KEV                      → +30 pts
      Exploitation active           → +25 pts
      Exploit public                → +20 pts
      RCE                           → +20 pts
      Auth bypass                   → +15 pts
      Privilege escalation          → +10 pts
      Ransomware                    → +15 pts
      Produit sensible              → +10 pts
      Pas de patch                  → +5 pts
      Internet exposé (texte)       → +5 pts
    """
    score = 0.0

    # CVSS
    if item.cvss_score is not None:
        score += float(item.cvss_score)

    # Flags
    if item.is_kev:
        score += 30
    if item.is_actively_exploited:
        score += 25
    if item.has_public_exploit:
        score += 20
    if item.is_rce:
        score += 20
    if item.is_auth_bypass:
        score += 15
    if item.mentions_ransomware:
        score += 15
    if item.is_privilege_escalation:
        score += 10

    corpus = f"{item.title} {item.summary}"
    if _mentions_sensitive_product(corpus):
        score += 10
    if not item.patch_available:
        score += 5
    if _contains(corpus, _INTERNET_EXPOSED_KEYWORDS):
        score += 5

    item.internal_score = round(score, 2)

    # Sévérité
    item.severity = _classify_severity(item)
    return item


def _classify_severity(item: CyberItem) -> str:
    s = item.internal_score
    cvss = item.cvss_score or 0.0

    if (
        s >= 55
        or item.is_kev
        or (cvss >= 9.0 and item.is_actively_exploited)
        or (item.is_rce and item.is_actively_exploited)
    ):
        return Severity.CRITICAL

    if (
        s >= 35
        or cvss >= 9.0
        or (cvss >= 7.0 and item.has_public_exploit)
        or (cvss >= 7.0 and item.is_actively_exploited)
        or item.is_rce
        or item.is_auth_bypass
    ):
        return Severity.HIGH

    if s >= 15 or cvss >= config.MIN_CVSS_ALERT:
        return Severity.MEDIUM

    return Severity.INFO


def score_item(item: CyberItem) -> CyberItem:
    """Point d'entrée unique : détecte les flags puis calcule le score."""
    item = detect_flags(item)
    item = compute_score(item)
    return item
