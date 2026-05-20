"""
Source : NVD CVE API v2.
Documentation : https://nvd.nist.gov/developers/vulnerabilities
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from app import config
from app.logger import log
from app.models import CyberItem, ItemType
from app.normalizer import parse_date, clean_text, truncate
from app.dedup import assign_hash
from app.scoring import score_item

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE_NAME = "NVD"

# NVD : max 2000 résultats par requête, pagination obligatoire
_PAGE_SIZE = 2000
# Délai entre requêtes (NVD rate-limit : 5 req/30s sans clé, 50 req/30s avec clé)
_DELAY_NO_KEY = 6.5
_DELAY_WITH_KEY = 0.7


def _delay() -> None:
    time.sleep(_DELAY_WITH_KEY if config.NVD_API_KEY else _DELAY_NO_KEY)


@retry(stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
       wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=5, max=120),
       reraise=True)
def _fetch_page(params: dict) -> dict:
    headers = {"User-Agent": config.HTTP_USER_AGENT}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    resp = requests.get(
        _BASE,
        params=params,
        headers=headers,
        timeout=config.HTTP_TIMEOUT,
        proxies=config.PROXIES or None,
    )
    resp.raise_for_status()
    return resp.json()


def _parse_cvss(cve_data: dict) -> tuple[Optional[float], Optional[str]]:
    """Extrait le score CVSS le plus récent disponible."""
    metrics = cve_data.get("metrics", {})
    # Préférer CVSSv3.1 > CVSSv3.0 > CVSSv2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            version = data.get("version")
            if score is not None:
                return float(score), str(version)
    return None, None


def _parse_item(vuln: dict) -> Optional[CyberItem]:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    published = parse_date(cve.get("published"))
    modified = parse_date(cve.get("lastModified"))

    # Description en anglais (ou la première disponible)
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    summary = clean_text(desc_en)

    cvss_score, cvss_version = _parse_cvss(cve)

    # Tags depuis les faiblesses CWE
    tags = []
    weaknesses = cve.get("weaknesses", [])
    for w in weaknesses:
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                tags.append(val)

    # Références
    refs = cve.get("references", [])
    extra_urls = [r["url"] for r in refs[:5] if r.get("url")]

    # Vendor/product depuis CPE
    vendor, product = "", ""
    configs = cve.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = vendor or parts[3].replace("_", " ").title()
                    product = product or parts[4].replace("_", " ").title()
                    break
            if vendor:
                break
        if vendor:
            break

    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    item = CyberItem(
        source=SOURCE_NAME,
        external_id=cve_id,
        title=f"{cve_id} — {summary[:100]}" if summary else cve_id,
        url=nvd_url,
        summary=truncate(summary, 800),
        published_at=published,
        item_type=ItemType.CVE,
        cvss_score=cvss_score,
        cvss_version=cvss_version,
        vendor=vendor,
        product=product,
        tags=tags[:10],
        extra_urls=extra_urls,
    )
    item = assign_hash(item)
    item = score_item(item)
    return item


def fetch(since: Optional[datetime] = None, days: int = 7) -> list[CyberItem]:
    """
    Récupère les CVE publiées depuis `since` (ou les `days` derniers jours).
    Filtre sur cvss >= MIN_CVSS_ALERT pour réduire le volume.
    """
    if since is None:
        since = datetime.utcnow() - timedelta(days=days)
    elif since.tzinfo is not None:
        since = since.replace(tzinfo=None)

    # NVD attend des dates au format ISO 8601
    pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")

    log.info("[NVD] Récupération CVE depuis %s", since.strftime("%Y-%m-%d"))

    items: list[CyberItem] = []
    start_index = 0

    while True:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "startIndex": start_index,
            "resultsPerPage": _PAGE_SIZE,
        }
        # Filtrer sur CVSS si pas de clé (pour rester dans les limites)
        if config.MIN_CVSS_ALERT >= 7.0:
            params["cvssV3Severity"] = "HIGH"  # HIGH + CRITICAL

        try:
            _delay()
            data = _fetch_page(params)
        except Exception as exc:
            log.error("[NVD] Erreur page start=%d : %s", start_index, exc)
            break

        vulnerabilities = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)

        for vuln in vulnerabilities:
            item = _parse_item(vuln)
            if item:
                items.append(item)

        start_index += len(vulnerabilities)
        log.debug("[NVD] %d/%d CVE récupérées", start_index, total)

        if start_index >= total or not vulnerabilities:
            break

    log.info("[NVD] %d CVE récupérées au total", len(items))
    return items
