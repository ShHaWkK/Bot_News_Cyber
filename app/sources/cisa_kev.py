"""
Source : CISA Known Exploited Vulnerabilities (KEV) Catalog.
URL : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from datetime import datetime, timedelta
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from app import config
from app.logger import log
from app.models import CyberItem, ItemType, Severity
from app.normalizer import parse_date, clean_text, truncate
from app.dedup import assign_hash
from app.scoring import score_item

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE_NAME = "CISA-KEV"


@retry(stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
       wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=2, max=60),
       reraise=True)
def _fetch() -> dict:
    resp = requests.get(
        _URL,
        timeout=config.HTTP_TIMEOUT,
        headers={"User-Agent": config.HTTP_USER_AGENT},
        proxies=config.PROXIES or None,
    )
    resp.raise_for_status()
    return resp.json()


def fetch(since: Optional[datetime] = None) -> list[CyberItem]:
    """
    Récupère le catalogue KEV complet et filtre sur `since` si fourni.
    Toutes les entrées KEV sont marquées is_kev=True et is_actively_exploited=True.
    """
    log.info("[CISA-KEV] Récupération du catalogue...")
    try:
        data = _fetch()
    except Exception as exc:
        log.error("[CISA-KEV] Erreur de récupération : %s", exc)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    log.info("[CISA-KEV] %d entrées dans le catalogue", len(vulnerabilities))

    items: list[CyberItem] = []
    for vuln in vulnerabilities:
        date_added = parse_date(vuln.get("dateAdded"))

        # Filtre temporel
        if since and date_added and date_added < since:
            continue

        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        description = clean_text(vuln.get("shortDescription", ""))
        due_date = vuln.get("dueDate", "")
        action = clean_text(vuln.get("requiredAction", ""))

        summary = description
        if action:
            summary += f"\n\nAction requise : {action}"
        if due_date:
            summary += f"\nDate limite CISA : {due_date}"

        item = CyberItem(
            source=SOURCE_NAME,
            external_id=cve_id,
            title=f"[KEV] {cve_id} — {vendor} {product}".strip(" —"),
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            summary=truncate(summary, 800),
            published_at=date_added,
            item_type=ItemType.KEV,
            vendor=vendor,
            product=product,
            is_kev=True,
            is_actively_exploited=True,
            tags=["kev", "cisa", "actively-exploited"],
        )
        item = assign_hash(item)
        item = score_item(item)
        items.append(item)

    log.info("[CISA-KEV] %d nouvelles entrées après filtre date", len(items))
    return items
