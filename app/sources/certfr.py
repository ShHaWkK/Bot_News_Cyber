"""
Source : CERT-FR — Avis et Alertes de sécurité.
Utilise les flux RSS officiels + scraping léger de la page de détail si nécessaire.
"""

from datetime import datetime
from typing import Optional

import feedparser
import requests
from tenacity import retry, stop_after_attempt, wait_exponential
from tenacity import retry, stop_after_attempt, wait_exponential

from app import config
from app.logger import log
from app.models import CyberItem, ItemType
from app.normalizer import parse_date, clean_text, truncate, extract_cve_ids
from app.dedup import assign_hash
from app.scoring import score_item

_FEEDS = [
    {"name": "CERT-FR Alertes", "url": "https://www.cert.ssi.gouv.fr/alerte/feed/", "type": ItemType.ADVISORY},
    {"name": "CERT-FR Avis",    "url": "https://www.cert.ssi.gouv.fr/avis/feed/",   "type": ItemType.CERT},
    {"name": "CERT-FR IOC",     "url": "https://www.cert.ssi.gouv.fr/ioc/feed/",    "type": ItemType.INCIDENT},
]
SOURCE_NAME = "CERT-FR"


def _parse_feed(feed_url: str, feed_type: str, since: Optional[datetime]) -> list[CyberItem]:
    try:
        resp = requests.get(
            feed_url,
            headers={"User-Agent": config.HTTP_USER_AGENT},
            timeout=config.HTTP_TIMEOUT,
            proxies=config.PROXIES or None,
        )
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    except Exception as exc:
        log.error("[CERT-FR] Erreur parsing %s : %s", feed_url, exc)
        return []

    items: list[CyberItem] = []
    for entry in parsed.entries:
        published = parse_date(getattr(entry, "published", None) or getattr(entry, "updated", None))

        if since and published and published < since:
            continue

        title = clean_text(getattr(entry, "title", ""))
        url = getattr(entry, "link", "")
        summary_raw = getattr(entry, "summary", "") or getattr(entry, "description", "")
        summary = clean_text(summary_raw)

        # Extraction des CVE mentionnées
        cve_ids = extract_cve_ids(f"{title} {summary}")
        external_id = cve_ids[0] if cve_ids else ""

        tags = ["cert-fr"]
        if "alerte" in feed_url:
            tags.append("alerte")
        if "avis" in feed_url:
            tags.append("avis")

        item = CyberItem(
            source=SOURCE_NAME,
            external_id=external_id,
            title=title,
            url=url,
            summary=truncate(summary, 800),
            published_at=published,
            item_type=feed_type,
            tags=tags,
            extra_urls=cve_ids[:3],
        )
        item = assign_hash(item)
        item = score_item(item)
        items.append(item)

    return items


def fetch(since: Optional[datetime] = None) -> list[CyberItem]:
    if since is not None and since.tzinfo is not None:
        since = since.replace(tzinfo=None)
    log.info("[CERT-FR] Récupération des flux RSS...")
    all_items: list[CyberItem] = []
    for feed_def in _FEEDS:
        items = _parse_feed(feed_def["url"], feed_def["type"], since)
        log.info("[CERT-FR] %s : %d items", feed_def["name"], len(items))
        all_items.extend(items)
    log.info("[CERT-FR] Total : %d items", len(all_items))
    return all_items
