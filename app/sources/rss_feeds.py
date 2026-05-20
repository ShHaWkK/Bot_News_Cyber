"""
Source : Flux RSS cybersécurité multisources.
Parse tous les flux définis dans config.RSS_FEEDS.
"""

import time
from datetime import datetime
from typing import Optional

import feedparser
import requests

from app import config
from app.logger import log
from app.models import CyberItem, ItemType
from app.normalizer import parse_date, clean_text, truncate, extract_cve_ids
from app.dedup import assign_hash
from app.scoring import score_item


def _fetch_feed_content(url: str) -> bytes:
    """Télécharge le flux via requests pour une meilleure gestion des encodages."""
    resp = requests.get(
        url,
        headers={
            "User-Agent": config.HTTP_USER_AGENT,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        },
        timeout=config.HTTP_TIMEOUT,
        proxies=config.PROXIES or None,
    )
    resp.raise_for_status()
    return resp.content


def _parse_single_feed(
    name: str, url: str, since: Optional[datetime]
) -> list[CyberItem]:
    try:
        content = _fetch_feed_content(url)
        parsed = feedparser.parse(content)
    except Exception as exc:
        log.warning("[RSS:%s] Erreur fetch : %s", name, exc)
        return []

    if parsed.bozo and not parsed.entries:
        log.warning("[RSS:%s] Feed invalide ou inaccessible (bozo=%s)", name, parsed.bozo_exception)
        return []

    items: list[CyberItem] = []
    for entry in parsed.entries:
        published = parse_date(
            getattr(entry, "published", None)
            or getattr(entry, "updated", None)
            or getattr(entry, "created", None)
        )

        if since and published and published < since:
            continue

        title = clean_text(getattr(entry, "title", ""))
        if not title:
            continue

        url_item = getattr(entry, "link", "")
        summary_raw = (
            getattr(entry, "summary", "")
            or getattr(entry, "description", "")
            or getattr(entry, "content", [{}])[0].get("value", "")
        )
        summary = clean_text(summary_raw)

        cve_ids = extract_cve_ids(f"{title} {summary}")
        external_id = cve_ids[0] if cve_ids else ""

        item = CyberItem(
            source=name,
            external_id=external_id,
            title=title,
            url=url_item,
            summary=truncate(summary, 600),
            published_at=published,
            item_type=ItemType.NEWS,
            tags=["rss", name.lower().replace(" ", "-")],
        )
        item = assign_hash(item)
        item = score_item(item)
        items.append(item)

    return items


def fetch(since: Optional[datetime] = None) -> list[CyberItem]:
    log.info("[RSS] Récupération de %d flux...", len(config.RSS_FEEDS))
    all_items: list[CyberItem] = []

    for feed_def in config.RSS_FEEDS:
        name = feed_def["name"]
        url = feed_def["url"]
        try:
            items = _parse_single_feed(name, url, since)
            log.info("[RSS:%s] %d items", name, len(items))
            all_items.extend(items)
        except Exception as exc:
            log.error("[RSS:%s] Erreur inattendue : %s", name, exc)
        # Pause légère entre les requêtes
        time.sleep(0.5)

    log.info("[RSS] Total : %d items", len(all_items))
    return all_items
