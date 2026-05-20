"""
Pipeline d'enrichissement CVE.

Pour chaque item contenant un CVE ID :
1. Vérifie si les données NVD sont déjà connues
2. Fetche NVD si CVSS manquant
3. Fetche EPSS (batch pour tous les CVEs d'un cycle)
4. Détecte la watchlist
5. Re-score avec les données enrichies
"""

import re
import time
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from app import config, database as db
from app.logger import log
from app.models import CyberItem
from app.normalizer import clean_text, truncate, parse_date
from app.sources.epss import fetch_scores as fetch_epss

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE   = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


#  Watchlist 

def _on_watchlist(item: CyberItem) -> bool:
    corpus = f"{item.title} {item.summary} {item.vendor} {item.product}".lower()
    for v in config.WATCH_VENDORS:
        if v and v in corpus:
            return True
    for p in config.WATCH_PRODUCTS:
        if p and p in corpus:
            return True
    return False


#  NVD single CVE lookup 

@retry(
    stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
    wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=3, max=60),
    reraise=True,
)
def _nvd_fetch_cve(cve_id: str) -> Optional[dict]:
    headers = {"User-Agent": config.HTTP_USER_AGENT}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY
    resp = requests.get(
        _NVD_BASE,
        params={"cveId": cve_id},
        headers=headers,
        timeout=config.HTTP_TIMEOUT,
        proxies=config.PROXIES or None,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None


def _parse_cvss(cve_data: dict) -> tuple[Optional[float], Optional[str], Optional[str]]:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0].get("cvssData", {})
            score   = d.get("baseScore")
            version = d.get("version")
            vector  = d.get("vectorString")
            if score is not None:
                return float(score), str(version), vector
    return None, None, None


def _parse_affected(cve_data: dict) -> tuple[str, str, str, str]:
    """Retourne (vendor, product, affected_versions, fixed_versions)."""
    vendor, product = "", ""
    affected_v, fixed_v = [], []
    configs = cve_data.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor  = vendor  or parts[3].replace("_", " ").title()
                    product = product or parts[4].replace("_", " ").title()
                if match.get("vulnerable"):
                    vi = match.get("versionStartIncluding", "")
                    ve = match.get("versionEndExcluding", "")
                    if vi:
                        affected_v.append(f">= {vi}")
                    if ve:
                        fixed_v.append(f"< {ve} (fix)")
    return (
        vendor,
        product,
        ", ".join(affected_v[:3]),
        ", ".join(fixed_v[:3]),
    )


#  Enrichissement d'un item 

def enrich_item(item: CyberItem) -> CyberItem:
    """
    Tente d'enrichir un item avec les données NVD.
    N'appelle pas NVD si le CVE n'est pas identifié ou si CVSS déjà connu.
    """
    cve_id = item.external_id.upper() if item.external_id else ""
    if not cve_id or not cve_id.startswith("CVE-"):
        return item
    if item.cvss_score is not None:
        return item  # déjà enrichi

    if not config.ENRICH_CVE:
        return item

    # Rate-limit NVD : 6.5s sans clé, 0.7s avec clé
    delay = 0.7 if config.NVD_API_KEY else 6.5
    time.sleep(delay)

    try:
        cve_data = _nvd_fetch_cve(cve_id)
    except Exception as exc:
        log.debug("[Enricher] NVD erreur pour %s : %s", cve_id, exc)
        return item

    if not cve_data:
        return item

    cvss_score, cvss_version, cvss_vector = _parse_cvss(cve_data)
    vendor, product, affected_v, fixed_v = _parse_affected(cve_data)

    # Description
    descs = cve_data.get("descriptions", [])
    desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    if desc_en and not item.summary:
        item.summary = truncate(clean_text(desc_en), 800)

    # Références
    refs = [r["url"] for r in cve_data.get("references", [])[:5] if r.get("url")]
    for r in refs:
        if r not in item.extra_urls:
            item.extra_urls.append(r)

    # Mise à jour des champs
    if cvss_score is not None:
        item.cvss_score   = cvss_score
        item.cvss_version = cvss_version
        item.cvss_vector  = cvss_vector
    if vendor and not item.vendor:
        item.vendor = vendor
    if product and not item.product:
        item.product = product
    if affected_v:
        item.affected_versions = affected_v
    if fixed_v:
        item.fixed_versions = fixed_v
        item.patch_available = True

    item.enriched = True
    return item


#  Enrichissement EPSS batch 

def enrich_epss_batch(items: list[CyberItem]) -> list[CyberItem]:
    """
    Enrichit tous les items ayant un CVE ID avec les scores EPSS.
    Un seul appel API pour tout le lot.
    """
    if not config.ENRICH_EPSS:
        return items

    cve_ids = list({
        i.external_id.upper()
        for i in items
        if i.external_id and i.external_id.upper().startswith("CVE-")
        and i.epss_score is None
    })
    if not cve_ids:
        return items

    try:
        scores = fetch_epss(cve_ids)
    except Exception as exc:
        log.warning("[Enricher] EPSS batch erreur : %s", exc)
        return items

    for item in items:
        if not item.external_id:
            continue
        cid = item.external_id.upper()
        if cid in scores:
            item.epss_score       = scores[cid]["epss"]
            item.epss_percentile  = scores[cid]["percentile"]

    log.debug("[Enricher] EPSS : %d CVEs enrichis", len(scores))
    return items


#  Watchlist check 

def apply_watchlist(items: list[CyberItem]) -> list[CyberItem]:
    if not config.WATCH_VENDORS and not config.WATCH_PRODUCTS:
        return items
    for item in items:
        item.on_watchlist = _on_watchlist(item)
    return items


#  Pipeline complet 

def run_pipeline(items: list[CyberItem]) -> list[CyberItem]:
    """
    Pipeline d'enrichissement complet à appliquer après fetch, avant insert.
    1. EPSS batch (un seul appel API)
    2. NVD individuel pour les CVEs sans CVSS
    3. Watchlist
    4. Re-score
    """
    from app.scoring import score_item
    from app.dedup import assign_hash

    # 1. EPSS en lot (une seule requête)
    items = enrich_epss_batch(items)

    # 2. NVD individuel (seulement si CVSS manquant)
    enriched_count = 0
    for i, item in enumerate(items):
        if (
            item.external_id
            and item.external_id.upper().startswith("CVE-")
            and item.cvss_score is None
        ):
            items[i] = enrich_item(item)
            if items[i].enriched:
                enriched_count += 1

    # 3. Watchlist
    items = apply_watchlist(items)

    # 4. Re-score avec les données enrichies + recalcul hash
    for i, item in enumerate(items):
        items[i] = score_item(item)
        if not item.dedup_hash:
            items[i] = assign_hash(item)

    if enriched_count:
        log.info("[Enricher] %d items enrichis via NVD", enriched_count)

    return items


#  Enrichissement différé (items déjà en BDD) 

def enrich_pending_in_db(limit: int = 30) -> int:
    """
    Enrichit les items en BDD qui n'ont pas encore de CVSS/EPSS.
    Appelé périodiquement par le scheduler.
    Retourne le nombre d'items enrichis.
    """
    from app.scoring import score_item

    rows = db.get_unenriched_cves(limit=limit)
    if not rows:
        return 0

    # EPSS batch d'abord
    cve_ids = [r["external_id"] for r in rows if r["external_id"].startswith("CVE-")]
    epss_scores: dict = {}
    if cve_ids and config.ENRICH_EPSS:
        try:
            epss_scores = fetch_epss(cve_ids)
        except Exception as exc:
            log.warning("[Enricher] EPSS pending erreur : %s", exc)

    enriched = 0
    for row in rows:
        # Reconstituer un CyberItem depuis la row
        import json
        item = CyberItem(
            source=row["source"],
            external_id=row["external_id"] or "",
            title=row["title"],
            url=row["url"] or "",
            summary=row["summary"] or "",
            published_at=row["published_at"],
            item_type=row["item_type"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            vendor=row["vendor"] or "",
            product=row["product"] or "",
            extra_urls=json.loads(row["extra_urls"] or "[]"),
            is_kev=bool(row["is_kev"]),
            is_actively_exploited=bool(row["is_actively_exploited"]),
            has_public_exploit=bool(row["has_public_exploit"]),
            is_rce=bool(row["is_rce"]),
            patch_available=bool(row["patch_available"]),
            on_watchlist=bool(row["on_watchlist"]),
        )

        # EPSS
        cid = item.external_id.upper()
        if cid in epss_scores:
            item.epss_score      = epss_scores[cid]["epss"]
            item.epss_percentile = epss_scores[cid]["percentile"]

        # NVD si CVSS manquant
        if item.cvss_score is None and item.external_id.startswith("CVE-"):
            item = enrich_item(item)

        # Watchlist
        item.on_watchlist = _on_watchlist(item)

        # Re-score
        item = score_item(item)
        item.enriched = True

        # Mise à jour BDD
        db.update_item_enrichment(row["id"], item)
        enriched += 1

    log.info("[Enricher] %d items en BDD enrichis", enriched)
    return enriched
