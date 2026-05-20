"""
Source : EPSS — Exploit Prediction Scoring System (FIRST.org)
https://www.first.org/epss/

Donne la probabilité qu'un CVE soit exploité dans les 30 prochains jours.
Score 0..1  (ex: 0.97 = 97% de probabilité d'exploitation)
Percentile : position relative parmi tous les CVEs connus.

API gratuite, pas d'authentification requise.
Batch jusqu'à plusieurs centaines de CVEs par requête.
"""

import time
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from app import config
from app.logger import log

_BASE_URL = "https://api.first.org/data/v1/epss"
_MAX_BATCH = 300   # limite pratique pour éviter les URLs trop longues


@retry(
    stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
    wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=2, max=30),
    reraise=True,
)
def _fetch_batch(cve_ids: list[str]) -> dict[str, dict]:
    """
    Récupère les scores EPSS pour une liste de CVE IDs.
    Retourne un dict { "CVE-XXXX-XXXX": {"epss": 0.97, "percentile": 0.999} }
    """
    params = {"cve": ",".join(cve_ids)}
    resp = requests.get(
        _BASE_URL,
        params=params,
        headers={"User-Agent": config.HTTP_USER_AGENT},
        timeout=config.HTTP_TIMEOUT,
        proxies=config.PROXIES or None,
    )
    resp.raise_for_status()
    data = resp.json()

    result: dict[str, dict] = {}
    for entry in data.get("data", []):
        cve = entry.get("cve", "").upper()
        if cve:
            result[cve] = {
                "epss":       float(entry.get("epss", 0)),
                "percentile": float(entry.get("percentile", 0)),
            }
    return result


def fetch_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Récupère les scores EPSS pour une liste de CVE IDs (avec batching automatique).
    Filtre les IDs non-CVE en entrée.
    """
    valid_ids = [c.upper() for c in cve_ids if c.upper().startswith("CVE-")]
    if not valid_ids:
        return {}

    results: dict[str, dict] = {}
    for i in range(0, len(valid_ids), _MAX_BATCH):
        batch = valid_ids[i : i + _MAX_BATCH]
        try:
            partial = _fetch_batch(batch)
            results.update(partial)
            if i + _MAX_BATCH < len(valid_ids):
                time.sleep(0.5)
        except Exception as exc:
            log.warning("[EPSS] Erreur batch %d-%d : %s", i, i + len(batch), exc)

    log.debug("[EPSS] %d/%d CVEs scorés", len(results), len(valid_ids))
    return results


def get_score(cve_id: str) -> Optional[dict]:
    """Raccourci pour un seul CVE."""
    scores = fetch_scores([cve_id])
    return scores.get(cve_id.upper())


def epss_label(score: float) -> str:
    """Libellé lisible du score EPSS."""
    if score >= 0.90:
        return f"🔥 {score*100:.1f}% (exploitation quasi-certaine)"
    if score >= 0.50:
        return f"🚨 {score*100:.1f}% (très probable)"
    if score >= 0.20:
        return f"⚠️ {score*100:.1f}% (probable)"
    if score >= 0.05:
        return f"🟡 {score*100:.1f}% (possible)"
    return f"🟢 {score*100:.2f}% (peu probable)"
