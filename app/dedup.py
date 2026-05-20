"""
Moteur de déduplication.
Génère un hash SHA256 stable pour chaque item afin d'éviter les doublons.
"""

import hashlib
import re
from app.models import CyberItem


def _normalize(text: str) -> str:
    """Minuscule, supprime ponctuation et espaces superflus."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def compute_hash(item: CyberItem) -> str:
    """
    Calcule un hash de déduplication.
    Priorité : external_id (CVE-ID) > URL > titre normalisé.
    """
    if item.external_id and re.match(r"CVE-\d{4}-\d+", item.external_id, re.I):
        key = item.external_id.upper()
    elif item.url:
        # On retire les paramètres de tracking (?utm_...) pour stabiliser l'URL
        url_clean = re.sub(r"\?.*$", "", item.url.strip())
        key = url_clean
    else:
        key = _normalize(item.title)

    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def assign_hash(item: CyberItem) -> CyberItem:
    """Attribue le hash à l'item et le retourne (mutation in-place)."""
    item.dedup_hash = compute_hash(item)
    return item
