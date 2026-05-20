"""
Normalisation des items bruts provenant de sources hétérogènes.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as dateutil_parser


def parse_date(raw: Optional[str]) -> Optional[datetime]:
    """Parse une date quelconque en datetime UTC. Retourne None si impossible."""
    if not raw:
        return None
    try:
        dt = dateutil_parser.parse(str(raw))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        return None


def clean_text(text: str) -> str:
    """Supprime les balises HTML basiques et normalise les espaces."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"&#?\w+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def truncate(text: str, max_len: int = 800) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len].rsplit(" ", 1)[0] + "…"


def extract_cve_ids(text: str) -> list[str]:
    return re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)


def extract_vendor_product(title: str, summary: str) -> tuple[str, str]:
    """
    Heuristique simple : tente d'identifier vendor/product depuis le texte.
    Les sources spécialisées (NVD, CISA) surécrivent cette valeur.
    """
    from app import config
    corpus = f"{title} {summary}".lower()
    for product in config.SENSITIVE_PRODUCTS:
        if product in corpus:
            # Retourne le premier match comme produit, vendor vide (la source le précise)
            return "", product.title()
    return "", ""
