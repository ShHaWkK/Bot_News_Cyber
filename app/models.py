"""
Modèles de données Pydantic utilisés dans tout le projet.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ItemType(str, Enum):
    CVE = "CVE"
    KEV = "KEV"
    CERT = "CERT"
    NEWS = "NEWS"
    EXPLOIT = "EXPLOIT"
    PATCH = "PATCH"
    INCIDENT = "INCIDENT"
    ADVISORY = "ADVISORY"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"


class CyberItem(BaseModel):
    """Représente un élément de veille cybersécurité normalisé."""

    # Identifiants
    source: str
    external_id: str = ""          # CVE-ID, CERT ref, etc.
    dedup_hash: str = ""           # SHA256 pour déduplication

    # Contenu
    title: str
    url: str = ""
    summary: str = ""
    published_at: Optional[datetime] = None
    fetched_at: datetime = Field(default_factory=datetime.utcnow)

    # Classification
    item_type: ItemType = ItemType.NEWS
    severity: Severity = Severity.INFO

    # Scores
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    internal_score: float = 0.0

    # Contexte technique
    vendor: str = ""
    product: str = ""
    tags: list[str] = Field(default_factory=list)

    # Flags de criticité
    is_kev: bool = False                 # Présent dans CISA KEV
    is_actively_exploited: bool = False
    has_public_exploit: bool = False
    is_rce: bool = False
    is_auth_bypass: bool = False
    is_privilege_escalation: bool = False
    mentions_ransomware: bool = False
    patch_available: bool = False

    # Sources multiples (pour le formatage Telegram)
    extra_urls: list[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
