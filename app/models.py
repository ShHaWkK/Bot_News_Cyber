"""
Modèles de données Pydantic — v2.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ItemType(str, Enum):
    CVE       = "CVE"
    KEV       = "KEV"
    CERT      = "CERT"
    NEWS      = "NEWS"
    EXPLOIT   = "EXPLOIT"
    PATCH     = "PATCH"
    INCIDENT  = "INCIDENT"
    ADVISORY  = "ADVISORY"


class Severity(str, Enum):
    CRITICAL  = "CRITICAL"
    HIGH      = "HIGH"
    MEDIUM    = "MEDIUM"
    INFO      = "INFO"


class CyberItem(BaseModel):
    #  Identifiants 
    source: str
    external_id: str = ""       # CVE-XXXX-XXXX, GHSA-XXX, CERTFR-XXX
    dedup_hash: str  = ""       # SHA256

    #  Contenu 
    title: str
    url: str         = ""
    summary: str     = ""
    published_at: Optional[datetime] = None
    fetched_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    #  Classification 
    item_type: ItemType = ItemType.NEWS
    severity: Severity  = Severity.INFO

    #  Scores 
    cvss_score: Optional[float]    = None
    cvss_version: Optional[str]    = None
    cvss_vector: Optional[str]     = None   # ex: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    epss_score: Optional[float]    = None   # probabilité d'exploitation 0..1
    epss_percentile: Optional[float] = None # percentile parmi tous les CVEs
    internal_score: float          = 0.0

    #  Contexte technique 
    vendor: str          = ""
    product: str         = ""
    affected_versions: str = ""
    fixed_versions: str  = ""
    tags: list[str]      = Field(default_factory=list)

    #  Flags criticité 
    is_kev: bool                 = False
    is_actively_exploited: bool  = False
    has_public_exploit: bool     = False
    is_rce: bool                 = False
    is_auth_bypass: bool         = False
    is_privilege_escalation: bool = False
    is_sqli: bool                = False
    is_ssrf: bool                = False
    is_xxe: bool                 = False
    mentions_ransomware: bool    = False
    patch_available: bool        = False
    workaround_available: bool   = False
    internet_exposed: bool       = False
    on_watchlist: bool           = False    # produit dans la watchlist utilisateur

    #  Multi-sources 
    extra_urls: list[str]        = Field(default_factory=list)
    source_names: list[str]      = Field(default_factory=list)  # toutes les sources qui ont vu cet item

    #  Enrichissement 
    enriched: bool = False  # True si NVD/EPSS ont été consultés

    class Config:
        use_enum_values = True
