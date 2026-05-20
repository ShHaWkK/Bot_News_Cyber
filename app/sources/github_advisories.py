"""
Source : GitHub Security Advisories (GHSA).
Utilise l'API GraphQL GitHub (authentification optionnelle mais recommandée).
Sans token, limité à 60 req/h.
"""

from datetime import datetime
from typing import Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from app import config
from app.logger import log
from app.models import CyberItem, ItemType
from app.normalizer import parse_date, clean_text, truncate
from app.dedup import assign_hash
from app.scoring import score_item

_GRAPHQL_URL = "https://api.github.com/graphql"
_REST_URL = "https://api.github.com/advisories"
SOURCE_NAME = "GitHub-GHSA"

_QUERY = """
query($after: String, $publishedSince: DateTime) {
  securityAdvisories(
    first: 100
    after: $after
    publishedSince: $publishedSince
    orderBy: {field: PUBLISHED_AT, direction: DESC}
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cvss { score vectorString }
      cwes(first: 5) { nodes { cweId name } }
      identifiers { type value }
      references { url }
      vulnerabilities(first: 5) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""


@retry(stop=stop_after_attempt(config.HTTP_MAX_RETRIES),
       wait=wait_exponential(multiplier=config.HTTP_RETRY_BACKOFF, min=2, max=60),
       reraise=True)
def _graphql(after: Optional[str], published_since: str) -> dict:
    headers = {
        "User-Agent": config.HTTP_USER_AGENT,
        "Content-Type": "application/json",
    }
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    payload = {
        "query": _QUERY,
        "variables": {
            "after": after,
            "publishedSince": published_since,
        },
    }
    resp = requests.post(
        _GRAPHQL_URL,
        json=payload,
        headers=headers,
        timeout=config.HTTP_TIMEOUT,
        proxies=config.PROXIES or None,
    )
    resp.raise_for_status()
    return resp.json()


def _severity_map(sev: str) -> str:
    return {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "LOW": "INFO",
    }.get(sev.upper(), "INFO")


def _parse_node(node: dict) -> Optional[CyberItem]:
    ghsa_id = node.get("ghsaId", "")
    summary = clean_text(node.get("summary", ""))
    description = clean_text(node.get("description", ""))
    published = parse_date(node.get("publishedAt"))

    # CVE ID si disponible
    cve_id = ""
    for ident in node.get("identifiers", []):
        if ident.get("type") == "CVE":
            cve_id = ident.get("value", "")
            break

    cvss_score = None
    cvss_data = node.get("cvss", {})
    if cvss_data and cvss_data.get("score"):
        cvss_score = float(cvss_data["score"])

    refs = [r["url"] for r in node.get("references", [])[:5] if r.get("url")]
    ghsa_url = f"https://github.com/advisories/{ghsa_id}"
    if ghsa_url not in refs:
        refs.insert(0, ghsa_url)

    tags = ["ghsa"]
    for cwe in node.get("cwes", {}).get("nodes", []):
        tags.append(cwe.get("cweId", ""))

    # Produits concernés
    vulns = node.get("vulnerabilities", {}).get("nodes", [])
    products = []
    patch_available = False
    for v in vulns:
        pkg = v.get("package", {})
        if pkg.get("name"):
            products.append(pkg["name"])
        if v.get("firstPatchedVersion", {}).get("identifier"):
            patch_available = True

    product = ", ".join(products[:3])
    full_summary = f"{summary}\n\n{description}" if description else summary

    item = CyberItem(
        source=SOURCE_NAME,
        external_id=cve_id or ghsa_id,
        title=f"{cve_id or ghsa_id} — {summary[:100]}" if summary else (cve_id or ghsa_id),
        url=ghsa_url,
        summary=truncate(full_summary, 800),
        published_at=published,
        item_type=ItemType.CVE,
        cvss_score=cvss_score,
        product=product,
        tags=tags[:10],
        extra_urls=refs[:5],
        patch_available=patch_available,
    )
    item = assign_hash(item)
    item = score_item(item)
    return item


def fetch(since: Optional[datetime] = None) -> list[CyberItem]:
    if not config.GITHUB_TOKEN:
        log.info("[GitHub-GHSA] Pas de GITHUB_TOKEN — utilisation de l'API publique (limite 60 req/h)")

    from datetime import timedelta
    if since is None:
        since = datetime.utcnow() - timedelta(days=7)

    published_since = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    log.info("[GitHub-GHSA] Récupération depuis %s", since.strftime("%Y-%m-%d"))

    items: list[CyberItem] = []
    after = None

    while True:
        try:
            data = _graphql(after, published_since)
        except Exception as exc:
            log.error("[GitHub-GHSA] Erreur GraphQL : %s", exc)
            break

        errors = data.get("errors")
        if errors:
            log.error("[GitHub-GHSA] Erreurs GraphQL : %s", errors)
            break

        sa = data.get("data", {}).get("securityAdvisories", {})
        nodes = sa.get("nodes", [])
        page_info = sa.get("pageInfo", {})

        for node in nodes:
            item = _parse_node(node)
            if item:
                items.append(item)

        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")

    log.info("[GitHub-GHSA] %d advisories récupérés", len(items))
    return items
