"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Single JSON file, no auth, no pagination — small enough (~1500 entries) to refetch in full
each run. Each entry becomes its own Finding(source=KEV) (so "added to KEV" is itself a
matchable, notify-worthy event) and also flips is_kev=True on the sibling CVE finding, if we
already have one, purely for accurate dashboard display.
"""

import logging
from datetime import datetime, timezone

from app.models import Finding, FindingSource
from app.sources.base import http_client, retry_transient, upsert_finding

logger = logging.getLogger("reconfeed.sources.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@retry_transient
def _fetch_catalog() -> dict:
    with http_client() as client:
        resp = client.get(KEV_URL)
        resp.raise_for_status()
        return resp.json()


def fetch(db) -> list[int]:
    catalog = _fetch_catalog()
    touched: list[int] = []

    for vuln in catalog.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue

        published_at = None
        if vuln.get("dateAdded"):
            published_at = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)

        finding, changed = upsert_finding(
            db,
            FindingSource.KEV,
            cve_id,
            title=vuln.get("vulnerabilityName") or cve_id,
            summary=vuln.get("shortDescription") or "",
            is_kev=True,
            raw_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            published_at=published_at,
            raw={
                "vendor_project": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "required_action": vuln.get("requiredAction"),
                "due_date": vuln.get("dueDate"),
                "known_ransomware_campaign_use": vuln.get("knownRansomwareCampaignUse"),
                "notes": vuln.get("notes"),
            },
        )
        if changed:
            touched.append(finding.id)

        cve_finding = (
            db.query(Finding).filter(Finding.source == FindingSource.CVE, Finding.external_id == cve_id).first()
        )
        if cve_finding is not None and not cve_finding.is_kev:
            cve_finding.is_kev = True

    db.commit()
    logger.info("KEV: %d entries processed, %d new/changed", len(catalog.get("vulnerabilities", [])), len(touched))
    return touched
