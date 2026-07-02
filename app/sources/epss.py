"""FIRST.org EPSS bulk scores.

EPSS covers ~250k+ CVEs, far more than we track, and re-scores daily for all of them. Doing a
per-row upsert (like kev.py/nvd.py) would mean hundreds of thousands of round trips to Neon, so
instead we pull the set of CVE ids we already have in one query, filter the CSV down to that
set in Python, and apply the score updates in a single bulk_update_mappings call.

EPSS never creates new Finding rows and is intentionally excluded from the matching pipeline's
"touched" set — a score refresh on an already-matched/notified CVE shouldn't trigger a re-match
or re-notification. The current score is simply displayed live wherever a CVE finding is shown.
"""

import csv
import gzip
import logging

from app.models import Finding, FindingSource
from app.sources.base import http_client, retry_transient

logger = logging.getLogger("reconfeed.sources.epss")

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


@retry_transient
def _fetch_csv_rows() -> list[dict]:
    with http_client() as client:
        resp = client.get(EPSS_URL)
        resp.raise_for_status()
        raw = gzip.decompress(resp.content).decode("utf-8")

    lines = [line for line in raw.splitlines() if not line.startswith("#")]
    return list(csv.DictReader(lines))


def fetch(db) -> list[int]:
    rows = _fetch_csv_rows()

    existing = {
        f.external_id: (f.id, f.epss_score)
        for f in db.query(Finding.id, Finding.external_id, Finding.epss_score).filter(
            Finding.source == FindingSource.CVE
        )
    }

    updates = []
    for row in rows:
        cve_id = row.get("cve")
        if cve_id not in existing:
            continue
        finding_id, current_score = existing[cve_id]
        new_score = float(row["epss"])
        if current_score is None or abs(current_score - new_score) > 1e-6:
            updates.append({"id": finding_id, "epss_score": new_score})

    if updates:
        db.bulk_update_mappings(Finding, updates)
        db.commit()

    logger.info("EPSS: %d rows fetched, %d tracked CVEs updated", len(rows), len(updates))
    return []
