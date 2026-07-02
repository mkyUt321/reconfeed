"""Shared STIX-bundle handling for attack.py and capec.py.

Both MITRE ATT&CK and CAPEC ship their catalog as a single STIX 2.1 bundle where each technique
/ attack pattern is an `attack-pattern` object. We refetch the whole bundle every run (no
incremental cursor) and rely on upsert_finding's field-level diffing — since we stash the STIX
`modified` timestamp inside `raw`, any content or metadata change makes the stored raw dict
differ, which is exactly what "detect new/updated by modified" means here.
"""

import logging
from datetime import datetime

from app.models import FindingSource
from app.sources.base import http_client, retry_transient, upsert_finding

logger = logging.getLogger("reconfeed.sources.stix")


@retry_transient
def fetch_bundle(url: str) -> dict:
    with http_client() as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


def process_attack_patterns(db, bundle: dict, source: FindingSource, external_source_name: str) -> list[int]:
    touched: list[int] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        external_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == external_source_name and ref.get("external_id"):
                external_id = ref["external_id"]
                url = ref.get("url")
                break
        if external_id is None:
            continue

        tactics = sorted(
            {
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") in ("mitre-attack", "mitre-capec")
            }
        )

        published_at = None
        if obj.get("created"):
            published_at = datetime.fromisoformat(obj["created"].replace("Z", "+00:00"))

        finding, changed = upsert_finding(
            db,
            source,
            external_id,
            title=f"{external_id}: {obj.get('name', '')}",
            summary=obj.get("description") or "",
            raw_url=url,
            published_at=published_at,
            raw={
                "modified": obj.get("modified"),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
            },
        )
        if changed:
            touched.append(finding.id)

    db.commit()
    return touched
