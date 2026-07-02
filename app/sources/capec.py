"""MITRE CAPEC attack patterns, from the official STIX bundle."""

import logging

from app.models import FindingSource
from app.sources._stix_common import fetch_bundle, process_attack_patterns

logger = logging.getLogger("reconfeed.sources.capec")

CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"


def fetch(db) -> list[int]:
    bundle = fetch_bundle(CAPEC_URL)
    touched = process_attack_patterns(db, bundle, FindingSource.CAPEC, "capec")
    logger.info("CAPEC: %d new/changed attack patterns", len(touched))
    return touched
