"""MITRE ATT&CK Enterprise techniques, from the official STIX bundle."""

import logging

from app.models import FindingSource
from app.sources._stix_common import fetch_bundle, process_attack_patterns

logger = logging.getLogger("reconfeed.sources.attack")

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def fetch(db) -> list[int]:
    bundle = fetch_bundle(ATTACK_URL)
    touched = process_attack_patterns(db, bundle, FindingSource.ATTACK, "mitre-attack")
    logger.info("ATT&CK: %d new/changed techniques", len(touched))
    return touched
