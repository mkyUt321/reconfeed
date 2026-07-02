"""Tag-level matching: for a batch of findings, decide which tags they match via keyword
dictionary and/or ATT&CK technique, and record it in finding_tag_matches.

Runs once per finding per daily job (only over the "touched" findings each fetcher returns),
not per user — a finding is matched against every tag in the system exactly once, and any
watchlist containing that tag picks it up at distribution time (see matching/distribute.py).
"""

import logging
import re
from collections import defaultdict

from sqlalchemy.orm import Session

from app.models import Finding, FindingSource, FindingTagMatch, TagAttackTechnique, TagKeyword

logger = logging.getLogger("reconfeed.matching.engine")


def build_haystack(finding: Finding) -> str:
    """Flatten title/summary/raw into one lowercase blob for keyword matching."""
    parts = [finding.title or "", finding.summary or ""]
    for value in (finding.raw or {}).values():
        if isinstance(value, list):
            parts.extend(str(v) for v in value)
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts).lower()


def compile_keyword_pattern(keyword: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(keyword.lower()) + r"\b")


def match_findings(db: Session, finding_ids: list[int]) -> int:
    """Match the given findings against every tag's keywords/ATT&CK techniques.

    Returns the number of new finding_tag_matches rows created (existing matches are left
    untouched, and re-matching an already-matched finding is a safe no-op).
    """
    if not finding_ids:
        return 0

    findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
    keywords = db.query(TagKeyword).all()
    techniques = db.query(TagAttackTechnique).all()

    keyword_patterns = [(kw, compile_keyword_pattern(kw.keyword)) for kw in keywords]
    technique_map: dict[str, list[TagAttackTechnique]] = defaultdict(list)
    for t in techniques:
        technique_map[t.attack_technique_id.upper()].append(t)

    existing = {
        (m.finding_id, m.tag_id, m.matched_keyword_id, m.matched_technique_id)
        for m in db.query(FindingTagMatch).filter(FindingTagMatch.finding_id.in_(finding_ids))
    }

    new_rows: list[FindingTagMatch] = []
    for finding in findings:
        haystack = build_haystack(finding)

        for kw, pattern in keyword_patterns:
            if pattern.search(haystack):
                key = (finding.id, kw.tag_id, kw.id, None)
                if key not in existing:
                    new_rows.append(
                        FindingTagMatch(finding_id=finding.id, tag_id=kw.tag_id, matched_keyword_id=kw.id)
                    )
                    existing.add(key)

        if finding.source == FindingSource.ATTACK:
            # tag_attack_techniques stores ATT&CK technique IDs (e.g. T1078), not CAPEC IDs.
            # CAPEC findings still get matched, just via the keyword pass above.
            for t in technique_map.get(finding.external_id.upper(), []):
                key = (finding.id, t.tag_id, None, t.id)
                if key not in existing:
                    new_rows.append(
                        FindingTagMatch(finding_id=finding.id, tag_id=t.tag_id, matched_technique_id=t.id)
                    )
                    existing.add(key)

    if new_rows:
        db.add_all(new_rows)
        db.commit()

    logger.info("matching: %d findings scanned, %d new tag matches", len(findings), len(new_rows))
    return len(new_rows)
