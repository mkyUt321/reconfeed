"""Per-user distribution: given the tag matches computed by matching/engine.py, figure out
which findings a specific user should be notified about.

Two filters apply here rather than at match time, because they're per-user, not per-tag:

1. Keyword-ownership scoping: a match via a keyword/technique the user didn't add themselves
   only counts if that keyword/technique is a preset. A match via another user's custom
   addition to a shared preset tag never surfaces for anyone but that user.
2. CVSS attack-vector filter: optional, per-user, applied only to findings that actually carry
   a CVSS vector (ATT&CK/CAPEC/GHSA-without-CVSS/PoC findings pass through untouched).
"""

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.models import Finding, FindingTagMatch, NotificationSent, TagAttackTechnique, TagKeyword, User, Watchlist


_AV_CODE_TO_NAME = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}


def _cvss_attack_vector(vector: str | None) -> str | None:
    """Extract the Attack Vector as a full name (NETWORK/ADJACENT_NETWORK/LOCAL/PHYSICAL) to
    match the vocabulary used in users.cvss_allowed_attack_vectors and the settings UI."""
    if not vector:
        return None
    for part in vector.split("/"):
        if part.startswith("AV:"):
            return _AV_CODE_TO_NAME.get(part[3:])
    return None


def pending_findings_for_user(db: Session, user: User) -> list[Finding]:
    """Findings matching this user's watchlists, ownership-scoped, CVSS-filtered, not yet
    recorded in notifications_sent. Doesn't mark anything as notified — call mark_notified()
    after the caller has actually delivered the notification."""
    watchlist_tag_ids = {
        tag.id for wl in db.query(Watchlist).filter(Watchlist.user_id == user.id) for tag in wl.tags
    }
    if not watchlist_tag_ids:
        return []

    already_notified = db.query(NotificationSent.finding_id).filter(NotificationSent.user_id == user.id)

    query = (
        db.query(Finding)
        .join(FindingTagMatch, FindingTagMatch.finding_id == Finding.id)
        .outerjoin(TagKeyword, FindingTagMatch.matched_keyword_id == TagKeyword.id)
        .outerjoin(TagAttackTechnique, FindingTagMatch.matched_technique_id == TagAttackTechnique.id)
        .filter(FindingTagMatch.tag_id.in_(watchlist_tag_ids))
        .filter(
            or_(
                and_(
                    FindingTagMatch.matched_keyword_id.isnot(None),
                    or_(TagKeyword.is_preset.is_(True), TagKeyword.created_by_user_id == user.id),
                ),
                and_(
                    FindingTagMatch.matched_technique_id.isnot(None),
                    or_(TagAttackTechnique.is_preset.is_(True), TagAttackTechnique.created_by_user_id == user.id),
                ),
            )
        )
        .filter(~Finding.id.in_(already_notified))
        .distinct()
    )

    findings = query.all()

    if user.cvss_filter_enabled and user.cvss_allowed_attack_vectors:
        allowed = {v.strip().upper() for v in user.cvss_allowed_attack_vectors.split(",") if v.strip()}
        findings = [f for f in findings if _cvss_attack_vector(f.cvss_vector) is None or _cvss_attack_vector(f.cvss_vector) in allowed]

    return findings


def mark_notified(db: Session, user: User, findings: list[Finding]) -> None:
    for f in findings:
        db.add(NotificationSent(user_id=user.id, finding_id=f.id))
    db.commit()
