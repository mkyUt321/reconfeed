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
from sqlalchemy.orm import Query, Session

from app.models import (
    Finding,
    FindingSource,
    FindingTagMatch,
    NotificationSent,
    Tag,
    TagAttackTechnique,
    TagKeyword,
    User,
    Watchlist,
)


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


def _apply_cvss_filter(user: User, findings: list[Finding]) -> list[Finding]:
    if not (user.cvss_filter_enabled and user.cvss_allowed_attack_vectors):
        return findings
    allowed = {v.strip().upper() for v in user.cvss_allowed_attack_vectors.split(",") if v.strip()}
    return [f for f in findings if _cvss_attack_vector(f.cvss_vector) is None or _cvss_attack_vector(f.cvss_vector) in allowed]


def _ownership_scoped_query(db: Session, user: User, tag_ids: set[int]) -> Query:
    """Findings matched (via tag_ids) under this user's keyword-ownership scope: a match only
    counts if the keyword/technique that triggered it is a preset or was added by this user."""
    return (
        db.query(Finding)
        .join(FindingTagMatch, FindingTagMatch.finding_id == Finding.id)
        .outerjoin(TagKeyword, FindingTagMatch.matched_keyword_id == TagKeyword.id)
        .outerjoin(TagAttackTechnique, FindingTagMatch.matched_technique_id == TagAttackTechnique.id)
        .filter(FindingTagMatch.tag_id.in_(tag_ids))
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
    )


def user_watchlist_tag_ids(db: Session, user: User, watchlist_id: int | None = None) -> set[int]:
    query = db.query(Watchlist).filter(Watchlist.user_id == user.id)
    if watchlist_id is not None:
        query = query.filter(Watchlist.id == watchlist_id)
    return {tag.id for wl in query for tag in wl.tags}


def pending_findings_for_user(db: Session, user: User) -> list[Finding]:
    """Findings matching this user's watchlists, ownership-scoped, CVSS-filtered, not yet
    recorded in notifications_sent. Doesn't mark anything as notified — call mark_notified()
    after the caller has actually delivered the notification."""
    tag_ids = user_watchlist_tag_ids(db, user)
    if not tag_ids:
        return []

    already_notified = db.query(NotificationSent.finding_id).filter(NotificationSent.user_id == user.id)
    findings = (
        _ownership_scoped_query(db, user, tag_ids).filter(~Finding.id.in_(already_notified)).distinct().all()
    )
    return _apply_cvss_filter(user, findings)


def matched_findings_for_user(
    db: Session,
    user: User,
    watchlist_id: int | None = None,
    tag_id: int | None = None,
    source: FindingSource | None = None,
    limit: int = 200,
) -> list[Finding]:
    """Browsing view for the dashboard: every ownership-scoped match for this user (regardless
    of notification status), optionally narrowed to one watchlist, one tag, and/or one source."""
    tag_ids = user_watchlist_tag_ids(db, user, watchlist_id)
    if tag_id is not None:
        tag_ids &= {tag_id}
    if not tag_ids:
        return []

    query = _ownership_scoped_query(db, user, tag_ids)
    if source is not None:
        query = query.filter(Finding.source == source)

    findings = (
        query.distinct()
        .order_by(Finding.published_at.desc().nullslast(), Finding.fetched_at.desc())
        .limit(limit)
        .all()
    )
    return _apply_cvss_filter(user, findings)


def mark_notified(db: Session, user: User, findings: list[Finding]) -> None:
    for f in findings:
        db.add(NotificationSent(user_id=user.id, finding_id=f.id))
    db.commit()


def matched_tag_names_for_findings(db: Session, user: User, finding_ids: list[int]) -> dict[int, list[str]]:
    """finding_id -> sorted list of matched tag names, respecting this user's ownership scope
    (so we never display a tag name a user shouldn't be able to see)."""
    tag_ids = user_watchlist_tag_ids(db, user)
    if not tag_ids or not finding_ids:
        return {}

    rows = (
        _ownership_scoped_query(db, user, tag_ids)
        .join(Tag, Tag.id == FindingTagMatch.tag_id)
        .filter(Finding.id.in_(finding_ids))
        .with_entities(Finding.id, Tag.name)
        .distinct()
        .all()
    )
    result: dict[int, list[str]] = {}
    for finding_id, tag_name in rows:
        result.setdefault(finding_id, []).append(tag_name)
    for k in result:
        result[k].sort()
    return result
