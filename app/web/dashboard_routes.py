from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth.security import require_user
from app.db import get_db
from app.matching.distribute import matched_findings_for_user, user_watchlist_tag_ids
from app.models import Finding, FindingSource, FindingTagMatch, Tag, User, Watchlist
from app.web.templating import templates

router = APIRouter()


@router.get("/dashboard")
def dashboard(
    request: Request,
    watchlist_id: int | None = None,
    tag_id: int | None = None,
    source: str | None = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    source_enum = None
    if source:
        try:
            source_enum = FindingSource(source)
        except ValueError:
            source_enum = None

    findings = matched_findings_for_user(
        db, user, watchlist_id=watchlist_id, tag_id=tag_id, source=source_enum
    )

    finding_ids = [f.id for f in findings]
    matched_tag_names = _matched_tag_names(db, user, finding_ids) if finding_ids else {}

    watchlists = db.query(Watchlist).filter(Watchlist.user_id == user.id).order_by(Watchlist.name).all()
    all_tag_ids = user_watchlist_tag_ids(db, user)
    tags = (
        db.query(Tag).filter(Tag.id.in_(all_tag_ids)).order_by(Tag.name).all() if all_tag_ids else []
    )

    return templates.TemplateResponse(
        request,
        "dashboard/list.html",
        {
            "user": user,
            "findings": findings,
            "matched_tag_names": matched_tag_names,
            "watchlists": watchlists,
            "tags": tags,
            "sources": list(FindingSource),
            "selected_watchlist_id": watchlist_id,
            "selected_tag_id": tag_id,
            "selected_source": source,
        },
    )


def _matched_tag_names(db: Session, user: User, finding_ids: list[int]) -> dict[int, list[str]]:
    """finding_id -> sorted list of matched tag names, for display. Reuses the same
    ownership-scoped filter as the main query so we don't leak a tag name the user
    wouldn't otherwise see."""
    from app.matching.distribute import _ownership_scoped_query

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
