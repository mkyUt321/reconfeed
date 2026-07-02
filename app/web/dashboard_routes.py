from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth.security import require_user
from app.db import get_db
from app.matching.distribute import matched_findings_for_user, matched_tag_names_for_findings, user_watchlist_tag_ids
from app.models import FindingSource, Tag, User, Watchlist
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
    matched_tag_names = matched_tag_names_for_findings(db, user, finding_ids)

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
