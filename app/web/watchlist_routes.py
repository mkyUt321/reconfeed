from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.auth.security import require_user
from app.db import get_db
from app.models import Tag, User, Watchlist
from app.web.tag_routes import visible_tags_for
from app.web.templating import templates

router = APIRouter()


def _owned_watchlist_or_404(watchlist_id: int, user: User, db: Session) -> Watchlist:
    wl = (
        db.query(Watchlist)
        .options(selectinload(Watchlist.tags))
        .filter(Watchlist.id == watchlist_id, Watchlist.user_id == user.id)
        .first()
    )
    if wl is None:
        raise HTTPException(status_code=404)
    return wl


@router.get("/watchlists")
def list_watchlists(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    watchlists = (
        db.query(Watchlist)
        .options(selectinload(Watchlist.tags))
        .filter(Watchlist.user_id == user.id)
        .order_by(Watchlist.name)
        .all()
    )
    return templates.TemplateResponse(request, "watchlists/list.html", {"user": user, "watchlists": watchlists})


@router.get("/watchlists/new")
def new_watchlist_form(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    tags = visible_tags_for(user, db)
    return templates.TemplateResponse(
        request, "watchlists/form.html", {"user": user, "tags": tags, "watchlist": None, "selected_ids": set()}
    )


@router.post("/watchlists")
def create_watchlist(
    request: Request,
    name: str = Form(...),
    tag_ids: list[int] = Form(default=[]),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="ウォッチリスト名は必須です。")

    wl = Watchlist(user_id=user.id, name=name)
    if tag_ids:
        wl.tags = (
            db.query(Tag)
            .filter(Tag.id.in_(tag_ids))
            .filter((Tag.is_preset.is_(True)) | (Tag.created_by_user_id == user.id))
            .all()
        )
    db.add(wl)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        tags = visible_tags_for(user, db)
        return templates.TemplateResponse(
            request,
            "watchlists/form.html",
            {
                "user": user,
                "tags": tags,
                "watchlist": None,
                "selected_ids": set(tag_ids),
                "error": "同じ名前のウォッチリストが既に存在します。",
            },
            status_code=400,
        )
    return RedirectResponse("/watchlists", status_code=303)


@router.get("/watchlists/{watchlist_id}/edit")
def edit_watchlist_form(
    request: Request, watchlist_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    wl = _owned_watchlist_or_404(watchlist_id, user, db)
    tags = visible_tags_for(user, db)
    selected_ids = {t.id for t in wl.tags}
    return templates.TemplateResponse(
        request,
        "watchlists/form.html",
        {"user": user, "tags": tags, "watchlist": wl, "selected_ids": selected_ids},
    )


@router.post("/watchlists/{watchlist_id}/edit")
def update_watchlist(
    request: Request,
    watchlist_id: int,
    name: str = Form(...),
    tag_ids: list[int] = Form(default=[]),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    wl = _owned_watchlist_or_404(watchlist_id, user, db)
    name = name.strip()
    if name:
        wl.name = name
    wl.tags = (
        db.query(Tag)
        .filter(Tag.id.in_(tag_ids))
        .filter((Tag.is_preset.is_(True)) | (Tag.created_by_user_id == user.id))
        .all()
        if tag_ids
        else []
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        tags = visible_tags_for(user, db)
        return templates.TemplateResponse(
            request,
            "watchlists/form.html",
            {
                "user": user,
                "tags": tags,
                "watchlist": wl,
                "selected_ids": set(tag_ids),
                "error": "同じ名前のウォッチリストが既に存在します。",
            },
            status_code=400,
        )
    return RedirectResponse("/watchlists", status_code=303)


@router.post("/watchlists/{watchlist_id}/delete")
def delete_watchlist(watchlist_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    wl = _owned_watchlist_or_404(watchlist_id, user, db)
    db.delete(wl)
    db.commit()
    return RedirectResponse("/watchlists", status_code=303)
