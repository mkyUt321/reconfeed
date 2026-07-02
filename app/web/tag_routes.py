import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session, selectinload

from app.auth.security import require_user
from app.db import get_db
from app.models import Tag, TagAttackTechnique, TagKeyword, User
from app.web.templating import templates

router = APIRouter()

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def _visible_tag_or_404(tag_id: int, user: User, db: Session) -> Tag:
    tag = (
        db.query(Tag)
        .options(selectinload(Tag.keywords), selectinload(Tag.attack_techniques))
        .filter(Tag.id == tag_id)
        .first()
    )
    if tag is None:
        raise HTTPException(status_code=404)
    if not tag.is_preset and tag.created_by_user_id != user.id:
        raise HTTPException(status_code=404)
    return tag


@router.get("/tags")
def list_tags(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    preset_tags = db.query(Tag).filter(Tag.is_preset.is_(True)).order_by(Tag.name).all()
    custom_tags = (
        db.query(Tag)
        .filter(Tag.is_preset.is_(False), Tag.created_by_user_id == user.id)
        .order_by(Tag.name)
        .all()
    )
    return templates.TemplateResponse(
        request, "tags/list.html", {"user": user, "preset_tags": preset_tags, "custom_tags": custom_tags}
    )


@router.post("/tags")
def create_tag(
    request: Request,
    name: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    name = name.strip()
    if name and not db.query(Tag).filter(Tag.name == name, Tag.created_by_user_id == user.id).first():
        tag = Tag(name=name, is_preset=False, created_by_user_id=user.id)
        db.add(tag)
        db.commit()
    return RedirectResponse("/tags", status_code=303)


@router.get("/tags/{tag_id}")
def tag_detail(
    request: Request, tag_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)
):
    tag = _visible_tag_or_404(tag_id, user, db)
    return templates.TemplateResponse(request, "tags/detail.html", {"user": user, "tag": tag})


@router.post("/tags/{tag_id}/keywords")
def add_keyword(
    tag_id: int,
    keyword: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    tag = _visible_tag_or_404(tag_id, user, db)
    keyword = keyword.strip().lower()
    if keyword:
        exists = (
            db.query(TagKeyword)
            .filter(TagKeyword.tag_id == tag.id, TagKeyword.keyword == keyword, TagKeyword.created_by_user_id == user.id)
            .first()
        )
        if not exists:
            db.add(TagKeyword(tag_id=tag.id, keyword=keyword, is_preset=False, created_by_user_id=user.id))
            db.commit()
    return RedirectResponse(f"/tags/{tag_id}", status_code=303)


@router.post("/tags/{tag_id}/keywords/{keyword_id}/delete")
def delete_keyword(
    tag_id: int,
    keyword_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _visible_tag_or_404(tag_id, user, db)
    kw = db.get(TagKeyword, keyword_id)
    if kw and kw.tag_id == tag_id and kw.created_by_user_id == user.id:
        db.delete(kw)
        db.commit()
    return RedirectResponse(f"/tags/{tag_id}", status_code=303)


@router.post("/tags/{tag_id}/techniques")
def add_technique(
    tag_id: int,
    attack_technique_id: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    tag = _visible_tag_or_404(tag_id, user, db)
    technique_id = attack_technique_id.strip().upper()
    if _TECHNIQUE_RE.match(technique_id):
        exists = (
            db.query(TagAttackTechnique)
            .filter(
                TagAttackTechnique.tag_id == tag.id,
                TagAttackTechnique.attack_technique_id == technique_id,
                TagAttackTechnique.created_by_user_id == user.id,
            )
            .first()
        )
        if not exists:
            db.add(
                TagAttackTechnique(
                    tag_id=tag.id, attack_technique_id=technique_id, is_preset=False, created_by_user_id=user.id
                )
            )
            db.commit()
    return RedirectResponse(f"/tags/{tag_id}", status_code=303)


@router.post("/tags/{tag_id}/techniques/{technique_id}/delete")
def delete_technique(
    tag_id: int,
    technique_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    _visible_tag_or_404(tag_id, user, db)
    tech = db.get(TagAttackTechnique, technique_id)
    if tech and tech.tag_id == tag_id and tech.created_by_user_id == user.id:
        db.delete(tech)
        db.commit()
    return RedirectResponse(f"/tags/{tag_id}", status_code=303)
