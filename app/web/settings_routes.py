from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth.security import require_user
from app.db import get_db
from app.models import User
from app.web.templating import templates

router = APIRouter()

_ATTACK_VECTORS = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]


@router.get("/settings")
def settings_form(request: Request, user: User = Depends(require_user)):
    allowed = set((user.cvss_allowed_attack_vectors or "").split(",")) if user.cvss_allowed_attack_vectors else set()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {"user": user, "attack_vectors": _ATTACK_VECTORS, "allowed_vectors": allowed},
    )


@router.post("/settings")
def update_settings(
    request: Request,
    notify_email: str = Form(""),
    cvss_filter_enabled: bool = Form(False),
    cvss_allowed_attack_vectors: list[str] = Form(default=[]),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    notify_email = notify_email.strip()
    user.notify_email = notify_email or None
    user.cvss_filter_enabled = cvss_filter_enabled
    valid = [v for v in cvss_allowed_attack_vectors if v in _ATTACK_VECTORS]
    user.cvss_allowed_attack_vectors = ",".join(valid) if valid else None
    db.commit()
    return RedirectResponse("/settings", status_code=303)
