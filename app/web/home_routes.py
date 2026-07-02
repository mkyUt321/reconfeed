from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.auth.security import get_current_user
from app.db import get_db
from app.web.templating import templates

router = APIRouter()


@router.get("/")
def home(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse(request, "home.html", {"user": user})
