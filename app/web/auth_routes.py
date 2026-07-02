import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.auth.security import get_current_user, hash_password, login_user, logout_user, verify_password
from app.db import get_db
from app.models import User
from app.web.templating import templates

router = APIRouter()

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.get("/signup")
def signup_form(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "auth/signup.html", {})


@router.post("/signup")
def signup_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    error = None
    if not _EMAIL_RE.match(email):
        error = "メールアドレスの形式が正しくありません。"
    elif len(password) < 8:
        error = "パスワードは8文字以上にしてください。"
    elif password != password_confirm:
        error = "パスワードが一致しません。"
    elif db.query(User).filter(User.email == email).first():
        error = "このメールアドレスは既に登録されています。"

    if error:
        return templates.TemplateResponse(
            request, "auth/signup.html", {"error": error, "email": email}, status_code=400
        )

    user = User(email=email, password_hash=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    login_user(request, user)
    return RedirectResponse("/", status_code=303)


@router.get("/login")
def login_form(request: Request, db: Session = Depends(get_db)):
    if get_current_user(request, db):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "auth/login.html", {})


@router.post("/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {"error": "メールアドレスまたはパスワードが正しくありません。", "email": email},
            status_code=400,
        )

    login_user(request, user)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    logout_user(request)
    return RedirectResponse("/login", status_code=303)
