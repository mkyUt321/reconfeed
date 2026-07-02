from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings

app = FastAPI(title="ReconFeed")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
