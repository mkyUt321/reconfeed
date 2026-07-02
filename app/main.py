from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.web import auth_routes, dashboard_routes, home_routes, settings_routes, tag_routes, watchlist_routes

app = FastAPI(title="ReconFeed")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(home_routes.router)
app.include_router(auth_routes.router)
app.include_router(tag_routes.router)
app.include_router(watchlist_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(settings_routes.router)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
