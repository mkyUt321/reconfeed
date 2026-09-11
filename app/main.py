from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.security_headers import SecurityHeadersMiddleware
from app.web import auth_routes, dashboard_routes, home_routes, settings_routes, tag_routes, watchlist_routes

app = FastAPI(title="ReconFeed")

# Session cookie hardening: HttpOnly is SessionMiddleware's default (JS never needs to read this
# cookie). SameSite=Lax stops it being sent on cross-site requests while still following normal
# top-level navigation links. Secure is derived from APP_BASE_URL's scheme rather than
# hard-coded: Render's APP_BASE_URL is https, so the cookie is Secure in production, but local
# dev (http://localhost) still gets a working login without a self-signed cert.
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    same_site="lax",
    https_only=settings.app_base_url.startswith("https://"),
)
app.add_middleware(SecurityHeadersMiddleware)
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
