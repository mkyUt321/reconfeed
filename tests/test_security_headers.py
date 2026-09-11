from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_security_headers_present_on_response():
    response = client.get("/healthz")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "max-age=" in response.headers["strict-transport-security"]
    assert "includeSubDomains" in response.headers["strict-transport-security"]
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "geolocation=()" in response.headers["permissions-policy"]


def test_security_headers_present_on_redirect():
    # /dashboard requires auth; an unauthenticated request should redirect to /login and still
    # carry the same hardening headers (they're added by outer middleware, not per-route).
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert response.headers["x-frame-options"] == "DENY"


def test_dashboard_redirects_when_not_logged_in():
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
