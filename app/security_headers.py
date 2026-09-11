from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# All templates/static assets are same-origin only (no CDN, no inline style/script), so the CSP
# below can omit 'unsafe-inline'/'unsafe-eval' entirely without breaking any page. If a future
# page needs an inline <script>/<style> or a third-party asset, extend this policy deliberately
# rather than loosening it wholesale.
_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
    ]
)

_PERMISSIONS_POLICY = ", ".join(
    [
        "accelerometer=()",
        "camera=()",
        "geolocation=()",
        "gyroscope=()",
        "magnetometer=()",
        "microphone=()",
        "payment=()",
        "usb=()",
    ]
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard hardening headers to every response.

    HSTS assumes TLS is terminated by a reverse proxy in front of the app (Render); the header
    itself is harmless to send over a plain HTTP connection, browsers just ignore it there.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY
        response.headers["Content-Security-Policy"] = _CSP
        return response
