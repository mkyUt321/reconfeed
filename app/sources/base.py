import logging
import time
from datetime import datetime, timezone

import certifi
import httpx
from sqlalchemy.orm import Session
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.models import Finding, FindingSource

logger = logging.getLogger("reconfeed.sources")


class RateLimiter:
    """Simple synchronous throttle: blocks just long enough to keep calls at least
    `min_interval_seconds` apart. Good enough for a single-threaded batch job."""

    def __init__(self, min_interval_seconds: float) -> None:
        self.min_interval_seconds = min_interval_seconds
        self._last_call: float | None = None

    def wait(self) -> None:
        if self._last_call is not None:
            elapsed = time.monotonic() - self._last_call
            remaining = self.min_interval_seconds - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self._last_call = time.monotonic()


def http_client(**kwargs) -> httpx.Client:
    # Explicit certifi bundle: some environments (e.g. a conda env with a stale SSL_CERT_FILE)
    # point the system SSL context at a CA file that no longer exists.
    return httpx.Client(timeout=30.0, follow_redirects=True, verify=certifi.where(), **kwargs)


retry_transient = retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, min=1, max=20),
    retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def upsert_finding(db: Session, source: FindingSource, external_id: str, **fields) -> tuple[Finding, bool]:
    """Get-or-create a Finding by (source, external_id) and apply `fields`.

    Returns (finding, changed) where `changed` is True if a new row was created or any
    field value actually differed from what was stored. Callers use `changed` to decide
    whether this finding needs to go through tag matching in this run.
    """
    finding = db.query(Finding).filter(Finding.source == source, Finding.external_id == external_id).first()
    is_new = finding is None
    if finding is None:
        finding = Finding(source=source, external_id=external_id)
        db.add(finding)

    changed = is_new
    for key, value in fields.items():
        if getattr(finding, key) != value:
            setattr(finding, key, value)
            changed = True

    finding.fetched_at = utcnow()
    db.flush()
    return finding, changed


def get_cursor(db: Session, source: str) -> str | None:
    from app.models import FetchState

    state = db.get(FetchState, source)
    return state.cursor if state else None


def set_cursor(db: Session, source: str, cursor: str) -> None:
    from app.models import FetchState

    state = db.get(FetchState, source)
    if state is None:
        state = FetchState(source=source, cursor=cursor)
        db.add(state)
    else:
        state.cursor = cursor
    db.flush()
