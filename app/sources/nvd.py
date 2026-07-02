"""NVD API 2.0 (CVEs), fetched incrementally by lastModified window.

Rate limit: 50 req/30s with an API key, 5 req/30s without. Max lastMod window per call is
120 days, so a long-idle deployment catches up 120 days at a time across successive runs
rather than in one huge call.
"""

import logging
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models import FindingSource
from app.sources.base import RateLimiter, get_cursor, http_client, retry_transient, set_cursor, upsert_finding

logger = logging.getLogger("reconfeed.sources.nvd")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120
RESULTS_PER_PAGE = 2000
INITIAL_LOOKBACK_DAYS = 7

_rate_limiter = RateLimiter(0.65 if True else 6.5)  # overwritten per-call based on api key presence


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def _best_cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString")
    return None, None


def _cwe_ids(weaknesses: list[dict]) -> list[str]:
    ids = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value"):
                ids.append(d["value"])
    return ids


def _products(configurations: list[dict]) -> list[str]:
    products = set()
    for config in configurations or []:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) > 4 and parts[4] not in ("*", "-"):
                    products.add(parts[4].replace("_", " "))
    return sorted(products)


def _description(descriptions: list[dict]) -> str:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


@retry_transient
def _fetch_page(start_index: int, start: datetime, end: datetime, headers: dict) -> dict:
    _rate_limiter.wait()
    with http_client(headers=headers) as client:
        resp = client.get(
            NVD_URL,
            params={
                "lastModStartDate": _iso(start),
                "lastModEndDate": _iso(end),
                "resultsPerPage": RESULTS_PER_PAGE,
                "startIndex": start_index,
            },
        )
        resp.raise_for_status()
        return resp.json()


def fetch(db) -> list[int]:
    global _rate_limiter
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
        _rate_limiter = RateLimiter(0.65)
    else:
        _rate_limiter = RateLimiter(6.5)
        logger.warning("NVD_API_KEY not set; falling back to unauthenticated rate limit (much slower)")

    now = datetime.now(timezone.utc)
    cursor = get_cursor(db, "nvd")
    start = datetime.fromisoformat(cursor) if cursor else now - timedelta(days=INITIAL_LOOKBACK_DAYS)
    end = min(start + timedelta(days=MAX_WINDOW_DAYS), now)

    if start >= now:
        logger.info("NVD: cursor already caught up to now, nothing to do")
        return []

    touched: list[int] = []
    start_index = 0
    total_results = None

    while total_results is None or start_index < total_results:
        page = _fetch_page(start_index, start, end, headers)
        total_results = page.get("totalResults", 0)

        for item in page.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            cvss_score, cvss_vector = _best_cvss(cve.get("metrics", {}))
            published_at = None
            if cve.get("published"):
                published_at = datetime.fromisoformat(cve["published"]).replace(tzinfo=timezone.utc)

            finding, changed = upsert_finding(
                db,
                FindingSource.CVE,
                cve_id,
                title=cve_id,
                summary=_description(cve.get("descriptions", [])),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                raw_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_at=published_at,
                raw={
                    "cwe": _cwe_ids(cve.get("weaknesses", [])),
                    "products": _products(cve.get("configurations", [])),
                    "vuln_status": cve.get("vulnStatus"),
                },
            )
            if changed:
                touched.append(finding.id)

        db.commit()
        start_index += RESULTS_PER_PAGE

    set_cursor(db, "nvd", _iso(end))
    db.commit()
    logger.info("NVD: window %s..%s, %d results, %d new/changed", start, end, total_results, len(touched))
    return touched
