"""New GitHub repos that look like PoC/exploit releases for a CVE.

Uses the REST Search API (simpler than GraphQL for this) restricted to repos created after our
cursor, then filters to ones whose name/description actually contain a CVE-YYYY-NNNN pattern
(the search itself is a broad substring match and would otherwise include a lot of noise).

Known limitation: GitHub's Search API caps any single query at 1000 results (10 pages of 100),
so an extremely high-volume day could lose the tail; acceptable for a daily incremental run.
"""

import logging
import re
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models import FindingSource
from app.sources.base import RateLimiter, get_cursor, http_client, retry_transient, set_cursor, upsert_finding

logger = logging.getLogger("reconfeed.sources.github_poc")

SEARCH_URL = "https://api.github.com/search/repositories"
PER_PAGE = 100
INITIAL_LOOKBACK_DAYS = 7

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_rate_limiter = RateLimiter(2.1)  # GitHub search API: 30 req/min authenticated


@retry_transient
def _search_page(created_after: str, page: int, headers: dict) -> dict:
    _rate_limiter.wait()
    with http_client(headers=headers) as client:
        resp = client.get(
            SEARCH_URL,
            params={
                "q": f"CVE in:name,description created:>{created_after}",
                "sort": "created",
                "order": "asc",
                "per_page": PER_PAGE,
                "page": page,
            },
        )
        resp.raise_for_status()
        return resp.json()


def fetch(db) -> list[int]:
    if not settings.github_token:
        logger.warning("GITHUB_TOKEN not set; skipping GitHub PoC search")
        return []

    headers = {"Authorization": f"Bearer {settings.github_token}", "Accept": "application/vnd.github+json"}
    cursor = get_cursor(db, "github_poc")
    created_after = cursor or (datetime.now(timezone.utc) - timedelta(days=INITIAL_LOOKBACK_DAYS)).strftime(
        "%Y-%m-%d"
    )

    touched: list[int] = []
    newest_created: str | None = None
    page = 1

    while True:
        result = _search_page(created_after, page, headers)
        items = result.get("items", [])
        if not items:
            break

        for repo in items:
            haystack = f"{repo['name']} {repo.get('description') or ''}"
            cve_ids = sorted({m.upper() for m in _CVE_RE.findall(haystack)})
            if not cve_ids:
                continue

            created_at = repo.get("created_at")
            if created_at and (newest_created is None or created_at > newest_created):
                newest_created = created_at

            finding, changed = upsert_finding(
                db,
                FindingSource.GITHUB_POC,
                repo["full_name"],
                title=repo["name"],
                summary=repo.get("description") or "",
                raw_url=repo["html_url"],
                published_at=datetime.fromisoformat(created_at.replace("Z", "+00:00")) if created_at else None,
                raw={
                    "cve_ids": cve_ids,
                    "stars": repo.get("stargazers_count", 0),
                    "owner": repo.get("owner", {}).get("login"),
                },
            )
            if changed:
                touched.append(finding.id)

        db.commit()

        if len(items) < PER_PAGE or page * PER_PAGE >= 1000:
            break
        page += 1

    if newest_created:
        # GitHub's created:> qualifier only has day granularity, so the boundary day gets
        # reprocessed on the next run. Harmless — upsert_finding no-ops on unchanged repos.
        set_cursor(db, "github_poc", newest_created[:10])
        db.commit()

    logger.info("GitHub PoC: %d new/changed", len(touched))
    return touched
