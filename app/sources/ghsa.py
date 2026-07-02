"""GitHub Security Advisories via the GraphQL API.

Paginated newest-updated-first; we stop as soon as we see an advisory whose updatedAt is not
newer than our stored cursor (the newest updatedAt seen on the previous run).
"""

import logging
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models import FindingSource
from app.sources.base import RateLimiter, get_cursor, http_client, retry_transient, set_cursor, upsert_finding

logger = logging.getLogger("reconfeed.sources.ghsa")

GRAPHQL_URL = "https://api.github.com/graphql"
PAGE_SIZE = 50
INITIAL_LOOKBACK_DAYS = 7
MAX_PAGES = 200  # hard stop even if a cursor somehow goes stale; avoids an unbounded first run

_QUERY = """
query($first: Int!, $after: String) {
  securityAdvisories(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      permalink
      identifiers { type value }
      cvss { score vectorString }
      vulnerabilities(first: 10) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""

_rate_limiter = RateLimiter(1.0)


@retry_transient
def _fetch_page(after: str | None, headers: dict) -> dict:
    _rate_limiter.wait()
    with http_client(headers=headers) as client:
        resp = client.post(GRAPHQL_URL, json={"query": _QUERY, "variables": {"first": PAGE_SIZE, "after": after}})
        resp.raise_for_status()
        body = resp.json()
        if "errors" in body:
            raise RuntimeError(f"GHSA GraphQL error: {body['errors']}")
        return body["data"]["securityAdvisories"]


def fetch(db) -> list[int]:
    if not settings.github_token:
        logger.warning("GITHUB_TOKEN not set; skipping GHSA fetch")
        return []

    headers = {"Authorization": f"Bearer {settings.github_token}"}
    cursor = get_cursor(db, "ghsa")
    cursor_dt = (
        datetime.fromisoformat(cursor) if cursor else datetime.now(timezone.utc) - timedelta(days=INITIAL_LOOKBACK_DAYS)
    )

    touched: list[int] = []
    newest_seen: str | None = None
    after = None
    stop = False
    pages_fetched = 0

    while not stop and pages_fetched < MAX_PAGES:
        page = _fetch_page(after, headers)
        pages_fetched += 1
        nodes = page["nodes"]
        if not nodes:
            break

        for node in nodes:
            updated_at = datetime.fromisoformat(node["updatedAt"].replace("Z", "+00:00"))
            if newest_seen is None:
                newest_seen = node["updatedAt"]
            if updated_at <= cursor_dt:
                stop = True
                break

            cve_ids = [i["value"] for i in node.get("identifiers", []) if i["type"] == "CVE"]
            packages = [
                {"name": v["package"]["name"], "ecosystem": v["package"]["ecosystem"]}
                for v in node.get("vulnerabilities", {}).get("nodes", [])
                if v.get("package")
            ]
            cvss = node.get("cvss") or {}
            published_at = None
            if node.get("publishedAt"):
                published_at = datetime.fromisoformat(node["publishedAt"].replace("Z", "+00:00"))

            finding, changed = upsert_finding(
                db,
                FindingSource.GHSA,
                node["ghsaId"],
                title=node.get("summary") or node["ghsaId"],
                summary=node.get("description") or "",
                cvss_score=cvss.get("score"),
                cvss_vector=cvss.get("vectorString"),
                raw_url=node.get("permalink"),
                published_at=published_at,
                raw={"severity": node.get("severity"), "cve_ids": cve_ids, "packages": packages},
            )
            if changed:
                touched.append(finding.id)

        db.commit()

        page_info = page["pageInfo"]
        if stop or not page_info["hasNextPage"]:
            break
        after = page_info["endCursor"]

    if newest_seen:
        set_cursor(db, "ghsa", newest_seen)
        db.commit()

    logger.info("GHSA: %d new/changed", len(touched))
    return touched
