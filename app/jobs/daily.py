"""Daily batch entrypoint: fetch -> match -> distribute -> notify.

Run via `python -m app.jobs.daily`. Intended to be invoked by the GitHub Actions scheduled
workflow (see .github/workflows/daily.yml) once or twice a day.
"""

import logging

from app.db import SessionLocal
from app.matching.engine import match_findings
from app.notify.digest import send_all_digests
from app.notify.resend_client import preflight
from app.sources import attack, capec, epss, ghsa, github_poc, kev, nvd

logger = logging.getLogger("reconfeed.jobs.daily")

# Order matters: nvd (and therefore epss/kev's CVE cross-referencing) runs first so same-day
# KEV/EPSS enrichment has the freshest possible set of CVE findings to attach to. Older KEV
# entries whose CVE predates our incremental NVD window won't get the enrichment flag on the
# CVE-sourced row — only their dedicated KEV-sourced finding — which is an accepted limitation.
FETCHERS = [
    ("nvd", nvd.fetch),
    ("epss", epss.fetch),
    ("kev", kev.fetch),
    ("ghsa", ghsa.fetch),
    ("github_poc", github_poc.fetch),
    ("attack", attack.fetch),
    ("capec", capec.fetch),
]


def run_fetchers(db) -> dict[str, list[int]]:
    results: dict[str, list[int]] = {}
    for name, fn in FETCHERS:
        try:
            touched = fn(db)
            results[name] = touched
            logger.info("fetch %s: %d new/changed findings", name, len(touched))
        except Exception:
            logger.exception("fetch %s failed; continuing with remaining sources", name)
            db.rollback()
            results[name] = []
    return results


def main() -> None:
    db = SessionLocal()
    try:
        results = run_fetchers(db)
        touched_ids = sorted({fid for ids in results.values() for fid in ids})
        logger.info("daily job: fetch stage complete, %d total new/changed findings", len(touched_ids))

        new_matches = match_findings(db, touched_ids)
        logger.info("daily job: matching stage complete, %d new tag matches", new_matches)

        # Surfaced once up front rather than per user: a misconfigured sender fails every
        # digest identically, and "0 findings notified" alone doesn't distinguish that from
        # simply having nothing new to send.
        for warning in preflight():
            logger.warning("notification preflight: %s", warning)

        notified_count = send_all_digests(db)
        logger.info("daily job: notification stage complete, %d findings notified across all users", notified_count)
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    main()
