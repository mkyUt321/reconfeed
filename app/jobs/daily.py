"""Daily batch entrypoint: fetch -> match -> distribute -> notify.

Run via `python -m app.jobs.daily`. Intended to be invoked by the GitHub Actions scheduled
workflow (see .github/workflows/daily.yml) once or twice a day.
"""

import logging

from app.db import SessionLocal
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
        total = sum(len(v) for v in results.values())
        logger.info("daily job: fetch stage complete, %d total new/changed findings", total)
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    main()
