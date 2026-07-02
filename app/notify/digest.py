"""Builds and sends each user's daily digest email.

Ordering within a digest puts "actionable" findings first — KEV-listed, then by descending
EPSS score — since those are the ones a researcher most likely wants to act on immediately.
"""

import logging
from html import escape

from sqlalchemy.orm import Session

from app.matching.distribute import mark_notified, matched_tag_names_for_findings, pending_findings_for_user
from app.models import Finding, User
from app.notify.resend_client import send_email

logger = logging.getLogger("reconfeed.notify.digest")


def _sort_key(finding: Finding):
    return (not finding.is_kev, -(finding.epss_score or 0.0))


def _finding_row_html(finding: Finding, tag_names: list[str]) -> str:
    highlights = []
    if finding.is_kev:
        highlights.append('<span style="color:#c62828;font-weight:600;">KEV収録</span>')
    if finding.epss_score is not None and finding.epss_score >= 0.5:
        highlights.append(f'<span style="color:#8a6d00;font-weight:600;">EPSS {finding.epss_score:.2f}</span>')

    title = escape(finding.title)
    url = escape(finding.raw_url or "#")
    tags = escape(", ".join(tag_names)) if tag_names else "-"
    highlight_html = " / ".join(highlights)
    cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "-"

    return f"""
    <tr>
      <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;">{escape(finding.source.value)}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;">
        <a href="{url}">{title}</a>
        {f'<br>{highlight_html}' if highlight_html else ''}
      </td>
      <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;">{cvss}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;">{tags}</td>
    </tr>"""


def build_digest_html(findings: list[Finding], tag_names_by_finding: dict[int, list[str]]) -> str:
    sorted_findings = sorted(findings, key=_sort_key)
    rows = "".join(_finding_row_html(f, tag_names_by_finding.get(f.id, [])) for f in sorted_findings)

    return f"""
    <div style="font-family:sans-serif;color:#1c2530;">
      <h2>ReconFeed 日次ダイジェスト</h2>
      <p>ウォッチリストに該当する新着 {len(findings)} 件です。</p>
      <table style="border-collapse:collapse;width:100%;">
        <thead>
          <tr>
            <th style="text-align:left;padding:6px 8px;border-bottom:2px solid #333;">情報源</th>
            <th style="text-align:left;padding:6px 8px;border-bottom:2px solid #333;">タイトル</th>
            <th style="text-align:left;padding:6px 8px;border-bottom:2px solid #333;">CVSS</th>
            <th style="text-align:left;padding:6px 8px;border-bottom:2px solid #333;">該当タグ</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""


def send_daily_digest(db: Session, user: User) -> int:
    """Send this user's digest if they have anything pending; returns the number of findings
    included (0 if nothing was pending or the send failed — either way nothing is marked
    notified, so a failed send is retried on the next run)."""
    findings = pending_findings_for_user(db, user)
    if not findings:
        return 0

    tag_names = matched_tag_names_for_findings(db, user, [f.id for f in findings])
    html = build_digest_html(findings, tag_names)

    sent = send_email(
        to=user.notification_target(),
        subject=f"ReconFeed 日次ダイジェスト: {len(findings)}件の新着",
        html=html,
    )
    if not sent:
        return 0

    mark_notified(db, user, findings)
    logger.info("sent digest to user_id=%s: %d findings", user.id, len(findings))
    return len(findings)


def send_all_digests(db: Session) -> int:
    total = 0
    for user in db.query(User).all():
        try:
            total += send_daily_digest(db, user)
        except Exception:
            logger.exception("failed to send digest to user_id=%s", user.id)
            db.rollback()
    return total
