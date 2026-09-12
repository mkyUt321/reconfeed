"""Send a single test email to check the Resend configuration end to end.

Uses the same send path as the daily digest, so a success here means the API key, the
RESEND_FROM_EMAIL address and (once you move off the sandbox sender) the domain verification
are all good. Touches neither the database nor the source fetchers, so it returns immediately
instead of taking the minutes a full `python -m app.jobs.daily` run needs.

Usage: python -m app.notify.send_test --to you@example.com

Exits 0 when the send succeeded, 1 otherwise, so it can gate a deployment script.
"""

import argparse
import logging
import sys

from app.config import settings
from app.notify.resend_client import preflight, send_email

SUBJECT = "ReconFeed 送信テスト"

BODY_HTML = """
<div style="font-family:sans-serif;color:#1c2530;">
  <h2>ReconFeed 送信テスト</h2>
  <p>このメールが届いていれば、Resend の設定（APIキー・送信元アドレス・ドメイン検証）は
     日次ダイジェストを送れる状態です。</p>
  <p style="color:#607080;font-size:13px;">送信元: {sender}</p>
</div>"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Send a ReconFeed test email via Resend.")
    parser.add_argument("--to", required=True, help="recipient address")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    print(f"送信元 (RESEND_FROM_EMAIL): {settings.resend_from_email}")
    print(f"宛先:                        {args.to}")

    warnings = preflight()
    for warning in warnings:
        print(f"[警告] {warning}")

    if send_email(to=args.to, subject=SUBJECT, html=BODY_HTML.format(sender=settings.resend_from_email)):
        print("\n送信に成功しました。受信箱を確認してください。")
        if settings.using_sandbox_sender:
            # The API accepts the request either way; only the mailbox shows the difference.
            print(
                "注意: サンドボックス送信元のままです。Resend アカウント所有者本人以外の宛先には、"
                "API が成功を返しても実際には配送されません。"
            )
        return 0

    print("\n送信に失敗しました。上のログに Resend が返した理由が出ています。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
