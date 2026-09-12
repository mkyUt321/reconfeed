import logging

import resend

from app.config import RESEND_SANDBOX_FROM, settings

logger = logging.getLogger("reconfeed.notify.resend")


def preflight() -> list[str]:
    """Reasons the next send is likely not to reach its recipient, as human-readable warnings.

    Checked without calling Resend, so it is cheap enough to run at the top of the daily job.
    An empty list means the configuration looks capable of delivering to arbitrary addresses;
    it is not a promise the domain is actually verified — only a real send proves that.
    """
    warnings = []
    if not settings.resend_api_key:
        warnings.append("RESEND_API_KEY is not set; no mail will be sent at all.")
    if settings.using_sandbox_sender:
        warnings.append(
            f"RESEND_FROM_EMAIL is still the shared sandbox sender ({RESEND_SANDBOX_FROM}); "
            "Resend only delivers these to the API key owner's own address, so digests for "
            "every other user will fail. Verify a custom domain and set RESEND_FROM_EMAIL to "
            "an address on it."
        )
    return warnings


def send_email(to: str, subject: str, html: str) -> bool:
    if not settings.resend_api_key:
        logger.warning("RESEND_API_KEY not set; skipping email to %s", to)
        return False

    resend.api_key = settings.resend_api_key
    try:
        resend.Emails.send(
            {
                "from": settings.resend_from_email,
                "to": [to],
                "subject": subject,
                "html": html,
            }
        )
        return True
    except Exception as exc:
        # Log the provider's own message rather than just the traceback: Resend reports the
        # actionable causes (unverified domain, sandbox-sender recipient restriction, quota)
        # in the error body, and without it a failed digest looks identical to "no findings".
        logger.error("Failed to send email to %s: %s", to, exc)
        if settings.using_sandbox_sender:
            logger.error(
                "Sending from the sandbox address %s, which only reaches the Resend account "
                "owner — this is the expected failure for any other recipient.",
                RESEND_SANDBOX_FROM,
            )
        logger.debug("Resend send failure detail", exc_info=True)
        return False
