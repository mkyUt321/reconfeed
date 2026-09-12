import pytest

from app.config import RESEND_SANDBOX_FROM, Settings, settings
from app.models.finding import Finding, FindingSource
from app.notify import resend_client
from app.notify.digest import _sort_key, build_digest_html


def make_finding(finding_id=1, title="CVE-2024-0001", is_kev=False, epss=None, cvss=None, url="https://example.com/a"):
    # Built unbound: nothing here touches a session, so column defaults never fire and every
    # field the digest reads has to be set explicitly.
    return Finding(
        id=finding_id,
        source=FindingSource.CVE,
        external_id=title,
        title=title,
        summary="",
        is_kev=is_kev,
        epss_score=epss,
        cvss_score=cvss,
        raw_url=url,
    )


def test_digest_escapes_finding_title():
    # Titles come from third-party feeds, so they reach the digest untrusted.
    finding = make_finding(title='<script>alert("x")</script>')
    html = build_digest_html([finding], {})
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_digest_escapes_tag_names_and_url():
    finding = make_finding(url='https://example.com/"onmouseover="evil()')
    html = build_digest_html([finding], {1: ["<b>tag</b>"]})
    assert "<b>tag</b>" not in html
    assert '"onmouseover="' not in html


def test_digest_renders_finding_count_and_metadata():
    findings = [make_finding(1, "CVE-A", cvss=9.8), make_finding(2, "CVE-B")]
    html = build_digest_html(findings, {})
    assert "2 件" in html
    assert "9.8" in html
    assert "CVE-A" in html and "CVE-B" in html


def test_sort_key_puts_kev_before_higher_epss():
    kev = make_finding(1, "kev", is_kev=True, epss=0.01)
    high_epss = make_finding(2, "epss", is_kev=False, epss=0.99)
    assert sorted([high_epss, kev], key=_sort_key) == [kev, high_epss]


def test_sort_key_orders_by_descending_epss_within_same_kev_status():
    low = make_finding(1, "low", epss=0.1)
    high = make_finding(2, "high", epss=0.9)
    missing = make_finding(3, "missing", epss=None)
    assert sorted([missing, low, high], key=_sort_key) == [high, low, missing]


def test_send_email_returns_false_without_api_key(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "")
    # Any actual send attempt would blow up here rather than silently hitting the network.
    monkeypatch.setattr(
        resend_client.resend.Emails, "send", lambda *a, **kw: pytest.fail("must not call Resend")
    )
    assert resend_client.send_email("a@example.com", "s", "<p>h</p>") is False


def test_send_email_swallows_provider_errors(monkeypatch):
    # A raising send must not abort the batch: send_all_digests relies on the False return so
    # the findings stay unmarked and are retried on the next run.
    def boom(*args, **kwargs):
        raise RuntimeError("domain is not verified")

    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    monkeypatch.setattr(resend_client.resend.Emails, "send", boom)
    assert resend_client.send_email("a@example.com", "s", "<p>h</p>") is False


def test_send_email_returns_true_on_success(monkeypatch):
    sent = {}

    def capture(payload):
        sent.update(payload)
        return {"id": "abc"}

    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    monkeypatch.setattr(settings, "resend_from_email", "ReconFeed <notify@example.com>")
    monkeypatch.setattr(resend_client.resend.Emails, "send", capture)

    assert resend_client.send_email("a@example.com", "subject", "<p>h</p>") is True
    assert sent["from"] == "ReconFeed <notify@example.com>"
    assert sent["to"] == ["a@example.com"]


def build_settings(**overrides):
    base = {"database_url": "postgresql://u:p@localhost/db", "session_secret": "s"}
    return Settings(**{**base, **overrides})


def test_using_sandbox_sender_detects_bare_and_display_name_forms():
    assert build_settings(resend_from_email=RESEND_SANDBOX_FROM).using_sandbox_sender is True
    assert build_settings(resend_from_email=f"ReconFeed <{RESEND_SANDBOX_FROM}>").using_sandbox_sender is True
    assert build_settings(resend_from_email="ONBOARDING@RESEND.DEV").using_sandbox_sender is True
    assert build_settings(resend_from_email="notify@example.com").using_sandbox_sender is False


def test_preflight_warns_about_missing_key_and_sandbox_sender(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "")
    monkeypatch.setattr(settings, "resend_from_email", RESEND_SANDBOX_FROM)
    warnings = resend_client.preflight()
    assert len(warnings) == 2
    assert any("RESEND_API_KEY" in w for w in warnings)
    assert any(RESEND_SANDBOX_FROM in w for w in warnings)


def test_preflight_is_quiet_when_configured_for_a_custom_domain(monkeypatch):
    monkeypatch.setattr(settings, "resend_api_key", "re_test")
    monkeypatch.setattr(settings, "resend_from_email", "notify@example.com")
    assert resend_client.preflight() == []
