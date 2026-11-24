"""Unit tests for recursive MIME parsing, nh3 XSS sanitization, and pixel blocking."""

import base64

import pytest

from mymailapp.gmail.mime import format_email_date, parse_gmail_message
from mymailapp.gmail.models import (
    GmailHeader,
    GmailMessage,
    GmailMessagePart,
    GmailMessagePartBody,
)
from mymailapp.gmail.sanitize import sanitize_email_html


def _b64url(raw: bytes | str) -> str:
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize(
    ("malicious_html", "forbidden_substring"),
    [
        ("<script>alert('xss')</script><p>Safe</p>", "<script"),
        ('<img src="x" onerror="alert(1)">', "onerror"),
        ('<a href="javascript:alert(1)">Click</a>', "javascript:"),
        ('<a href="data:text/html;base64,PHNjcmlwdD4=">Bad</a>', "data:text/html"),
        ('<iframe src="https://evil.example"></iframe>', "<iframe"),
        ('<svg onload="alert(1)"></svg>', "<svg"),
        ('<form action="https://phish.example"><input></form>', "<form"),
    ],
)
def test_sanitize_strips_hostile_markup(
    malicious_html: str,
    forbidden_substring: str,
) -> None:
    result = sanitize_email_html(malicious_html, allow_remote_images=True)
    assert forbidden_substring.lower() not in result.srcdoc.lower()


def test_remote_tracking_pixel_blocked_by_default_and_allowed_on_opt_in() -> None:
    html_with_pixel = (
        '<p>Hello</p><img src="https://tracker.example.com/open?id=99" width="1" height="1">'
    )
    blocked = sanitize_email_html(html_with_pixel, allow_remote_images=False)
    assert blocked.has_blocked_remote_images is True
    assert "https://tracker.example.com/open" not in blocked.srcdoc
    assert "[Remote image blocked]" in blocked.srcdoc

    allowed = sanitize_email_html(html_with_pixel, allow_remote_images=True)
    assert allowed.has_blocked_remote_images is False
    assert "https://tracker.example.com/open?id=99" in allowed.srcdoc


def test_parse_nested_multipart_with_inline_cid_and_attachment() -> None:
    png_bytes = b"\x89PNG\r\n\x1a\nfake-png"
    msg = GmailMessage(
        id="msg-101",
        threadId="thr-101",
        snippet="Invoice &amp; receipt",
        payload=GmailMessagePart(
            mimeType="multipart/mixed",
            headers=(
                GmailHeader(name="Subject", value="Q4 Architecture Invoice"),
                GmailHeader(name="From", value="Alice <alice@example.org>"),
                GmailHeader(name="To", value="User <user@example.com>"),
                GmailHeader(name="Date", value="Tue, 24 Nov 2026 14:30:00 +0100"),
            ),
            parts=(
                GmailMessagePart(
                    mimeType="multipart/related",
                    parts=(
                        GmailMessagePart(
                            mimeType="multipart/alternative",
                            parts=(
                                GmailMessagePart(
                                    mimeType="text/plain",
                                    body=GmailMessagePartBody(data=_b64url("Plain fallback")),
                                ),
                                GmailMessagePart(
                                    mimeType="text/html",
                                    body=GmailMessagePartBody(
                                        data=_b64url('<p>Logo: <img src="cid:logo@cid"></p>')
                                    ),
                                ),
                            ),
                        ),
                        GmailMessagePart(
                            partId="1.2",
                            mimeType="image/png",
                            headers=(GmailHeader(name="Content-ID", value="<logo@cid>"),),
                            body=GmailMessagePartBody(
                                size=len(png_bytes),
                                data=_b64url(png_bytes),
                            ),
                        ),
                    ),
                ),
                GmailMessagePart(
                    partId="2",
                    mimeType="application/pdf",
                    filename="invoice-2026.pdf",
                    headers=(
                        GmailHeader(
                            name="Content-Disposition",
                            value='attachment; filename="invoice-2026.pdf"',
                        ),
                    ),
                    body=GmailMessagePartBody(attachmentId="att-pdf-99", size=4096),
                ),
            ),
        ),
    )

    parsed = parse_gmail_message(msg)
    assert parsed.subject == "Q4 Architecture Invoice"
    assert parsed.snippet == "Invoice & receipt"
    assert parsed.date_display == "2026-11-24 13:30 UTC"
    assert "data:image/png;base64," in parsed.sanitized_srcdoc
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice-2026.pdf"
    assert parsed.attachments[0].attachment_id == "att-pdf-99"
    assert parsed.attachments[0].human_size == "4.0 KB"


def test_malformed_date_header_falls_back_cleanly() -> None:
    assert format_email_date("not-a-valid-rfc2822-date", "1764000000000").endswith("UTC")
    assert format_email_date("completely-broken", None) == "completely-broken"
