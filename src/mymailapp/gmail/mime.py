"""Recursive MIME payload parser and RFC 2822 header utilities."""

import base64
import binascii
import html
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from mymailapp.gmail.models import (
    AttachmentView,
    GmailHeader,
    GmailMessage,
    GmailMessagePart,
    ParsedMessageView,
)
from mymailapp.gmail.sanitize import render_plain_text_srcdoc, sanitize_email_html

SAFE_INLINE_IMAGE_MIMES: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp"}
)


def decode_base64url(data: str) -> bytes:
    """Decode Gmail's unpadded URL-safe base64 payload into raw bytes."""
    padded = data.strip()
    remainder = len(padded) % 4
    if remainder:
        padded += "=" * (4 - remainder)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Invalid base64url payload from Gmail API") from exc


def format_human_size(size_bytes: int) -> str:
    """Format byte size into compact human-readable units."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def get_header_map(headers: tuple[GmailHeader, ...]) -> dict[str, str]:
    """Return lowercase header lookup dictionary preserving last non-empty value."""
    lookup: dict[str, str] = {}
    for hdr in headers:
        key = hdr.name.strip().lower()
        if key and (key not in lookup or hdr.value):
            lookup[key] = hdr.value.strip()
    return lookup


def format_email_date(raw_date: str | None, internal_date_ms: str | None = None) -> str:
    """Format RFC 2822 Date header or internalDate epoch ms safely without crashing on junk."""
    if raw_date:
        try:
            dt = parsedate_to_datetime(raw_date)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        except (TypeError, ValueError, IndexError, OverflowError):
            pass

    if internal_date_ms and internal_date_ms.isdigit():
        try:
            dt = datetime.fromtimestamp(int(internal_date_ms) / 1000.0, tz=UTC)
            return dt.strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, OSError, OverflowError):
            pass

    return raw_date.strip()[:40] if raw_date else "Unknown date"


def parse_gmail_message(
    message: GmailMessage,
    *,
    allow_remote_images: bool = False,
    inline_cid_max_bytes: int = 2_097_152,
) -> ParsedMessageView:
    """Walk a GmailMessage MIME tree and produce a sanitized ParsedMessageView."""
    root = message.payload
    headers = get_header_map(root.headers) if root else {}

    subject = headers.get("subject") or "(no subject)"
    sender = headers.get("from") or "(unknown sender)"
    recipients = headers.get("to") or "(undisclosed recipients)"
    date_display = format_email_date(headers.get("date"), message.internalDate)
    unescaped_snippet = html.unescape(message.snippet)

    html_chunks: list[str] = []
    text_chunks: list[str] = []
    inline_cids: dict[str, str] = {}
    attachments: list[AttachmentView] = []

    def _walk(part: GmailMessagePart) -> None:
        mime = part.mimeType.lower().strip()
        part_headers = get_header_map(part.headers)
        content_id = part_headers.get("content-id", "").strip("<> ")
        content_disp = part_headers.get("content-disposition", "").lower()

        if part.parts:
            for child in part.parts:
                _walk(child)
            return

        is_attachment = bool(part.filename) or content_disp.startswith("attachment")

        if (
            content_id
            and mime in SAFE_INLINE_IMAGE_MIMES
            and part.body.data
            and not content_disp.startswith("attachment")
        ):
            raw_bytes = decode_base64url(part.body.data)
            if len(raw_bytes) <= inline_cid_max_bytes:
                b64_std = base64.b64encode(raw_bytes).decode("ascii")
                inline_cids[content_id] = f"data:{mime};base64,{b64_std}"
                return

        if part.body.attachmentId and (is_attachment or content_id):
            safe_name = part.filename.strip() or f"attachment-{part.partId or 'file'}"
            attachments.append(
                AttachmentView(
                    attachment_id=part.body.attachmentId,
                    message_id=message.id,
                    filename=safe_name,
                    mime_type=mime or "application/octet-stream",
                    size_bytes=max(part.body.size, 0),
                    human_size=format_human_size(max(part.body.size, 0)),
                )
            )
            return

        if part.body.data and not is_attachment:
            decoded_text = decode_base64url(part.body.data).decode("utf-8", errors="replace")
            if mime == "text/html":
                html_chunks.append(decoded_text)
            elif mime == "text/plain":
                text_chunks.append(decoded_text)

    if root is not None:
        _walk(root)

    if html_chunks:
        sanitized = sanitize_email_html(
            "\n".join(html_chunks),
            inline_cid_data_uris=inline_cids,
            allow_remote_images=allow_remote_images,
        )
    elif text_chunks:
        sanitized = render_plain_text_srcdoc("\n\n".join(text_chunks))
    else:
        sanitized = render_plain_text_srcdoc(unescaped_snippet or "(empty message body)")

    return ParsedMessageView(
        message_id=message.id,
        sender=sender,
        recipients=recipients,
        subject=subject,
        date_display=date_display,
        snippet=unescaped_snippet,
        sanitized_srcdoc=sanitized.srcdoc,
        has_blocked_remote_images=sanitized.has_blocked_remote_images,
        attachments=tuple(attachments),
    )
