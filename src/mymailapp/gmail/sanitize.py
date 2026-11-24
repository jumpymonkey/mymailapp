"""Server-side HTML sanitization and remote tracking-pixel blocking."""

import html
import re
from collections.abc import Mapping
from dataclasses import dataclass

import nh3

ALLOWED_TAGS: frozenset[str] = frozenset(
    {
        "a",
        "abbr",
        "b",
        "blockquote",
        "br",
        "caption",
        "code",
        "col",
        "colgroup",
        "dd",
        "del",
        "div",
        "dl",
        "dt",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "i",
        "img",
        "ins",
        "li",
        "ol",
        "p",
        "pre",
        "q",
        "s",
        "small",
        "span",
        "strong",
        "sub",
        "sup",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "u",
        "ul",
    }
)

ALLOWED_ATTRIBUTES: dict[str, set[str]] = {
    "*": {"align", "dir", "lang", "title"},
    "a": {"href", "target"},
    "col": {"span", "width"},
    "colgroup": {"span", "width"},
    "img": {"alt", "height", "src", "width"},
    "table": {"border", "cellpadding", "cellspacing", "width"},
    "td": {"colspan", "rowspan", "valign", "width"},
    "th": {"colspan", "rowspan", "scope", "valign", "width"},
}

ALLOWED_URL_SCHEMES: set[str] = {"http", "https", "mailto", "cid"}

_CID_IMG_SRC_RE = re.compile(
    r"""(<img\b[^>]*?\bsrc=)(["'])cid:([^"']+)\2""",
    flags=re.IGNORECASE,
)
_REMOTE_IMG_TAG_RE = re.compile(
    r"""<img\b[^>]*?\bsrc=(["'])https?://[^"']+\1[^>]*>""",
    flags=re.IGNORECASE,
)
_REMOTE_SRC_ATTR_RE = re.compile(
    r"""\bsrc=(["'])https?://[^"']+\1""",
    flags=re.IGNORECASE,
)

_SRCDOC_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  :root {{ color-scheme: light; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.55;
    color: #111827;
    background: #ffffff;
    margin: 14px 16px;
    overflow-wrap: anywhere;
  }}
  a {{ color: #1d4ed8; }}
  img {{ max-width: 100%; height: auto; }}
  blockquote {{
    border-left: 3px solid #d1d5db;
    margin: 10px 0;
    padding-left: 12px;
    color: #4b5563;
  }}
  pre, code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
  }}
  pre {{
    white-space: pre-wrap;
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 10px 12px;
  }}
  table {{ border-collapse: collapse; max-width: 100%; }}
  .blocked-remote-img {{
    display: inline-block;
    font-size: 12px;
    color: #6b7280;
    background: #f3f4f6;
    border: 1px dashed #d1d5db;
    border-radius: 4px;
    padding: 2px 6px;
  }}
</style>
</head>
<body>{body}</body>
</html>"""


@dataclass(frozen=True, slots=True)
class SanitizedEmailBody:
    """Result of sanitizing an email body for sandboxed srcdoc rendering."""

    srcdoc: str
    has_blocked_remote_images: bool


def sanitize_email_html(
    raw_html: str,
    *,
    inline_cid_data_uris: Mapping[str, str] | None = None,
    allow_remote_images: bool = False,
) -> SanitizedEmailBody:
    """Sanitize untrusted email HTML via nh3, resolve safe CIDs, and gate remote images."""
    cleaned = nh3.clean(
        raw_html,
        tags=set(ALLOWED_TAGS),
        attributes={k: set(v) for k, v in ALLOWED_ATTRIBUTES.items()},
        url_schemes=set(ALLOWED_URL_SCHEMES),
        link_rel="noopener noreferrer",
    )

    cid_lookup = inline_cid_data_uris or {}

    def _replace_cid(match: re.Match[str]) -> str:
        prefix, quote, cid_key = match.group(1), match.group(2), match.group(3).strip("<> ")
        data_uri = cid_lookup.get(cid_key)
        if data_uri:
            return f"{prefix}{quote}{data_uri}{quote}"
        return f'{prefix}{quote}{quote} alt="[Inline image unavailable]"'

    cleaned = _CID_IMG_SRC_RE.sub(_replace_cid, cleaned)

    has_blocked = False
    if not allow_remote_images and _REMOTE_IMG_TAG_RE.search(cleaned):
        has_blocked = True

        def _strip_remote_img(img_match: re.Match[str]) -> str:
            tag = img_match.group(0)
            stripped = _REMOTE_SRC_ATTR_RE.sub('data-remote-blocked="true"', tag)
            return f'{stripped}<span class="blocked-remote-img">[Remote image blocked]</span>'

        cleaned = _REMOTE_IMG_TAG_RE.sub(_strip_remote_img, cleaned)

    # Ensure links open outside the sandboxed iframe cleanly when user clicks
    cleaned = re.sub(
        r"<a\b(?![^>]*\btarget=)",
        '<a target="_blank"',
        cleaned,
        flags=re.IGNORECASE,
    )

    return SanitizedEmailBody(
        srcdoc=_SRCDOC_TEMPLATE.format(body=cleaned),
        has_blocked_remote_images=has_blocked,
    )


def render_plain_text_srcdoc(plain_text: str) -> SanitizedEmailBody:
    """Escape plain-text email content into a safe srcdoc document."""
    escaped = html.escape(plain_text)
    body = f"<pre>{escaped}</pre>"
    return SanitizedEmailBody(
        srcdoc=_SRCDOC_TEMPLATE.format(body=body),
        has_blocked_remote_images=False,
    )
