"""Read-only Gmail search, thread conversation view, and attachment download routes."""

import re
from typing import Annotated
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from fastapi.templating import Jinja2Templates

from mymailapp.auth.session import SessionPayload
from mymailapp.dependencies import get_gmail_client, get_templates, require_session
from mymailapp.gmail.client import GmailClient, GmailNotFoundError

router = APIRouter(tags=["mail"])

_GMAIL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _validate_gmail_identifier(value: str, label: str) -> str:
    if not _GMAIL_ID_RE.match(value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {label} format",
        )
    return value


def build_attachment_disposition(filename: str) -> str:
    """Format an RFC 5987 safe Content-Disposition attachment header value."""
    cleaned = _CONTROL_CHARS_RE.sub("", filename).strip() or "attachment.bin"
    ascii_fallback = cleaned.encode("ascii", errors="ignore").decode("ascii")
    ascii_fallback = re.sub(r'[\\";]', "_", ascii_fallback).strip() or "attachment.bin"
    utf8_encoded = quote(cleaned, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{utf8_encoded}"


@router.get("/", response_model=None)
@router.get("/search", response_model=None)
async def search_inbox(
    request: Request,
    session: Annotated[SessionPayload, Depends(require_session)],
    gmail_client: Annotated[GmailClient, Depends(get_gmail_client)],
    templates: Annotated[Jinja2Templates, Depends(get_templates)],
    q: str = Query(default="in:inbox", max_length=500),
    page_token: str | None = Query(default=None, max_length=256),
) -> Response:
    """Search Gmail threads and render full layout or HTMX partial list."""
    results = await gmail_client.search_threads(
        session.access_token,
        query=q,
        page_token=page_token,
    )
    is_htmx = request.headers.get("hx-request", "").lower() == "true"
    template_name = "partials/thread_list.html" if is_htmx else "inbox.html"

    headers: dict[str, str] = {}
    if is_htmx:
        push_params: dict[str, str] = {"q": results.query}
        if page_token:
            push_params["page_token"] = page_token
        headers["HX-Push-Url"] = f"/search?{urlencode(push_params)}"

    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context={
            "user_email": session.email,
            "results": results,
        },
        headers=headers,
    )


@router.get("/threads/{thread_id}", response_model=None)
async def view_thread(
    request: Request,
    thread_id: Annotated[str, Path(max_length=128)],
    session: Annotated[SessionPayload, Depends(require_session)],
    gmail_client: Annotated[GmailClient, Depends(get_gmail_client)],
    templates: Annotated[Jinja2Templates, Depends(get_templates)],
    load_images: bool = Query(default=False),
    q: str = Query(default="in:inbox", max_length=500),
) -> Response:
    """Render full chronological thread conversation with sandboxed message iframes."""
    safe_thread_id = _validate_gmail_identifier(thread_id, "thread_id")
    try:
        thread = await gmail_client.get_thread_detail(
            session.access_token,
            safe_thread_id,
            allow_remote_images=load_images,
        )
    except GmailNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversation thread not found",
        ) from exc

    return templates.TemplateResponse(
        request=request,
        name="thread.html",
        context={
            "user_email": session.email,
            "thread": thread,
            "back_query": q,
        },
    )


@router.get("/messages/{message_id}/attachments/{attachment_id}", response_model=None)
async def download_attachment(
    message_id: Annotated[str, Path(max_length=128)],
    attachment_id: Annotated[str, Path(max_length=512)],
    session: Annotated[SessionPayload, Depends(require_session)],
    gmail_client: Annotated[GmailClient, Depends(get_gmail_client)],
    filename: str = Query(default="attachment.bin", max_length=255),
) -> Response:
    """Fetch attachment bytes from Gmail and force safe browser download."""
    safe_msg_id = _validate_gmail_identifier(message_id, "message_id")
    if not re.match(r"^[A-Za-z0-9_-]{1,512}$", attachment_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid attachment_id format",
        )

    try:
        raw_bytes = await gmail_client.get_attachment_bytes(
            session.access_token,
            message_id=safe_msg_id,
            attachment_id=attachment_id,
        )
    except GmailNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attachment not found",
        ) from exc

    headers = {
        "Content-Disposition": build_attachment_disposition(filename),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store",
    }
    return Response(
        content=raw_bytes,
        media_type="application/octet-stream",
        headers=headers,
    )
