"""Async HTTP/2 Gmail REST API v1 wrapper with bounded concurrency."""

import asyncio
import html
from typing import Any

import httpx
from pydantic import ValidationError

from mymailapp.auth.oauth import ReauthRequiredError
from mymailapp.gmail.mime import (
    decode_base64url,
    format_email_date,
    get_header_map,
    parse_gmail_message,
)
from mymailapp.gmail.models import (
    GmailAttachmentResponse,
    GmailProfileResponse,
    GmailThread,
    GmailThreadListItem,
    GmailThreadListResponse,
    SearchResultsView,
    ThreadDetailView,
    ThreadSummaryView,
)

GMAIL_USER_BASE_URL = "https://gmail.googleapis.com/gmail/v1/users/me"


class GmailApiError(Exception):
    """Base exception for upstream Gmail REST API errors."""


class GmailRateLimitError(GmailApiError):
    """Raised when Gmail API returns 429 or rateLimitExceeded."""


class GmailNotFoundError(GmailApiError):
    """Raised when a requested thread, message, or attachment does not exist."""


class GmailAccessNotConfiguredError(GmailApiError):
    """Raised when gmail.googleapis.com is disabled on the GCP project."""


class GmailClient:
    """Stateless async client for read-only Gmail v1 operations."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        max_concurrency: int = 10,
        inline_cid_max_bytes: int = 2_097_152,
    ) -> None:
        self._http = http_client
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._inline_cid_max_bytes = inline_cid_max_bytes

    async def _get_json(
        self,
        access_token: str,
        path: str,
        params: list[tuple[str, str]] | dict[str, str] | None = None,
    ) -> Any:
        url = f"{GMAIL_USER_BASE_URL}{path}"
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            async with self._semaphore:
                response = await self._http.get(url, headers=headers, params=params)
        except httpx.HTTPError as exc:
            raise GmailApiError("Upstream network error calling Gmail API") from exc

        if response.status_code == 401:
            raise ReauthRequiredError("Gmail API rejected access token with 401")
        if response.status_code == 404:
            raise GmailNotFoundError(f"Gmail resource not found: {path}")
        if response.status_code == 429:
            raise GmailRateLimitError("Gmail API quota temporarily exceeded")
        if response.status_code == 403:
            reason = self._extract_error_reason(response)
            if reason in {"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"}:
                raise GmailRateLimitError("Gmail API rate limit exceeded")
            if reason == "accessNotConfigured":
                raise GmailAccessNotConfiguredError(
                    "Gmail API is not enabled on the configured GCP project"
                )
            raise GmailApiError(f"Gmail API access forbidden ({reason or '403'})")
        if response.status_code != 200:
            raise GmailApiError(f"Gmail API returned unexpected HTTP {response.status_code}")

        try:
            return response.json()
        except ValueError as exc:
            raise GmailApiError("Malformed JSON returned by Gmail API") from exc

    @staticmethod
    def _extract_error_reason(response: httpx.Response) -> str:
        try:
            payload = response.json()
            errors = payload.get("error", {}).get("errors", [])
            if errors and isinstance(errors[0], dict):
                return str(errors[0].get("reason", ""))
        except (ValueError, AttributeError, TypeError):
            pass
        return ""

    async def get_profile_email(self, access_token: str) -> str:
        """Fetch the authenticated user's primary Gmail address via users.getProfile."""
        raw = await self._get_json(access_token, "/profile")
        try:
            profile = GmailProfileResponse.model_validate(raw)
        except ValidationError as exc:
            raise GmailApiError("Invalid profile payload from Gmail API") from exc
        return profile.emailAddress

    async def _hydrate_thread_summary(
        self,
        access_token: str,
        item: GmailThreadListItem,
    ) -> ThreadSummaryView:
        params: list[tuple[str, str]] = [
            ("format", "metadata"),
            ("metadataHeaders", "Subject"),
            ("metadataHeaders", "From"),
            ("metadataHeaders", "Date"),
        ]
        raw = await self._get_json(access_token, f"/threads/{item.id}", params=params)
        try:
            thread = GmailThread.model_validate(raw)
        except ValidationError as exc:
            raise GmailApiError("Invalid thread metadata payload") from exc

        if not thread.messages:
            return ThreadSummaryView(
                thread_id=thread.id,
                subject="(no subject)",
                participants="(unknown)",
                date_display="",
                message_count=0,
                snippet=html.unescape(item.snippet),
            )

        first_headers = (
            get_header_map(thread.messages[0].payload.headers) if thread.messages[0].payload else {}
        )
        last_msg = thread.messages[-1]
        last_headers = get_header_map(last_msg.payload.headers) if last_msg.payload else {}

        subject = first_headers.get("subject") or last_headers.get("subject") or "(no subject)"

        seen_senders: list[str] = []
        for msg in thread.messages:
            hdrs = get_header_map(msg.payload.headers) if msg.payload else {}
            raw_from = hdrs.get("from", "").strip()
            short_from = raw_from.split("<", maxsplit=1)[0].strip(' "') or raw_from
            if short_from and short_from not in seen_senders:
                seen_senders.append(short_from)

        participants = ", ".join(seen_senders[:3]) or "(unknown sender)"
        if len(seen_senders) > 3:
            participants += f" (+{len(seen_senders) - 3})"

        snippet_source = last_msg.snippet or item.snippet
        return ThreadSummaryView(
            thread_id=thread.id,
            subject=subject,
            participants=participants,
            date_display=format_email_date(last_headers.get("date"), last_msg.internalDate),
            message_count=len(thread.messages),
            snippet=html.unescape(snippet_source),
        )

    async def search_threads(
        self,
        access_token: str,
        query: str,
        *,
        page_token: str | None = None,
        max_results: int = 20,
    ) -> SearchResultsView:
        """Search Gmail threads using native query syntax and hydrate summaries concurrently."""
        effective_query = query.strip() or "in:inbox"
        params: dict[str, str] = {
            "q": effective_query,
            "maxResults": str(max_results),
        }
        if page_token:
            params["pageToken"] = page_token

        raw_list = await self._get_json(access_token, "/threads", params=params)
        try:
            thread_list = GmailThreadListResponse.model_validate(raw_list)
        except ValidationError as exc:
            raise GmailApiError("Invalid threads.list response from Gmail API") from exc

        if not thread_list.threads:
            return SearchResultsView(
                query=effective_query,
                threads=(),
                next_page_token=None,
                result_size_estimate=0,
            )

        summaries = await asyncio.gather(
            *(self._hydrate_thread_summary(access_token, item) for item in thread_list.threads)
        )
        return SearchResultsView(
            query=effective_query,
            threads=tuple(summaries),
            next_page_token=thread_list.nextPageToken,
            result_size_estimate=thread_list.resultSizeEstimate,
        )

    async def get_thread_detail(
        self,
        access_token: str,
        thread_id: str,
        *,
        allow_remote_images: bool = False,
    ) -> ThreadDetailView:
        """Fetch full thread conversation and parse/sanitize all messages."""
        raw = await self._get_json(
            access_token,
            f"/threads/{thread_id}",
            params={"format": "full"},
        )
        try:
            thread = GmailThread.model_validate(raw)
        except ValidationError as exc:
            raise GmailApiError("Invalid full thread payload from Gmail API") from exc

        parsed_messages = tuple(
            parse_gmail_message(
                msg,
                allow_remote_images=allow_remote_images,
                inline_cid_max_bytes=self._inline_cid_max_bytes,
            )
            for msg in thread.messages
        )
        subject = parsed_messages[0].subject if parsed_messages else "(no subject)"
        return ThreadDetailView(
            thread_id=thread.id,
            subject=subject,
            messages=parsed_messages,
            remote_images_loaded=allow_remote_images,
        )

    async def get_attachment_bytes(
        self,
        access_token: str,
        message_id: str,
        attachment_id: str,
    ) -> bytes:
        """Download and base64url-decode an attachment payload."""
        raw = await self._get_json(
            access_token,
            f"/messages/{message_id}/attachments/{attachment_id}",
        )
        try:
            att = GmailAttachmentResponse.model_validate(raw)
            return decode_base64url(att.data)
        except (ValidationError, ValueError) as exc:
            raise GmailApiError("Invalid attachment payload from Gmail API") from exc
