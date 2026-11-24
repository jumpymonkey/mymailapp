"""Unit tests for async GmailClient search hydration and error mapping."""

import httpx
import pytest
import respx

from mymailapp.auth.oauth import ReauthRequiredError
from mymailapp.gmail.client import (
    GMAIL_USER_BASE_URL,
    GmailAccessNotConfiguredError,
    GmailClient,
    GmailNotFoundError,
    GmailRateLimitError,
)


@respx.mock
async def test_search_threads_hydrates_concurrently() -> None:
    respx.get(f"{GMAIL_USER_BASE_URL}/threads").mock(
        return_value=httpx.Response(
            200,
            json={
                "threads": [{"id": "t1", "snippet": "First &amp; foremost"}],
                "nextPageToken": "page-2",
                "resultSizeEstimate": 42,
            },
        )
    )
    respx.get(f"{GMAIL_USER_BASE_URL}/threads/t1").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "t1",
                "messages": [
                    {
                        "id": "m1",
                        "snippet": "Latest reply",
                        "internalDate": "1764000000000",
                        "payload": {
                            "headers": [
                                {"name": "Subject", "value": "Cloud Run Budget"},
                                {"name": "From", "value": '"Alice" <alice@example.com>'},
                            ]
                        },
                    }
                ],
            },
        )
    )

    async with httpx.AsyncClient() as http:
        client = GmailClient(http)
        res = await client.search_threads("mock-access-tok", "from:alice")

    assert res.query == "from:alice"
    assert res.next_page_token == "page-2"
    assert len(res.threads) == 1
    assert res.threads[0].subject == "Cloud Run Budget"
    assert res.threads[0].participants == "Alice"


@pytest.mark.parametrize(
    ("status_code", "payload", "expected_exc"),
    [
        (401, {"error": {"message": "Invalid Credentials"}}, ReauthRequiredError),
        (404, {"error": {"message": "Not Found"}}, GmailNotFoundError),
        (429, {"error": {"message": "Too Many Requests"}}, GmailRateLimitError),
        (
            403,
            {"error": {"errors": [{"reason": "userRateLimitExceeded"}]}},
            GmailRateLimitError,
        ),
        (
            403,
            {"error": {"errors": [{"reason": "accessNotConfigured"}]}},
            GmailAccessNotConfiguredError,
        ),
    ],
)
@respx.mock
async def test_gmail_client_error_mapping(
    status_code: int,
    payload: dict[str, object],
    expected_exc: type[Exception],
) -> None:
    respx.get(f"{GMAIL_USER_BASE_URL}/profile").mock(
        return_value=httpx.Response(status_code, json=payload)
    )
    async with httpx.AsyncClient() as http:
        client = GmailClient(http)
        with pytest.raises(expected_exc):
            await client.get_profile_email("mock-access-tok")
