"""Unit tests for Google OAuth 2.0 PKCE S256, least-privilege scope, and token refresh."""

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from mymailapp.auth.oauth import (
    GMAIL_READONLY_SCOPE,
    GOOGLE_REVOKE_URL,
    GOOGLE_TOKEN_URL,
    OAuthExchangeError,
    ReauthRequiredError,
    build_authorization_url,
    exchange_code_for_tokens,
    generate_pkce_pair,
    refresh_access_token,
    revoke_token,
    verify_state,
)
from mymailapp.config import Settings


def test_pkce_s256_pair_matches_rfc7636() -> None:
    verifier, challenge = generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert challenge == expected


def test_authorization_url_requests_only_gmail_readonly(prod_settings: Settings) -> None:
    url = build_authorization_url(prod_settings, state="state-123", code_challenge="chal-456")
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    assert query["scope"] == [GMAIL_READONLY_SCOPE]
    assert query["code_challenge"] == ["chal-456"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["access_type"] == ["offline"]
    assert query["redirect_uri"] == [prod_settings.redirect_uri]


@pytest.mark.parametrize("bad_state", [None, "", "wrong-state"])
def test_verify_state_rejects_mismatch(bad_state: str | None) -> None:
    with pytest.raises(OAuthExchangeError, match="state"):
        verify_state("expected-state-value", bad_state)


@respx.mock
async def test_exchange_code_validates_granted_scope(dev_settings: Settings) -> None:
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-access-tok",
                "expires_in": 3599,
                "refresh_token": "mock-refresh-tok",
                "scope": "https://www.googleapis.com/auth/userinfo.email",
            },
        )
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(OAuthExchangeError, match=r"gmail\.readonly"):
            await exchange_code_for_tokens(
                client,
                dev_settings,
                code="auth-code",
                code_verifier="v" * 64,
            )


@respx.mock
async def test_refresh_invalid_grant_raises_reauth_required(dev_settings: Settings) -> None:
    """Testing-mode refresh tokens expire after 7 days with HTTP 400 invalid_grant."""
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "Token has been expired or revoked.",
            },
        )
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(ReauthRequiredError):
            await refresh_access_token(client, dev_settings, "mock-expired-7-day-token")


@respx.mock
async def test_revoke_token_swallows_network_errors_cleanly() -> None:
    respx.post(GOOGLE_REVOKE_URL).mock(side_effect=httpx.ConnectError("offline"))
    async with httpx.AsyncClient() as client:
        await revoke_token(client, "mock-some-token")
