"""Google OAuth 2.0 Authorization Code + PKCE (S256) with strict gmail.readonly scope."""

import base64
import hashlib
import hmac
import logging
import secrets
import time
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mymailapp.config import Settings

logger = logging.getLogger(__name__)

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"


class OAuthError(Exception):
    """Base error for Google OAuth 2.0 operations."""


class ReauthRequiredError(OAuthError):
    """Raised when credentials are missing, expired, or rejected with invalid_grant."""


class OAuthExchangeError(OAuthError):
    """Raised when authorization code exchange or CSRF state validation fails."""


class TokenEndpointResponse(BaseModel):
    """Subset of Google's OAuth 2.0 token endpoint JSON response."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    access_token: str = Field(min_length=1)
    expires_in: int = Field(ge=1)
    refresh_token: str | None = None
    scope: str = ""
    token_type: str = "Bearer"  # noqa: S105

    def compute_expires_at(self, now: int | None = None) -> int:
        base_ts = int(time.time()) if now is None else now
        return base_ts + self.expires_in


def generate_pkce_pair() -> tuple[str, str]:
    """Return a cryptographic (code_verifier, code_challenge) S256 pair."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def generate_state_nonce() -> str:
    """Return a URL-safe random CSRF state token."""
    return secrets.token_urlsafe(24)


def verify_state(expected: str, received: str | None) -> None:
    """Verify OAuth callback state in constant time."""
    if not received or not hmac.compare_digest(expected, received):
        raise OAuthExchangeError("OAuth state parameter mismatch")


def build_authorization_url(settings: Settings, state: str, code_challenge: str) -> str:
    """Build the least-privilege Google OAuth 2.0 consent URL."""
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READONLY_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent select_account",
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_tokens(
    http_client: httpx.AsyncClient,
    settings: Settings,
    code: str,
    code_verifier: str,
) -> TokenEndpointResponse:
    """Exchange an authorization code and PKCE verifier for access/refresh tokens."""
    form_data = {
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret.get_secret_value(),
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": settings.redirect_uri,
    }
    try:
        response = await http_client.post(GOOGLE_TOKEN_URL, data=form_data)
    except httpx.HTTPError as exc:
        raise OAuthExchangeError("Network failure contacting Google token endpoint") from exc

    if response.status_code != 200:
        raise OAuthExchangeError(f"Token exchange failed with HTTP {response.status_code}")

    try:
        token_resp = TokenEndpointResponse.model_validate(response.json())
    except (ValidationError, ValueError) as exc:
        raise OAuthExchangeError("Malformed token response from Google") from exc

    granted_scopes = set(token_resp.scope.split())
    if granted_scopes and GMAIL_READONLY_SCOPE not in granted_scopes:
        raise OAuthExchangeError("Required gmail.readonly scope was not granted by user")

    return token_resp


async def refresh_access_token(
    http_client: httpx.AsyncClient,
    settings: Settings,
    refresh_token: str,
) -> TokenEndpointResponse:
    """Refresh an expired access token; translate invalid_grant into ReauthRequiredError."""
    form_data = {
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret.get_secret_value(),
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    try:
        response = await http_client.post(GOOGLE_TOKEN_URL, data=form_data)
    except httpx.HTTPError as exc:
        raise OAuthError("Temporary network failure refreshing OAuth token") from exc

    if response.status_code in {400, 401}:
        try:
            err_body = response.json()
        except ValueError:
            err_body = {}
        if err_body.get("error") == "invalid_grant" or response.status_code == 401:
            raise ReauthRequiredError("Refresh token expired or revoked")
        raise OAuthError(f"Token refresh failed with HTTP {response.status_code}")

    if response.status_code != 200:
        raise OAuthError(f"Token refresh failed with HTTP {response.status_code}")

    try:
        return TokenEndpointResponse.model_validate(response.json())
    except (ValidationError, ValueError) as exc:
        raise OAuthError("Malformed refresh response from Google") from exc


async def revoke_token(http_client: httpx.AsyncClient, token: str) -> None:
    """Best-effort server-side token revocation at Google."""
    try:
        response = await http_client.post(GOOGLE_REVOKE_URL, data={"token": token})
        if response.status_code not in {200, 400}:
            logger.warning("Unexpected status %s from Google token revoke", response.status_code)
    except httpx.HTTPError:
        logger.warning("Network error during best-effort token revocation")
