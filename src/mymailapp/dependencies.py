"""FastAPI dependency injection providers and silent session refresh guard."""

from typing import Annotated, cast

import httpx
from fastapi import Depends, Request
from fastapi.templating import Jinja2Templates

from mymailapp.auth.oauth import ReauthRequiredError, refresh_access_token
from mymailapp.auth.session import CookieCipher, InvalidSessionError, SessionPayload
from mymailapp.config import Settings
from mymailapp.gmail.client import GmailClient


def get_settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def get_http_client(request: Request) -> httpx.AsyncClient:
    return cast(httpx.AsyncClient, request.app.state.http_client)


def get_cookie_cipher(request: Request) -> CookieCipher:
    return cast(CookieCipher, request.app.state.cookie_cipher)


def get_gmail_client(request: Request) -> GmailClient:
    return cast(GmailClient, request.app.state.gmail_client)


def get_templates(request: Request) -> Jinja2Templates:
    return cast(Jinja2Templates, request.app.state.templates)


async def require_session(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    cipher: Annotated[CookieCipher, Depends(get_cookie_cipher)],
    http_client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
) -> SessionPayload:
    """Validate encrypted session cookie and transparently refresh expiring access tokens."""
    raw_cookie = request.cookies.get(settings.session_cookie_name)
    if not raw_cookie:
        raise ReauthRequiredError("No active session cookie")

    try:
        session = cipher.unseal_session(raw_cookie)
    except InvalidSessionError as exc:
        raise ReauthRequiredError("Invalid or expired session cookie") from exc

    if not session.needs_refresh():
        return session

    if not session.refresh_token:
        raise ReauthRequiredError("Access token expired and no refresh token available")

    refreshed = await refresh_access_token(http_client, settings, session.refresh_token)
    rotated = SessionPayload(
        access_token=refreshed.access_token,
        refresh_token=refreshed.refresh_token or session.refresh_token,
        expires_at=refreshed.compute_expires_at(),
        email=session.email,
    )
    request.state.updated_session = rotated
    return rotated
