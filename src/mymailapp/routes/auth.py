"""OAuth 2.0 login, PKCE callback, and token-revoking logout routes."""

from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from mymailapp.auth.oauth import (
    OAuthExchangeError,
    build_authorization_url,
    exchange_code_for_tokens,
    generate_pkce_pair,
    generate_state_nonce,
    revoke_token,
    verify_state,
)
from mymailapp.auth.session import (
    OAUTH_STATE_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    CookieCipher,
    InvalidSessionError,
    OAuthStatePayload,
    SessionPayload,
)
from mymailapp.config import Settings
from mymailapp.dependencies import (
    get_cookie_cipher,
    get_gmail_client,
    get_http_client,
    get_settings,
    get_templates,
)
from mymailapp.gmail.client import GmailApiError, GmailClient

router = APIRouter(prefix="/auth", tags=["auth"])


def _verify_same_origin_post(request: Request, settings: Settings) -> None:
    """Enforce CSRF protection on state-changing POST endpoints."""
    sec_fetch = request.headers.get("sec-fetch-site", "").lower()
    if sec_fetch and sec_fetch not in {"same-origin", "none"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-site POST denied")

    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != settings.app_base_url:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin mismatch")


@router.get("/login", response_model=None)
async def login_page(
    request: Request,
    templates: Annotated[Jinja2Templates, Depends(get_templates)],
    error: str | None = Query(default=None, max_length=120),
) -> Response:
    """Render minimal sign-in landing screen explaining the read-only permission."""
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": error},
    )


@router.get("/start", response_model=None)
async def start_oauth_flow(
    settings: Annotated[Settings, Depends(get_settings)],
    cipher: Annotated[CookieCipher, Depends(get_cookie_cipher)],
) -> RedirectResponse:
    """Mint PKCE S256 verifier + CSRF state cookie and redirect to Google OAuth."""
    verifier, challenge = generate_pkce_pair()
    state = generate_state_nonce()
    sealed_state = cipher.seal_oauth_state(OAuthStatePayload(state=state, code_verifier=verifier))
    auth_url = build_authorization_url(settings, state=state, code_challenge=challenge)

    response = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key=settings.oauth_state_cookie_name,
        value=sealed_state,
        max_age=OAUTH_STATE_TTL_SECONDS,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/callback", response_model=None)
async def oauth_callback(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    cipher: Annotated[CookieCipher, Depends(get_cookie_cipher)],
    http_client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
    gmail_client: Annotated[GmailClient, Depends(get_gmail_client)],
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> RedirectResponse:
    """Validate PKCE/state, exchange authorization code, and establish AEAD session."""
    if error:
        resp = RedirectResponse(
            url="/auth/login?error=Google+sign-in+was+cancelled+or+denied",
            status_code=status.HTTP_302_FOUND,
        )
        resp.delete_cookie(key=settings.oauth_state_cookie_name, path="/")
        return resp

    raw_state_cookie = request.cookies.get(settings.oauth_state_cookie_name)
    if not raw_state_cookie or not code:
        return RedirectResponse(
            url="/auth/login?error=Missing+OAuth+login+state.+Please+try+again.",
            status_code=status.HTTP_302_FOUND,
        )

    try:
        oauth_state = cipher.unseal_oauth_state(raw_state_cookie)
        verify_state(expected=oauth_state.state, received=state)
        tokens = await exchange_code_for_tokens(
            http_client,
            settings,
            code=code,
            code_verifier=oauth_state.code_verifier,
        )
        user_email = await gmail_client.get_profile_email(tokens.access_token)
    except (InvalidSessionError, OAuthExchangeError, GmailApiError):
        resp = RedirectResponse(
            url="/auth/login?error=Authentication+verification+failed.+Please+sign+in+again.",
            status_code=status.HTTP_302_FOUND,
        )
        resp.delete_cookie(key=settings.oauth_state_cookie_name, path="/")
        return resp

    session_payload = SessionPayload(
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=tokens.compute_expires_at(),
        email=user_email,
    )
    sealed_session = cipher.seal_session(session_payload)

    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key=settings.oauth_state_cookie_name, path="/")
    response.set_cookie(
        key=settings.session_cookie_name,
        value=sealed_session,
        max_age=SESSION_TTL_SECONDS,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.post("/logout", response_model=None)
async def logout(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    cipher: Annotated[CookieCipher, Depends(get_cookie_cipher)],
    http_client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
) -> RedirectResponse:
    """Revoke OAuth token server-side at Google and purge the encrypted session cookie."""
    _verify_same_origin_post(request, settings)

    raw_cookie = request.cookies.get(settings.session_cookie_name)
    if raw_cookie:
        try:
            session = cipher.unseal_session(raw_cookie)
            token_to_revoke = session.refresh_token or session.access_token
            await revoke_token(http_client, token_to_revoke)
        except InvalidSessionError:
            pass

    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key=settings.session_cookie_name, path="/")
    return response
