"""FastAPI application factory, security middleware, and lifespan management."""

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from mymailapp.auth.oauth import ReauthRequiredError
from mymailapp.auth.session import SESSION_TTL_SECONDS, CookieCipher, SessionPayload
from mymailapp.config import Settings
from mymailapp.gmail.client import (
    GmailAccessNotConfiguredError,
    GmailApiError,
    GmailClient,
    GmailRateLimitError,
)
from mymailapp.routes import auth as auth_routes
from mymailapp.routes import mail as mail_routes

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)


def create_app(
    settings: Settings | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Construct the FastAPI ASGI application with lifespan-managed HTTP/2 pooling."""
    resolved_settings = settings or Settings()  # type: ignore[call-arg]
    owns_client = http_client is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        client = http_client or httpx.AsyncClient(
            http2=True,
            timeout=httpx.Timeout(15.0, connect=5.0),
        )
        app.state.settings = resolved_settings
        app.state.http_client = client
        app.state.cookie_cipher = CookieCipher(
            resolved_settings.session_encryption_key.get_secret_value()
        )
        app.state.gmail_client = GmailClient(
            client,
            max_concurrency=resolved_settings.gmail_max_concurrency,
            inline_cid_max_bytes=resolved_settings.inline_cid_max_bytes,
        )
        app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
        try:
            yield
        finally:
            if owns_client:
                await client.aclose()

    app = FastAPI(
        title="MyMailApp",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # Pre-populate state so unit tests without lifespan entry still resolve dependencies cleanly
    if http_client is not None:
        app.state.settings = resolved_settings
        app.state.http_client = http_client
        app.state.cookie_cipher = CookieCipher(
            resolved_settings.session_encryption_key.get_secret_value()
        )
        app.state.gmail_client = GmailClient(
            http_client,
            max_concurrency=resolved_settings.gmail_max_concurrency,
            inline_cid_max_bytes=resolved_settings.inline_cid_max_bytes,
        )
        app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.middleware("http")
    async def security_headers_and_cookie_rotation(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        updated_session: SessionPayload | None = getattr(request.state, "updated_session", None)
        if updated_session is not None:
            cipher: CookieCipher = request.app.state.cookie_cipher
            response.set_cookie(
                key=resolved_settings.session_cookie_name,
                value=cipher.seal_session(updated_session),
                max_age=SESSION_TTL_SECONDS,
                path="/",
                secure=resolved_settings.cookie_secure,
                httponly=True,
                samesite="lax",
            )

        response.headers.setdefault("Content-Security-Policy", CSP_POLICY)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        if request.url.path not in {"/health", "/healthz"} and not request.url.path.startswith(
            "/static/"
        ):
            response.headers.setdefault("Cache-Control", "private, no-store")
        return response

    @app.exception_handler(ReauthRequiredError)
    async def handle_reauth(request: Request, _exc: ReauthRequiredError) -> Response:
        is_htmx = request.headers.get("hx-request", "").lower() == "true"
        if is_htmx:
            resp = Response(
                status_code=status.HTTP_200_OK,
                headers={"HX-Redirect": "/auth/login"},
            )
        else:
            resp = RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)
        resp.delete_cookie(key=resolved_settings.session_cookie_name, path="/")
        return resp

    @app.exception_handler(GmailRateLimitError)
    async def handle_rate_limit(request: Request, _exc: GmailRateLimitError) -> Response:
        templates: Jinja2Templates = request.app.state.templates
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "Gmail Quota Temporarily Reached",
                "message": "Please wait a few seconds before running another inbox search.",
            },
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": "10"},
        )

    @app.exception_handler(GmailAccessNotConfiguredError)
    async def handle_api_disabled(
        request: Request, _exc: GmailAccessNotConfiguredError
    ) -> Response:
        templates: Jinja2Templates = request.app.state.templates
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "Gmail API Not Enabled",
                "message": "Enable gmail.googleapis.com in your GCP project and try again.",
            },
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    @app.exception_handler(GmailApiError)
    async def handle_gmail_error(request: Request, _exc: GmailApiError) -> Response:
        templates: Jinja2Templates = request.app.state.templates
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "title": "Upstream Gmail Error",
                "message": "Unable to complete the read request against Gmail right now.",
            },
            status_code=status.HTTP_502_BAD_GATEWAY,
        )

    @app.get("/health", include_in_schema=False)
    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok"})

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(auth_routes.router)
    app.include_router(mail_routes.router)

    return app
