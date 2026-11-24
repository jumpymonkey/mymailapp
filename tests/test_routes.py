"""End-to-end async ASGI route tests covering OAuth, HTMX search, iframes, and downloads."""

import base64
from urllib.parse import parse_qs, urlparse

import httpx
import respx

from mymailapp.auth.oauth import GOOGLE_REVOKE_URL, GOOGLE_TOKEN_URL
from mymailapp.auth.session import CookieCipher, SessionPayload
from mymailapp.config import Settings
from mymailapp.gmail.client import GMAIL_USER_BASE_URL
from mymailapp.main import create_app


async def test_healthz_and_security_headers(prod_settings: Settings) -> None:
    async with httpx.AsyncClient() as upstream:
        app = create_app(settings=prod_settings, http_client=upstream)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=prod_settings.app_base_url,
        ) as client:
            resp = await client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


async def test_unauthenticated_redirect_and_htmx_redirect(prod_settings: Settings) -> None:
    async with httpx.AsyncClient() as upstream:
        app = create_app(settings=prod_settings, http_client=upstream)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=prod_settings.app_base_url,
            follow_redirects=False,
        ) as client:
            std_resp = await client.get("/")
            htmx_resp = await client.get("/search?q=test", headers={"HX-Request": "true"})

    assert std_resp.status_code == 302
    assert std_resp.headers["Location"] == "/auth/login"
    assert htmx_resp.status_code == 200
    assert htmx_resp.headers["HX-Redirect"] == "/auth/login"


@respx.mock
async def test_full_oauth_pkce_login_search_thread_and_attachment_flow(
    prod_settings: Settings,
) -> None:
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-fresh-token",
                "expires_in": 3600,
                "refresh_token": "mock-refresh-tok",
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
            },
        )
    )
    respx.get(f"{GMAIL_USER_BASE_URL}/profile").mock(
        return_value=httpx.Response(200, json={"emailAddress": "user@example.com"})
    )
    respx.get(f"{GMAIL_USER_BASE_URL}/threads").mock(
        return_value=httpx.Response(
            200,
            json={"threads": [{"id": "thr_abc123", "snippet": "Hello world"}]},
        )
    )
    html_body = base64.urlsafe_b64encode(
        b'<p>Body text</p><script>evil()</script><img src="https://pixel.example/p.gif">'
    ).decode("ascii")
    respx.get(f"{GMAIL_USER_BASE_URL}/threads/thr_abc123").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "thr_abc123",
                "messages": [
                    {
                        "id": "msg_001",
                        "snippet": "Hello world",
                        "payload": {
                            "mimeType": "multipart/mixed",
                            "headers": [
                                {"name": "Subject", "value": "Quarterly Review"},
                                {"name": "From", "value": "Alice <alice@example.org>"},
                                {"name": "To", "value": "user@example.com"},
                            ],
                            "parts": [
                                {"mimeType": "text/html", "body": {"data": html_body}},
                                {
                                    "mimeType": "application/pdf",
                                    "filename": "Report €2026.pdf",
                                    "body": {"attachmentId": "att_999", "size": 12},
                                },
                            ],
                        },
                    }
                ],
            },
        )
    )
    pdf_bytes = b"%PDF-1.7-bin"
    respx.get(f"{GMAIL_USER_BASE_URL}/messages/msg_001/attachments/att_999").mock(
        return_value=httpx.Response(
            200,
            json={
                "size": len(pdf_bytes),
                "data": base64.urlsafe_b64encode(pdf_bytes).rstrip(b"=").decode("ascii"),
            },
        )
    )
    revoke_route = respx.post(GOOGLE_REVOKE_URL).mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as upstream:
        app = create_app(settings=prod_settings, http_client=upstream)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=prod_settings.app_base_url,
            follow_redirects=False,
        ) as client:
            # 1. Start OAuth flow
            start_resp = await client.get("/auth/start")
            assert start_resp.status_code == 302
            state_param = parse_qs(urlparse(start_resp.headers["Location"]).query)["state"][0]
            assert "__Host-oauth_state" in client.cookies

            # 2. Complete OAuth callback
            cb_resp = await client.get(
                "/auth/callback",
                params={"code": "google-code-xyz", "state": state_param},
            )
            assert cb_resp.status_code == 302
            assert cb_resp.headers["Location"] == "/"
            session_cookie = client.cookies.get("__Host-session")
            assert session_cookie is not None
            assert "mock-fresh-token" not in session_cookie

            # 3. Search inbox (full page + HTMX partial)
            inbox_resp = await client.get("/")
            assert inbox_resp.status_code == 200
            assert "user@example.com" in inbox_resp.text
            assert "Quarterly Review" in inbox_resp.text

            htmx_search = await client.get(
                "/search?q=from:alice",
                headers={"HX-Request": "true"},
            )
            assert htmx_search.status_code == 200
            assert htmx_search.headers["HX-Push-Url"] == "/search?q=from%3Aalice"
            assert "<!doctype html>" not in htmx_search.text.lower()

            # 4. View full thread (sandboxed iframe + sanitized HTML + blocked pixel)
            thread_resp = await client.get("/threads/thr_abc123")
            assert thread_resp.status_code == 200
            assert 'sandbox=""' in thread_resp.text
            assert "evil()" not in thread_resp.text
            assert "Load remote images" in thread_resp.text
            assert "Report" in thread_resp.text

            # 5. Download attachment with Unicode RFC 5987 header
            dl_resp = await client.get(
                "/messages/msg_001/attachments/att_999",
                params={"filename": "Report €2026.pdf"},
            )
            assert dl_resp.status_code == 200
            assert dl_resp.content == pdf_bytes
            assert dl_resp.headers["Content-Type"] == "application/octet-stream"
            assert "UTF-8''Report%20%E2%82%AC2026.pdf" in dl_resp.headers["Content-Disposition"]

            # 6. Cross-origin logout blocked; same-origin logout revokes token
            csrf_logout = await client.post(
                "/auth/logout",
                headers={"Origin": "https://evil.example"},
            )
            assert csrf_logout.status_code == 403

            ok_logout = await client.post(
                "/auth/logout",
                headers={"Origin": prod_settings.app_base_url},
            )
            assert ok_logout.status_code == 303
            assert revoke_route.called


@respx.mock
async def test_silent_access_token_refresh_rotates_cookie(
    prod_settings: Settings,
    cookie_cipher: CookieCipher,
    expiring_session: SessionPayload,
) -> None:
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-rotated-new-token",
                "expires_in": 3600,
            },
        )
    )
    respx.get(f"{GMAIL_USER_BASE_URL}/threads").mock(
        return_value=httpx.Response(200, json={"threads": []})
    )

    async with httpx.AsyncClient() as upstream:
        app = create_app(settings=prod_settings, http_client=upstream)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=prod_settings.app_base_url,
            cookies={"__Host-session": cookie_cipher.seal_session(expiring_session)},
        ) as client:
            resp = await client.get("/search?q=in:inbox")

    assert resp.status_code == 200
    assert "__Host-session=" in resp.headers.get("set-cookie", "")
