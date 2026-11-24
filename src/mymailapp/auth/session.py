"""AEAD-encrypted browser cookie payloads with strict 4 KB size enforcement."""

import time

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_COOKIE_CIPHERTEXT_BYTES = 3800
SESSION_TTL_SECONDS = 7 * 24 * 3600
OAUTH_STATE_TTL_SECONDS = 300


class SessionError(Exception):
    """Base exception for cookie sealing and unsealing errors."""


class InvalidSessionError(SessionError):
    """Raised when a cookie is missing, expired, malformed, or tampered with."""


class SessionOverflowError(SessionError):
    """Raised when an encrypted cookie payload exceeds browser storage limits."""


class OAuthStatePayload(BaseModel):
    """Short-lived PKCE verifier and CSRF state bound to the login handshake."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: str = Field(min_length=16)
    code_verifier: str = Field(min_length=43, max_length=128)


class SessionPayload(BaseModel):
    """Stateless OAuth token bundle stored encrypted in the session cookie."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    access_token: str = Field(min_length=1)
    refresh_token: str | None = None
    expires_at: int
    email: str = Field(min_length=3)

    def needs_refresh(self, now: int | None = None, leeway_seconds: int = 60) -> bool:
        current_ts = int(time.time()) if now is None else now
        return (self.expires_at - current_ts) <= leeway_seconds


class CookieCipher:
    """Seals and unseals Pydantic payloads using Fernet AEAD."""

    def __init__(self, fernet_key: str) -> None:
        self._fernet = Fernet(fernet_key.encode("ascii"))

    def _encrypt_json(self, json_str: str) -> str:
        ciphertext = self._fernet.encrypt(json_str.encode("utf-8")).decode("ascii")
        if len(ciphertext.encode("ascii")) > MAX_COOKIE_CIPHERTEXT_BYTES:
            msg = (
                f"Encrypted cookie size ({len(ciphertext)} bytes) exceeds safe "
                f"{MAX_COOKIE_CIPHERTEXT_BYTES}-byte limit"
            )
            raise SessionOverflowError(msg)
        return ciphertext

    def seal_session(self, payload: SessionPayload) -> str:
        return self._encrypt_json(payload.model_dump_json())

    def unseal_session(
        self,
        token: str,
        ttl_seconds: int = SESSION_TTL_SECONDS,
    ) -> SessionPayload:
        try:
            plaintext = self._fernet.decrypt(token.encode("ascii"), ttl=ttl_seconds)
            return SessionPayload.model_validate_json(plaintext)
        except (InvalidToken, ValidationError, ValueError, UnicodeEncodeError) as exc:
            raise InvalidSessionError("Session cookie is invalid or expired") from exc

    def seal_oauth_state(self, payload: OAuthStatePayload) -> str:
        return self._encrypt_json(payload.model_dump_json())

    def unseal_oauth_state(
        self,
        token: str,
        ttl_seconds: int = OAUTH_STATE_TTL_SECONDS,
    ) -> OAuthStatePayload:
        try:
            plaintext = self._fernet.decrypt(token.encode("ascii"), ttl=ttl_seconds)
            return OAuthStatePayload.model_validate_json(plaintext)
        except (InvalidToken, ValidationError, ValueError, UnicodeEncodeError) as exc:
            raise InvalidSessionError("OAuth state cookie is invalid or expired") from exc
