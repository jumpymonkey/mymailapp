"""Unit tests for AEAD cookie encryption, tampering detection, and 4 KB guardrails."""

import pytest
from cryptography.fernet import Fernet

from mymailapp.auth.session import (
    CookieCipher,
    InvalidSessionError,
    OAuthStatePayload,
    SessionOverflowError,
    SessionPayload,
)


def test_session_seal_and_unseal_roundtrip(
    cookie_cipher: CookieCipher,
    valid_session: SessionPayload,
) -> None:
    sealed = cookie_cipher.seal_session(valid_session)
    assert valid_session.access_token not in sealed
    assert valid_session.email not in sealed

    unsealed = cookie_cipher.unseal_session(sealed)
    assert unsealed == valid_session


def test_oauth_state_roundtrip(cookie_cipher: CookieCipher) -> None:
    payload = OAuthStatePayload(
        state="a" * 24,
        code_verifier="v" * 64,
    )
    sealed = cookie_cipher.seal_oauth_state(payload)
    assert cookie_cipher.unseal_oauth_state(sealed) == payload


@pytest.mark.parametrize(
    "corrupt_fn",
    [
        lambda tok: tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB"),
        lambda tok: tok[:12],
        lambda _tok: "plain-unencrypted-junk",
        lambda _tok: "",
    ],
)
def test_tampered_session_cookie_raises(
    cookie_cipher: CookieCipher,
    valid_session: SessionPayload,
    corrupt_fn: object,
) -> None:
    sealed = cookie_cipher.seal_session(valid_session)
    corrupted = corrupt_fn(sealed)  # type: ignore[operator]
    with pytest.raises(InvalidSessionError):
        cookie_cipher.unseal_session(corrupted)


def test_wrong_fernet_key_rejected(
    cookie_cipher: CookieCipher,
    valid_session: SessionPayload,
) -> None:
    sealed = cookie_cipher.seal_session(valid_session)
    other_cipher = CookieCipher(Fernet.generate_key().decode("ascii"))
    with pytest.raises(InvalidSessionError):
        other_cipher.unseal_session(sealed)


def test_expired_ttl_rejected(
    cookie_cipher: CookieCipher,
    valid_session: SessionPayload,
) -> None:
    sealed = cookie_cipher.seal_session(valid_session)
    with pytest.raises(InvalidSessionError):
        cookie_cipher.unseal_session(sealed, ttl_seconds=-1)


def test_session_overflow_above_4kb_ceiling_raises(cookie_cipher: CookieCipher) -> None:
    oversized = SessionPayload(
        access_token="x" * 4000,
        refresh_token="r" * 500,
        expires_at=9999999999,
        email="user@example.com",
    )
    with pytest.raises(SessionOverflowError, match="exceeds safe"):
        cookie_cipher.seal_session(oversized)
