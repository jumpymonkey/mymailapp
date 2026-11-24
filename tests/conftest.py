"""Pure pytest fixtures for MyMailApp unit and integration tests."""

import time

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from mymailapp.auth.session import CookieCipher, SessionPayload
from mymailapp.config import Settings


@pytest.fixture
def fernet_key() -> str:
    return Fernet.generate_key().decode("ascii")


@pytest.fixture
def dev_settings(fernet_key: str) -> Settings:
    return Settings(
        environment="development",
        app_base_url="http://localhost:8000",
        google_client_id="test-client-id.apps.googleusercontent.com",
        google_client_secret=SecretStr("test-client-secret"),
        session_encryption_key=SecretStr(fernet_key),
    )


@pytest.fixture
def prod_settings(fernet_key: str) -> Settings:
    return Settings(
        environment="production",
        app_base_url="https://mymailapp-123456789.us-central1.run.app",
        google_client_id="prod-client-id.apps.googleusercontent.com",
        google_client_secret=SecretStr("prod-client-secret"),
        session_encryption_key=SecretStr(fernet_key),
    )


@pytest.fixture
def cookie_cipher(fernet_key: str) -> CookieCipher:
    return CookieCipher(fernet_key)


@pytest.fixture
def valid_session() -> SessionPayload:
    return SessionPayload(
        access_token="mock-valid-access-token",
        refresh_token="mock-valid-refresh-token",
        expires_at=int(time.time()) + 3600,
        email="user@example.com",
    )


@pytest.fixture
def expiring_session() -> SessionPayload:
    return SessionPayload(
        access_token="mock-expiring-access-token",
        refresh_token="mock-valid-refresh-token",
        expires_at=int(time.time()) + 15,
        email="user@example.com",
    )
