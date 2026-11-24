"""Unit tests for strict Pydantic Settings validation."""

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError

from mymailapp.config import Settings


def test_settings_cookie_names_by_environment(
    dev_settings: Settings,
    prod_settings: Settings,
) -> None:
    assert dev_settings.cookie_secure is False
    assert dev_settings.session_cookie_name == "dev_session"
    assert dev_settings.oauth_state_cookie_name == "dev_oauth_state"
    assert dev_settings.redirect_uri == "http://localhost:8000/auth/callback"

    assert prod_settings.cookie_secure is True
    assert prod_settings.session_cookie_name == "__Host-session"
    assert prod_settings.oauth_state_cookie_name == "__Host-oauth_state"
    assert (
        prod_settings.redirect_uri
        == "https://mymailapp-123456789.us-central1.run.app/auth/callback"
    )


@pytest.mark.parametrize(
    ("overrides", "expected_match"),
    [
        ({"environment": "production", "app_base_url": "http://insecure.example.com"}, "https://"),
        ({"app_base_url": "ftp://invalid.example.com"}, "http:// or https://"),
        ({"google_client_id": "   "}, "must not be empty"),
        ({"google_client_secret": SecretStr("  ")}, "must not be empty"),
        ({"session_encryption_key": SecretStr("not-a-valid-fernet-key")}, "Fernet key"),
    ],
)
def test_settings_rejects_invalid_inputs(
    fernet_key: str,
    overrides: dict[str, object],
    expected_match: str,
) -> None:
    base_kwargs: dict[str, object] = {
        "environment": "development",
        "app_base_url": "http://localhost:8000",
        "google_client_id": "client.apps.googleusercontent.com",
        "google_client_secret": SecretStr("secret"),
        "session_encryption_key": SecretStr(fernet_key),
    }
    base_kwargs.update(overrides)
    with pytest.raises(ValidationError, match=expected_match):
        Settings(**base_kwargs)  # type: ignore[arg-type]


def test_settings_forbids_extra_fields() -> None:
    key = Fernet.generate_key().decode("ascii")
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Settings(
            google_client_id="id",
            google_client_secret=SecretStr("secret"),
            session_encryption_key=SecretStr(key),
            undeclared_field="nope",  # type: ignore[call-arg]
        )
