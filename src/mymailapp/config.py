"""Strict runtime configuration loaded from environment variables."""

from typing import Literal
from urllib.parse import urlparse

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings validated strictly at startup."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
        frozen=True,
    )

    environment: Literal["development", "production"] = "development"
    app_base_url: str = "http://localhost:8000"
    google_client_id: str
    google_client_secret: SecretStr
    session_encryption_key: SecretStr
    gmail_max_concurrency: int = Field(default=10, ge=1, le=25)
    inline_cid_max_bytes: int = Field(default=2_097_152, ge=1024)

    @field_validator("app_base_url")
    @classmethod
    def validate_app_base_url(cls, value: str) -> str:
        normalized = value.strip().rstrip("/")
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            msg = "app_base_url must be a valid http:// or https:// origin"
            raise ValueError(msg)
        return normalized

    @field_validator("google_client_id")
    @classmethod
    def validate_non_empty_client_id(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            msg = "google_client_id must not be empty"
            raise ValueError(msg)
        return stripped

    @field_validator("google_client_secret")
    @classmethod
    def validate_non_empty_client_secret(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            msg = "google_client_secret must not be empty"
            raise ValueError(msg)
        return value

    @field_validator("session_encryption_key")
    @classmethod
    def validate_fernet_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        try:
            Fernet(raw.encode("ascii"))
        except (ValueError, TypeError) as exc:
            msg = "session_encryption_key must be a valid 32-byte urlsafe base64 Fernet key"
            raise ValueError(msg) from exc
        return SecretStr(raw)

    @model_validator(mode="after")
    def enforce_https_in_production(self) -> "Settings":
        if self.environment == "production" and not self.app_base_url.startswith("https://"):
            msg = "app_base_url must use https:// when environment='production'"
            raise ValueError(msg)
        return self

    @property
    def redirect_uri(self) -> str:
        return f"{self.app_base_url}/auth/callback"

    @property
    def cookie_secure(self) -> bool:
        return self.environment == "production"

    @property
    def session_cookie_name(self) -> str:
        return "__Host-session" if self.cookie_secure else "dev_session"

    @property
    def oauth_state_cookie_name(self) -> str:
        return "__Host-oauth_state" if self.cookie_secure else "dev_oauth_state"
