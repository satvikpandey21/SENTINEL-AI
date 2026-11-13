"""Administrative settings are never loaded by the demonstration service."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AdminSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_ADMIN_", extra="ignore", frozen=True, hide_input_in_errors=True
    )
    signing_key: SecretStr
    issuer: str = Field(default="sentinel-admin", min_length=1, max_length=128)
    audience: str = Field(default="sentinel-dashboard", min_length=1, max_length=128)
    access_seconds: int = Field(default=300, ge=60, le=900)
    session_seconds: int = Field(default=28800, ge=300, le=86400)
    cookie_secure: bool = True
    deployment: Literal["development", "production"] = "production"
    allowed_origins: tuple[str, ...] = ("https://localhost",)
    login_attempts: int = Field(default=10, ge=3, le=30)
    login_window_seconds: int = Field(default=300, ge=30, le=3600)

    @field_validator("signing_key")
    @classmethod
    def key_strength(cls, value):
        key = value.get_secret_value()
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("signing key must be 32 random bytes encoded as lowercase hex")
        return value

    @model_validator(mode="after")
    def browser_boundary(self):
        if not self.allowed_origins or len(self.allowed_origins) > 8:
            raise ValueError("configure 1..8 explicit frontend origins")
        for origin in self.allowed_origins:
            try:
                parsed = urlsplit(origin)
                _ = parsed.port
            except ValueError:
                raise ValueError("origins must contain a valid host and port") from None
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("origins must be exact HTTP(S) origins without paths")
            if self.deployment == "production" and parsed.scheme != "https":
                raise ValueError("production requires HTTPS origins")
        if self.deployment == "production" and not self.cookie_secure:
            raise ValueError("production requires Secure cookies")
        return self

    @property
    def cookie_name(self):
        return "__Secure-sentinel-refresh" if self.cookie_secure else "sentinel-refresh"
