"""Validated settings. Service URLs are secrets and must never be logged."""

from ipaddress import ip_network
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_", extra="ignore", frozen=True, hide_input_in_errors=True
    )

    environment: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    database_url: SecretStr
    redis_url: SecretStr
    rabbitmq_url: SecretStr
    dependency_timeout_seconds: float = Field(default=3, ge=0.1, le=30)
    database_pool_size: int = Field(default=5, ge=1, le=50)
    database_max_overflow: int = Field(default=5, ge=0, le=50)
    trusted_proxy_cidrs: tuple[str, ...] = ()

    @field_validator("database_url", "redis_url", "rabbitmq_url")
    @classmethod
    def validate_url(cls, value: SecretStr, info):
        schemes = {
            "database_url": {"postgresql+asyncpg"},
            "redis_url": {"redis", "rediss"},
            "rabbitmq_url": {"amqp", "amqps"},
        }
        try:
            parsed = urlsplit(value.get_secret_value())
            if parsed.scheme not in schemes[info.field_name] or not parsed.hostname:
                raise ValueError
            _ = parsed.port
        except ValueError:
            raise ValueError(f"{info.field_name} must be a valid supported service URL") from None
        return value

    @field_validator("trusted_proxy_cidrs")
    @classmethod
    def validate_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(str(ip_network(value, strict=True)) for value in values)
