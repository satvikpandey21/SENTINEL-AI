"""Validated settings. Service URLs are secrets and must never be logged."""

from ipaddress import ip_network
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinel_security.policies import EndpointPolicy, default_policies, validate_policies


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

    protection_enabled: bool = False
    protection_redis_timeout_seconds: float = Field(default=0.2, ge=0.01, le=2, allow_inf_nan=False)
    protection_policies: tuple[EndpointPolicy, ...] | None = None

    @field_validator("protection_policies")
    @classmethod
    def validate_protection_policies(cls, value):
        return validate_policies(value) if value is not None else None

    @property
    def effective_policies(self) -> tuple[EndpointPolicy, ...]:
        return (
            self.protection_policies if self.protection_policies is not None else default_policies()
        )

    monitoring_enabled: bool = False
    client_identity_key: SecretStr | None = None
    monitoring_excluded_paths: tuple[str, ...] = ("/health", "/docs", "/openapi.json")
    event_buffer_capacity: int = Field(default=256, ge=1, le=10000)
    event_max_bytes: int = Field(default=4096, ge=1024, le=12288)
    event_operation_timeout_seconds: float = Field(default=2, ge=0.1, le=10)
    event_publish_attempts: int = Field(default=5, ge=1, le=10)
    event_retry_delay_seconds: float = Field(default=0.5, ge=0.01, le=5)
    event_shutdown_timeout_seconds: float = Field(default=5, ge=0.1, le=30)
    broker_queue_max_messages: int = Field(default=10000, ge=1, le=1000000)
    broker_queue_max_bytes: int = Field(default=16777216, ge=16384, le=268435456)
    worker_prefetch: int = Field(default=16, ge=1, le=128)
    worker_storage_attempts: int = Field(default=4, ge=1, le=10)
    worker_storage_timeout_seconds: float = Field(default=3, ge=0.1, le=30)

    @field_validator("client_identity_key")
    @classmethod
    def validate_identity_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            secret = value.get_secret_value()
            if len(secret) != 64 or any(char not in "0123456789abcdef" for char in secret):
                raise ValueError("client identity key must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("monitoring_excluded_paths")
    @classmethod
    def validate_exclusions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) > 32 or any(
            not path.startswith("/") or len(path) > 256 or "?" in path or "#" in path
            for path in values
        ):
            raise ValueError("monitoring exclusions must be bounded URL path prefixes")
        return values

    @model_validator(mode="after")
    def require_identity_key(self):
        if (
            self.monitoring_enabled or self.protection_enabled
        ) and self.client_identity_key is None:
            raise ValueError("monitoring/protection requires SENTINEL_CLIENT_IDENTITY_KEY")
        return self

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
