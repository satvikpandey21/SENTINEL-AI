import pytest
from pydantic import ValidationError

from sentinel_security.config import Settings


def test_settings_require_dependency_urls(monkeypatch):
    for key in ("DATABASE_URL", "REDIS_URL", "RABBITMQ_URL"):
        monkeypatch.delenv(f"SENTINEL_{key}", raising=False)
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_url", "sqlite:///wrong"),
        ("redis_url", "http://localhost"),
        ("rabbitmq_url", "amqp://"),
        ("redis_url", "redis://localhost:bad"),
        ("dependency_timeout_seconds", 0),
        ("database_pool_size", 0),
        ("database_max_overflow", -1),
        ("trusted_proxy_cidrs", ["10.1.1.2/24"]),
        ("environment", "anything"),
    ],
)
def test_invalid_settings_rejected(settings, field, value):
    values = settings.model_dump()
    values[field] = value
    with pytest.raises(ValidationError):
        Settings(**values)


def test_secrets_redacted_and_settings_frozen(settings):
    assert "unit-secret" not in repr(settings)
    assert "unit-secret" not in settings.model_dump_json()
    with pytest.raises(ValidationError):
        settings.environment = "production"


def test_environment_is_loaded(monkeypatch, settings):
    monkeypatch.setenv("SENTINEL_DATABASE_URL", settings.database_url.get_secret_value())
    monkeypatch.setenv("SENTINEL_REDIS_URL", settings.redis_url.get_secret_value())
    monkeypatch.setenv("SENTINEL_RABBITMQ_URL", settings.rabbitmq_url.get_secret_value())
    monkeypatch.setenv("SENTINEL_TRUSTED_PROXY_CIDRS", '["10.0.0.0/8", "::1/128"]')
    assert Settings().trusted_proxy_cidrs == ("10.0.0.0/8", "::1/128")
