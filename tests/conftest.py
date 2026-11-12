import pytest

from sentinel_security.config import Settings


@pytest.fixture
def settings(monkeypatch):
    for key in (
        "DATABASE_URL",
        "REDIS_URL",
        "RABBITMQ_URL",
        "ENVIRONMENT",
        "LOG_LEVEL",
        "DEPENDENCY_TIMEOUT_SECONDS",
        "DATABASE_POOL_SIZE",
        "DATABASE_MAX_OVERFLOW",
        "TRUSTED_PROXY_CIDRS",
    ):
        monkeypatch.delenv(f"SENTINEL_{key}", raising=False)
    return Settings(
        environment="test",
        database_url="postgresql+asyncpg://test:unit-secret@localhost/sentinel_test",
        redis_url="redis://:unit-secret@localhost/0",
        rabbitmq_url="amqp://test:unit-secret@localhost/",
    )
