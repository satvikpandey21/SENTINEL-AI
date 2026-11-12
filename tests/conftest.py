from datetime import UTC, datetime
from uuid import uuid4

import pytest

from sentinel_security.config import Settings
from sentinel_security.events import SecurityEvent


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
        "PROTECTION_ENABLED",
        "PROTECTION_POLICIES",
        "PROTECTION_REDIS_TIMEOUT_SECONDS",
        "DEMO_AUTH_ENABLED",
        "DEMO_USERNAME",
        "DEMO_PASSWORD_HASH",
    ):
        monkeypatch.delenv(f"SENTINEL_{key}", raising=False)
    return Settings(
        environment="test",
        database_url="postgresql+asyncpg://test:unit-secret@localhost/sentinel_test",
        redis_url="redis://:unit-secret@localhost/0",
        rabbitmq_url="amqp://test:unit-secret@localhost/",
    )


@pytest.fixture
def security_event():
    return SecurityEvent(
        schema_version=1,
        event_type="http.request.completed",
        event_id=uuid4(),
        request_id=uuid4().hex,
        occurred_at=datetime.now(UTC),
        service="unit-service",
        method="GET",
        endpoint="/api/items/{item_id}",
        status_code=200,
        duration_ms=1.25,
        client_identifier="a" * 64,
        severity="info",
        authentication_outcome="not_provided",
        response_completed=True,
    )
