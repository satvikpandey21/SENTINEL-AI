"""Versioned, allowlisted wire schema. No free-form request data belongs here."""

import hashlib
import hmac
import re
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol, TypeAlias
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter, field_validator
from starlette.types import Scope

SCHEMA_VERSION = 1
MAX_DURATION_MS = 86_400_000
AuthenticationOutcome = Literal["not_provided", "succeeded", "failed"]
Severity = Literal["info", "warning", "error"]


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)

    schema_version: Literal[1]
    event_type: Literal["http.request.completed"]
    event_id: UUID
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    occurred_at: AwareDatetime
    service: str = Field(min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    method: Literal[
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT", "OTHER"
    ]
    endpoint: str = Field(min_length=1, max_length=256)
    status_code: int = Field(ge=100, le=599)
    duration_ms: float = Field(ge=0, le=MAX_DURATION_MS)
    client_identifier: str = Field(pattern=r"^[0-9a-f]{64}$")
    severity: Severity
    authentication_outcome: AuthenticationOutcome
    response_completed: bool

    @field_validator("occurred_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        if value != "unmatched" and not re.fullmatch(r"/[a-zA-Z0-9_./{}:~-]*", value):
            raise ValueError("endpoint must be a safe registered route template")
        return value

    @classmethod
    def from_wire(cls, body: bytes, max_bytes: int) -> "SecurityEvent":
        if len(body) > max_bytes:
            raise ValueError("event exceeds size limit")
        return cls.model_validate_json(body)


class DetectionEvent(SecurityEvent):
    schema_version: Literal[2]
    event_type: Literal["security.decision"]
    rule_id: str = Field(min_length=1, max_length=96, pattern=r"^[a-zA-Z0-9_.-]+$")
    security_action: Literal["record", "rate_limit", "temporary_block", "deny"]
    counter_value: int | None = Field(default=None, ge=0, le=10001)
    threshold: int | None = Field(default=None, ge=1, le=10000)
    window_seconds: float | None = Field(default=None, ge=0.1, le=3600)
    retry_after_seconds: int | None = Field(default=None, ge=1, le=3600)
    restriction_expires_at: AwareDatetime | None = None
    degraded: bool = False


MonitoringEvent: TypeAlias = Annotated[
    SecurityEvent | DetectionEvent, Field(discriminator="schema_version")
]
_EVENT_ADAPTER = TypeAdapter(MonitoringEvent)


def parse_event(body: bytes, max_bytes: int) -> SecurityEvent | DetectionEvent:
    if len(body) > max_bytes:
        raise ValueError("event exceeds size limit")
    return _EVENT_ADAPTER.validate_json(body)


def client_identifier(address: str, identity_key: bytes) -> str:
    return hmac.new(identity_key, address.encode("ascii"), hashlib.sha256).hexdigest()


class EventSink(Protocol):
    def offer(self, event: MonitoringEvent) -> bool: ...


def record_authentication_outcome(scope: Scope, outcome: AuthenticationOutcome) -> None:
    """Call from trusted application code after authentication; never infer from headers."""
    if outcome not in ("succeeded", "failed", "not_provided"):
        raise ValueError("unsupported authentication outcome")
    scope.setdefault("state", {})["sentinel_authentication_outcome"] = outcome


def route_template(scope: Scope) -> str:
    # ASGI routers without a registered template intentionally collapse to 'unmatched'.
    value = getattr(
        scope.get("route"), "path", scope.get("state", {}).get("sentinel_endpoint", "unmatched")
    )
    if isinstance(value, str) and len(value) <= 256:
        if value == "unmatched" or re.fullmatch(r"/[a-zA-Z0-9_./{}:~-]*", value):
            return value
    return "unmatched"


def build_event(
    *,
    scope: Scope,
    request_id: str,
    occurred_at: datetime,
    service: str,
    duration_ms: float,
    status_code: int,
    client_ip: str,
    identity_key: bytes,
    response_completed: bool,
    application_failed: bool,
) -> SecurityEvent:
    outcome = scope.get("state", {}).get("sentinel_authentication_outcome", "not_provided")
    if outcome not in ("succeeded", "failed", "not_provided"):
        outcome = "not_provided"
    severity = "info"
    if application_failed or status_code >= 500:
        severity = "error"
    elif status_code >= 400 or outcome == "failed" or not response_completed:
        severity = "warning"
    method = scope["method"]
    if method not in (
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
    ):
        method = "OTHER"
    return SecurityEvent(
        schema_version=SCHEMA_VERSION,
        event_type="http.request.completed",
        event_id=uuid4(),
        request_id=request_id,
        occurred_at=occurred_at,
        service=service,
        method=method,
        endpoint=route_template(scope),
        status_code=status_code,
        duration_ms=min(MAX_DURATION_MS, max(0.0, duration_ms)),
        client_identifier=client_identifier(client_ip, identity_key),
        severity=severity,
        authentication_outcome=outcome,
        response_completed=response_completed,
    )


class DeadLetterNotice(BaseModel):
    """Malformed input is never copied to the dead queue, even when it contains secrets."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    event_type: Literal["security.event.rejected"] = "security.event.rejected"
    rejected_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    reason: Literal[
        "invalid_event", "oversized_event", "retry_exhausted", "permanent_storage_error"
    ]
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    event: MonitoringEvent | None = None
