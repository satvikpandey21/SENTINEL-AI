"""Small immutable endpoint policy model; no database policy-management dependency."""

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RateLimitRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    requests: int = Field(default=600, ge=1, le=10000)
    window_seconds: float = Field(default=60, ge=0.1, le=3600, allow_inf_nan=False)
    exceed_action: Literal["record", "rate_limit", "block"] = "rate_limit"
    block_seconds: float = Field(default=60, ge=0.1, le=3600, allow_inf_nan=False)

    @model_validator(mode="after")
    def block_covers_window(self):
        if self.exceed_action == "block" and self.block_seconds < self.window_seconds:
            raise ValueError("rate block duration must cover the rate window")
        return self


class AuthenticationRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    failures: int = Field(default=5, ge=2, le=100)
    window_seconds: float = Field(default=60, ge=0.1, le=3600, allow_inf_nan=False)
    block_seconds: float = Field(default=60, ge=0.1, le=3600, allow_inf_nan=False)
    exceed_action: Literal["record", "block"] = "block"
    clear_on_success: bool = True


class EndpointPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=48, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    path_prefix: str = Field(min_length=1, max_length=128, pattern=r"^/[a-zA-Z0-9_/-]*$")
    methods: tuple[Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], ...] = ()
    enabled: bool = True
    failure_mode: Literal["open", "closed"] = "open"
    rate: RateLimitRule | None = Field(default_factory=RateLimitRule)
    authentication: AuthenticationRule | None = None

    @field_validator("path_prefix")
    @classmethod
    def canonical_prefix(cls, value: str) -> str:
        if "//" in value:
            raise ValueError("policy path prefix must be canonical")
        return value.rstrip("/") or "/"

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()[:16]

    def matches(self, path: str, method: str) -> bool:
        return (not self.methods or method in self.methods) and (
            self.path_prefix == "/"
            or path == self.path_prefix
            or path.startswith(self.path_prefix + "/")
        )


def default_policies() -> tuple[EndpointPolicy, ...]:
    return (
        EndpointPolicy(id="demo-read", path_prefix="/api/demo", rate=RateLimitRule()),
        EndpointPolicy(
            id="demo-limited",
            path_prefix="/api/demo/limited",
            rate=RateLimitRule(
                requests=5,
                window_seconds=3,
                exceed_action="block",
                block_seconds=3,
            ),
        ),
        EndpointPolicy(
            id="demo-login",
            path_prefix="/api/demo/login",
            failure_mode="closed",
            rate=RateLimitRule(requests=30, window_seconds=60),
            authentication=AuthenticationRule(),
        ),
    )


def validate_policies(policies: tuple[EndpointPolicy, ...]) -> tuple[EndpointPolicy, ...]:
    if len(policies) > 32 or len({policy.id for policy in policies}) != len(policies):
        raise ValueError("policies require unique IDs and at most 32 endpoint groups")
    for index, policy in enumerate(policies):
        for other in policies[index + 1 :]:
            if policy.path_prefix == other.path_prefix and (
                not policy.methods or not other.methods or set(policy.methods) & set(other.methods)
            ):
                raise ValueError("same-prefix policies must have disjoint methods")
    return policies
