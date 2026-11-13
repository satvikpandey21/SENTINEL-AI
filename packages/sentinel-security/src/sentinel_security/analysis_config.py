"""Versioned, bounded analysis policy; separate from synchronous enforcement policies."""

import re

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AnalysisPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    enabled: bool = True
    window_seconds: int = Field(default=60, ge=10, le=3600)
    max_requests: int = Field(default=2048, ge=100, le=10000)
    baseline_windows: int = Field(default=32, ge=8, le=128)
    baseline_min_windows: int = Field(default=8, ge=4, le=128)
    min_requests: int = Field(default=10, ge=3, le=100)
    z_threshold: float = Field(default=3.5, ge=2, le=20)
    request_threshold: int = Field(default=600, ge=10, le=10000)
    auth_threshold: int = Field(default=5, ge=2, le=100)
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "volume": 25,
            "authentication": 40,
            "policy": 40,
            "behavior": 20,
        }
    )
    severity_thresholds: tuple[int, int, int] = (20, 50, 80)
    sensitive_endpoints: tuple[str, ...] = ("/api/demo/login",)
    state_retention_days: int = Field(default=7, ge=1, le=90)
    assessment_retention_days: int = Field(default=30, ge=1, le=365)
    cleanup_batch: int = Field(default=500, ge=1, le=5000)
    ml_enabled: bool = False
    model_path: str = Field(default="/app/models/experimental-iforest-v1.json", max_length=512)
    model_version: str = Field(default="experimental-iforest-v1", pattern=r"^[a-z0-9.-]{1,64}$")
    model_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    inference_budget_ms: float = Field(default=10, ge=0.1, le=100)

    @model_validator(mode="after")
    def coherent(self):
        if self.baseline_min_windows > self.baseline_windows:
            raise ValueError("baseline minimum exceeds history capacity")
        if self.request_threshold > self.max_requests:
            raise ValueError("request threshold exceeds aggregation capacity")
        if set(self.weights) != {"volume", "authentication", "policy", "behavior"} or any(
            not 0 <= value <= 100 for value in self.weights.values()
        ):
            raise ValueError("weights require all four known groups with finite values in 0..100")
        if (
            not 0
            < self.severity_thresholds[0]
            < self.severity_thresholds[1]
            < self.severity_thresholds[2]
            <= 100
        ):
            raise ValueError("severity thresholds must be strictly increasing in 1..100")
        if len(self.sensitive_endpoints) > 32 or any(
            len(endpoint) > 256 or not re.fullmatch(r"/[a-zA-Z0-9_./{}:~-]*", endpoint)
            for endpoint in self.sensitive_endpoints
        ):
            raise ValueError("sensitive endpoints must be bounded registered templates")
        return self
