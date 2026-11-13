"""Data-only Isolation Forest inference. No pickle, code import, training, or network I/O."""

import hashlib
import json
import math
import os
import stat
import struct
from time import monotonic
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.features import ML_FEATURES, Features

ARTIFACT_FORMAT = "sentinel-iforest-json-v1"
TRAINER_VERSION = "1.8.0"


def average_path(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2 * (math.log(n - 1) + 0.5772156649015329) - 2 * (n - 1) / n


class Tree(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    # Each node: feature, threshold, left child, right child, training sample count.
    nodes: list[tuple[int, float, int, int, int]] = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def bounded_tree(self):
        depths = {0: 0}
        for i, (feature, _, left, right, samples) in enumerate(self.nodes):
            if i not in depths or depths[i] > 7 or not 1 <= samples <= 128:
                raise ValueError("invalid tree topology or sample count")
            if left == right == -1:
                if feature != -2:
                    raise ValueError("invalid leaf")
            elif (
                0 <= feature < len(ML_FEATURES)
                and i < left < len(self.nodes)
                and i < right < len(self.nodes)
            ):
                if left == right or left in depths or right in depths:
                    raise ValueError("shared tree child")
                depths[left] = depths[right] = depths[i] + 1
            else:
                raise ValueError("invalid tree split")
        return self


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    format: Literal["sentinel-iforest-json-v1"]
    version: str = Field(max_length=64)
    feature_schema: Literal["behavior-v1"]
    features: tuple[str, ...]
    sklearn_version: Literal["1.8.0"]
    window_seconds: int = Field(ge=10, le=3600)
    transform: Literal["log1p-count-interval-v1"]
    max_samples: Literal[128]
    threshold: float = Field(ge=0.5, le=1)
    trees: list[Tree] = Field(min_length=32, max_length=32)

    @model_validator(mode="after")
    def schema_matches(self):
        if self.features != ML_FEATURES:
            raise ValueError("feature order mismatch")
        return self


def transform(vector: list[float]) -> list[float]:
    # Tree splits do not need standard scaling; log transforms reduce heavy-tailed counts/timing.
    return [
        struct.unpack("f", struct.pack("f", math.log1p(value) if i in (0, 5) else value))[0]
        for i, value in enumerate(vector)
    ]


class AnomalyModel:
    def __init__(self, policy: AnalysisPolicy):
        self.policy = policy
        self.artifact: Artifact | None = None
        self.status = "disabled"
        self.load_count = 0
        if not policy.ml_enabled:
            return
        self.status = "untrusted_artifact"
        if not policy.model_sha256:
            return
        try:
            # One bounded startup read; the digest comes from trusted deployment config.
            descriptor = os.open(
                policy.model_path,
                os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2_000_000:
                    self.status = "invalid_artifact"
                    return
                body = stream.read(2_000_001)
            if len(body) > 2_000_000 or hashlib.sha256(body).hexdigest() != policy.model_sha256:
                return
            artifact = Artifact.model_validate_json(body)
            if (
                artifact.version != policy.model_version
                or artifact.window_seconds != policy.window_seconds
            ):
                self.status = "version_mismatch"
                return
            self.artifact = artifact
            self.status = "ready"
            self.load_count = 1
        except FileNotFoundError:
            self.status = "missing_model"
        except (OSError, ValueError, RecursionError):
            self.status = "invalid_artifact"

    def infer(self, features: Features, *, complete_window: bool) -> dict:
        if self.artifact is None:
            return {"status": self.status}
        try:
            features = Features.model_validate(
                features.model_dump() if isinstance(features, Features) else features
            )
        except ValueError:
            return {"status": "invalid_features"}
        if (
            not complete_window
            or features.saturated
            or features.request_count < self.policy.min_requests
        ):
            return {"status": "insufficient_traffic"}
        started = monotonic()
        try:
            vector = transform(features.vector())
            depth_sum = 0.0
            for tree in self.artifact.trees:
                node = depth = 0
                for _ in range(8):
                    if (monotonic() - started) * 1000 > self.policy.inference_budget_ms:
                        return {"status": "timeout"}
                    feature, threshold, left, right, samples = tree.nodes[node]
                    if left == -1:
                        depth_sum += depth + average_path(samples)
                        break
                    node = left if vector[feature] <= threshold else right
                    depth += 1
            anomaly_score = 2 ** (-depth_sum / (len(self.artifact.trees) * average_path(128)))
            return {
                "status": "ready",
                "anomaly_score": anomaly_score,
                "anomalous": anomaly_score > self.artifact.threshold,
                "threshold": self.artifact.threshold,
                "model_version": self.artifact.version,
                "experimental": True,
            }
        except (ValueError, OverflowError, TypeError, IndexError):
            return {"status": "inference_error"}


def canonical_bytes(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
