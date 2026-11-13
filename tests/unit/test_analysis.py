"""Risk, feature, statistics, and offline ML contracts; no service mocks in production."""

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.anomaly_model import AnomalyModel, Artifact, Tree, canonical_bytes
from sentinel_security.events import DetectionEvent
from sentinel_security.features import Features, extract, observe
from sentinel_security.model_training import controlled_windows, train_and_evaluate
from sentinel_security.risk import score, statistical


@pytest.fixture
def policy():
    return AnalysisPolicy()


@pytest.fixture
def normal(policy):
    return extract({}, policy).model_copy(
        update={
            "request_count": 20,
            "endpoint_distribution": {"/api/items": 20},
            "mean_interval": 2.0,
        }
    )


def evaluate(features, policy, flags=None, ml=None):
    return score(features, {"flags": flags or []}, ml or {"status": "disabled"}, policy)


@pytest.mark.parametrize(
    "field,value",
    [
        ("baseline_min_windows", 33),
        ("window_seconds", 0),
        ("weights", {"volume": 1}),
        ("weights", {"volume": float("nan"), "policy": 1, "authentication": 1, "behavior": 1}),
        ("severity_thresholds", (20, 20, 80)),
        ("request_threshold", 2049),
        ("max_requests", 10),
        ("inference_budget_ms", 0),
        ("assessment_retention_days", 0),
        ("sensitive_endpoints", ("/login?secret=x",)),
        ("model_sha256", "invalid"),
    ],
)
def test_invalid_analysis_configuration(field, value):
    with pytest.raises(ValidationError):
        AnalysisPolicy(**{field: value})


def test_normal_zero_risk_and_ml_never_adds_score(normal, policy):
    ordinary = evaluate(normal, policy)
    experimental = evaluate(normal, policy, ml={"anomalous": True, "model_version": "test"})
    assert ordinary["risk_score"] == experimental["risk_score"] == 0
    assert experimental["severity"] == "low"
    assert experimental["threats"][0]["category"] == "experimental_behavioral_anomaly"


@pytest.mark.parametrize("failures,expected", [(0, 0), (1, 8), (2, 16), (5, 40), (100, 40)])
def test_authentication_score_is_deterministic(normal, policy, failures, expected):
    features = normal.model_copy(update={"auth_failures": failures})
    assert evaluate(features, policy)["risk_score"] == expected
    assert evaluate(features, policy) == evaluate(features, policy)


def test_sensitivity_only_modulates_existing_evidence(normal, policy):
    assert evaluate(normal.model_copy(update={"sensitive_fraction": 1}), policy)["risk_score"] == 0
    f = normal.model_copy(update={"sensitive_fraction": 1, "auth_failures": 2})
    assert evaluate(f, policy)["risk_score"] == 20


def test_overlapping_volume_policy_and_statistics_not_double_counted(normal, policy):
    f = normal.model_copy(update={"request_count": 600, "rate_violations": 3})
    result = evaluate(
        f, policy, flags=[{"feature": "request_count", "rule_id": "stat.request_count"}]
    )
    assert result["risk_score"] == 40
    assert result["contributions"]["volume"] == 0
    assert result["contributions"]["behavior"] == 0


@pytest.mark.parametrize(
    "total,severity",
    [
        (0, "low"),
        (19, "low"),
        (20, "moderate"),
        (49, "moderate"),
        (50, "high"),
        (79, "high"),
        (80, "critical"),
        (100, "critical"),
    ],
)
def test_severity_boundaries(normal, policy, total, severity):
    configured = policy.model_copy(
        update={"weights": {"volume": 0, "policy": 0, "authentication": total, "behavior": 0}}
    )
    assert (
        evaluate(normal.model_copy(update={"auth_failures": 5}), configured)["severity"] == severity
    )


def test_score_clamps_and_explains_classifications(normal, policy):
    f = normal.model_copy(
        update={"auth_failures": 5, "rate_violations": 3, "restriction_episodes": 3}
    )
    configured = policy.model_copy(update={"weights": dict.fromkeys(policy.weights, 100)})
    result = evaluate(f, configured, flags=[{"feature": "timing_cv", "rule_id": "stat.timing_cv"}])
    assert result["risk_score"] == 100
    assert {t["category"] for t in result["threats"]} >= {
        "possible_brute_force",
        "repeated_policy_violations",
        "suspicious_behavioral_deviation",
    }
    assert all(t["evidence"] and t["rule_ids"] for t in result["threats"])


def test_v1_v2_merge_in_either_order_and_restriction_dedup(security_event, policy):
    event = security_event.model_copy(update={"authentication_outcome": "failed"})
    data = event.model_dump()
    data.update(
        schema_version=2,
        event_type="security.decision",
        event_id=uuid4(),
        rule_id="demo.rate",
        security_action="temporary_block",
        restriction_expires_at=event.occurred_at + timedelta(seconds=60),
    )
    decision = DetectionEvent(**data)
    for sequence in ((event, decision), (decision, event)):
        state = {}
        for item in sequence:
            state, f, _ = observe(state, item, policy)
        assert (
            f.request_count == f.auth_failures == f.rate_violations == f.restriction_episodes == 1
        )
        state, f, _ = observe(
            state, decision.model_copy(update={"request_id": uuid4().hex}), policy
        )
        assert f.restriction_episodes == 1
        assert f.request_count == 2


def test_infrastructure_degradation_is_not_attack_evidence(security_event, policy):
    data = security_event.model_dump()
    data.update(
        schema_version=2,
        event_type="security.decision",
        rule_id="redis.unavailable",
        security_action="deny",
        degraded=True,
    )
    _, f, _ = observe({}, DetectionEvent(**data), policy)
    assert f.rate_violations == f.restriction_episodes == 0


def test_window_rotation_history_and_late_events(security_event, policy):
    state = {}
    base = security_event.occurred_at.replace(second=0, microsecond=0)
    for window in range(40):
        for request in range(10):
            event = security_event.model_copy(
                update={
                    "request_id": uuid4().hex,
                    "occurred_at": base + timedelta(minutes=window, seconds=request),
                }
            )
            state, f, _ = observe(state, event, policy)
    assert len(state["baseline"]) == policy.baseline_windows
    assert f.request_count == 10
    old = json.dumps(state, sort_keys=True)
    _, _, status = observe(state, security_event.model_copy(update={"occurred_at": base}), policy)
    assert status == "late_event"
    assert json.dumps(state, sort_keys=True) == old
    state, _, _ = observe(
        state, security_event.model_copy(update={"occurred_at": base + timedelta(days=8)}), policy
    )
    assert not state["baseline"]


def test_capacity_is_bounded_and_explicit(security_event):
    policy = AnalysisPolicy(max_requests=100, request_threshold=100)
    state = {}
    for _ in range(105):
        state, f, status = observe(
            state, security_event.model_copy(update={"request_id": uuid4().hex}), policy
        )
    assert f.saturated and status == "capacity_reached"
    assert len(state["entries"]) == f.request_count == 100
    assert statistical(f, [], policy)["status"] == "insufficient_traffic"


def test_distribution_timing_and_sensitive_data_exclusion(security_event, policy):
    state = {}
    for i in range(3):
        event = security_event.model_copy(
            update={
                "request_id": uuid4().hex,
                "occurred_at": security_event.occurred_at.replace(second=0, microsecond=0)
                + timedelta(seconds=i * 2),
                "endpoint": "/api/demo/login" if i else "/api/items",
            }
        )
        state, f, _ = observe(state, event, policy)
    assert f.mean_interval == 2
    assert f.timing_cv == 0
    assert f.sensitive_fraction == 2 / 3
    assert f.endpoint_entropy > 0
    assert not any(
        word in json.dumps(state).lower()
        for word in ("password", "authorization", "cookie", "token", "client_ip")
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"request_count": -1},
        {"error_rate": float("nan")},
        {"mean_interval": float("inf")},
        {"error_rate": 2},
        {"unknown": 1},
    ],
)
def test_invalid_features_rejected(normal, changes):
    with pytest.raises(ValidationError):
        Features.model_validate({**normal.model_dump(), **changes})


def test_missing_features_rejected():
    with pytest.raises(ValidationError):
        Features.model_validate({})


def test_statistics_warmup_low_volume_and_malformed_baselines(normal, policy):
    assert statistical(normal, [], policy)["status"] == "insufficient_baseline"
    assert statistical(normal, [{"bad": 1}] * 10, policy)["status"] == "insufficient_baseline"
    assert (
        statistical(normal.model_copy(update={"request_count": 1}), [], policy)["status"]
        == "insufficient_traffic"
    )


def test_robust_statistics_constant_baseline_and_controlled_anomaly(normal, policy):
    history = [normal.model_dump()] * 8
    assert not statistical(normal, history, policy)["flags"]
    anomalous = normal.model_copy(update={"request_count": 200, "error_rate": 0.9})
    result = statistical(anomalous, history, policy)
    assert {flag["feature"] for flag in result["flags"]} == {"request_count", "error_rate"}
    assert all(flag["scale"] > 0 for flag in result["flags"])
    insensitive = policy.model_copy(update={"z_threshold": 100})
    assert not statistical(anomalous, history, insensitive)["flags"]


@pytest.fixture(scope="module")
def trained():
    return train_and_evaluate()


def trusted_model(tmp_path, artifact, **overrides):
    path = tmp_path / "model.json"
    body = canonical_bytes(artifact)
    path.write_bytes(body)
    return AnomalyModel(
        AnalysisPolicy(
            ml_enabled=True,
            model_path=str(path),
            model_sha256=hashlib.sha256(body).hexdigest(),
            **overrides,
        )
    )


def test_real_training_reproducibility_and_export_parity(trained):
    artifact, report = trained
    second, second_report = train_and_evaluate()
    assert canonical_bytes(artifact) == canonical_bytes(second)
    assert report == second_report
    assert report["max_sklearn_export_error"] < 1e-12
    assert report["evaluation"]["true_positive"] > 0
    assert report["evaluation"]["normal_windows"] == 256


def test_real_ml_inference_loaded_once_and_low_volume(tmp_path, trained):
    model = trusted_model(tmp_path, trained[0])
    normal = controlled_windows(4103, 1)[0]
    burst = controlled_windows(4200, 1, "burst")[0]
    assert model.status == "ready" and model.load_count == 1
    prediction = model.infer(burst, complete_window=True)
    assert prediction["anomalous"] == (prediction["anomaly_score"] > prediction["threshold"])
    assert (
        model.infer(normal, complete_window=True)["anomaly_score"]
        < model.infer(burst, complete_window=True)["anomaly_score"]
    )
    assert model.infer(normal, complete_window=False)["status"] == "insufficient_traffic"
    assert (
        model.infer(normal.model_copy(update={"saturated": True}), complete_window=True)["status"]
        == "insufficient_traffic"
    )
    assert model.load_count == 1


def test_ml_disabled_untrusted_missing_and_corrupt(tmp_path, policy, trained):
    normal = controlled_windows(1, 1)[0]
    assert AnomalyModel(policy).infer(normal, complete_window=True) == {"status": "disabled"}
    assert AnomalyModel(AnalysisPolicy(ml_enabled=True)).status == "untrusted_artifact"
    assert (
        AnomalyModel(
            AnalysisPolicy(
                ml_enabled=True, model_sha256="0" * 64, model_path=str(tmp_path / "absent")
            )
        ).status
        == "missing_model"
    )
    assert trusted_model(tmp_path, {"pickle": "not accepted"}).status == "invalid_artifact"
    model = trusted_model(tmp_path, trained[0], model_version="other")
    assert model.status == "version_mismatch"
    model = trusted_model(tmp_path, trained[0], window_seconds=120)
    assert model.status == "version_mismatch"
    path = tmp_path / "model.json"
    model = AnomalyModel(
        AnalysisPolicy(ml_enabled=True, model_path=str(path), model_sha256="0" * 64)
    )
    assert model.status == "untrusted_artifact"


@pytest.mark.parametrize(
    "change",
    [
        {"sklearn_version": "0.0"},
        {"feature_schema": "v0"},
        {"features": ["wrong"]},
        {"threshold": float("nan")},
    ],
)
def test_model_compatibility_checks(trained, change):
    with pytest.raises(ValidationError):
        Artifact.model_validate({**trained[0], **change})


@pytest.mark.parametrize(
    "nodes",
    [[(0, 1.0, 0, 0, 10)], [(-2, -2.0, -1, -1, 0)], [(0, 1.0, 1, 1, 10), (-2, -2.0, -1, -1, 5)]],
)
def test_malformed_tree_rejected(nodes):
    with pytest.raises(ValidationError):
        Tree(nodes=nodes)


def test_inference_timeout_is_safe(tmp_path, trained, monkeypatch):
    model = trusted_model(tmp_path, trained[0])
    values = iter((0.0, 10.0))
    monkeypatch.setattr("sentinel_security.anomaly_model.monotonic", lambda: next(values))
    assert model.infer(controlled_windows(1, 1)[0], complete_window=True) == {"status": "timeout"}


def test_authentication_and_policy_error_rates_do_not_add_behavior_score(normal, policy):
    f = normal.model_copy(update={"auth_failures": 20, "auth_failure_rate": 1.0, "error_rate": 1.0})
    result = evaluate(f, policy, flags=[{"feature": "error_rate", "rule_id": "stat.error_rate"}])
    assert result["contributions"]["behavior"] == 0


def test_ml_invalid_features_and_oversized_artifact(tmp_path, trained):
    model = trusted_model(tmp_path, trained[0])
    assert model.infer({}, complete_window=True)["status"] == "invalid_features"
    path = tmp_path / "large.json"
    path.write_bytes(b"x" * 2_000_001)
    assert (
        AnomalyModel(
            AnalysisPolicy(ml_enabled=True, model_path=str(path), model_sha256="0" * 64)
        ).status
        == "invalid_artifact"
    )
