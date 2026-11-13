"""Explainable grouped scoring and conservative robust statistical deviations."""

from statistics import median

from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.features import Features

RULE_VERSION = "risk-v1"
STAT_FLOORS = {
    "request_count": 5.0,
    "error_rate": 0.05,
    "auth_failure_rate": 0.05,
    "endpoint_entropy": 0.25,
    "timing_cv": 0.25,
}


def statistical(features: Features, history: list[dict], policy: AnalysisPolicy) -> dict:
    if features.saturated or features.request_count < policy.min_requests:
        return {"status": "insufficient_traffic", "flags": []}
    valid = []
    for row in history[-policy.baseline_windows :]:
        try:
            valid.append(Features.model_validate(row))
        except ValueError:
            continue
    if len(valid) < policy.baseline_min_windows:
        return {"status": "insufficient_baseline", "flags": []}
    flags = []
    for name, floor in STAT_FLOORS.items():
        values = [float(getattr(row, name)) for row in valid]
        center = median(values)
        scale = max(floor, 1.4826 * median([abs(value - center) for value in values]))
        observed = float(getattr(features, name))
        # Counts/rates are one-sided; behavioral diversity/timing may deviate either way.
        delta = observed - center
        z = (abs(delta) if name in ("endpoint_entropy", "timing_cv") else delta) / scale
        if z >= policy.z_threshold:
            flags.append(
                {
                    "rule_id": "stat." + name,
                    "feature": name,
                    "observed": observed,
                    "median": center,
                    "scale": scale,
                    "robust_z": round(z, 4),
                }
            )
    return {"status": "ready", "baseline_windows": len(valid), "flags": flags}


def score(features: Features, statistics: dict, ml: dict, policy: AnalysisPolicy) -> dict:
    f = features
    volume = (
        min(1.0, f.request_count / policy.request_threshold)
        if f.request_count > policy.request_threshold / 2
        else 0
    )
    authentication = min(1.0, f.auth_failures / policy.auth_threshold)
    # Sensitivity changes the authentication group only, never scores a normal sensitive visit.
    authentication = min(1.0, authentication * (1 + 0.25 * f.sensitive_fraction))
    policy_signal = max(
        min(1.0, f.rate_violations / 3), min(1.0, max(0, f.restriction_episodes - 1) / 2)
    )
    flags = statistics["flags"]
    # Overlapping count/auth flags already belong to their deterministic groups.
    residual_errors = max(0.0, f.error_rate - f.auth_failure_rate - f.rate_violation_rate)
    behavior = (
        1.0
        if any(
            flag["feature"] in ("endpoint_entropy", "timing_cv")
            or (flag["feature"] == "error_rate" and residual_errors > 0.5)
            for flag in flags
        )
        else 0.0
    )
    if f.request_count >= policy.min_requests and residual_errors > 0.5:
        behavior = max(behavior, residual_errors)
    # Uncalibrated ML is supporting evidence only; never adds risk or triggers enforcement.
    strengths = {
        "volume": volume,
        "authentication": authentication,
        "policy": policy_signal,
        "behavior": behavior,
    }
    # Rate violations and volume share a cause: take their maximum rather than summing.
    contributions = {key: round(policy.weights[key] * value, 2) for key, value in strengths.items()}
    if contributions["volume"] <= contributions["policy"]:
        contributions["volume"] = 0.0
    else:
        contributions["policy"] = 0.0
    total = round(min(100, sum(contributions.values())), 2)
    severity = ("low", "moderate", "high", "critical")[
        sum(total >= t for t in policy.severity_thresholds)
    ]
    threats = []

    def add(category, method, rules, evidence):
        threats.append(
            {
                "category": category,
                "severity": severity,
                "risk_score": total,
                "detection_method": method,
                "rule_ids": rules,
                "evidence": evidence,
            }
        )

    if f.auth_failures:
        add(
            "possible_brute_force"
            if f.auth_failures >= policy.auth_threshold
            else "repeated_authentication_failures",
            "deterministic",
            ["risk.authentication"],
            {"failures": f.auth_failures},
        )
    if volume or f.rate_violations:
        add(
            "excessive_api_requests",
            "deterministic",
            ["risk.volume", "risk.policy"],
            {"requests": f.request_count, "rate_violations": f.rate_violations},
        )
    if f.restriction_episodes >= 2:
        add(
            "repeated_policy_violations",
            "deterministic",
            ["risk.policy"],
            {"restriction_episodes": f.restriction_episodes},
        )
    if flags:
        add(
            "suspicious_behavioral_deviation",
            "robust_statistics",
            [flag["rule_id"] for flag in flags],
            {"flags": flags},
        )
    if ml.get("anomalous"):
        add("experimental_behavioral_anomaly", "isolation_forest", ["ml.isolation_forest"], ml)
    return {
        "risk_score": total,
        "severity": severity,
        "contributions": contributions,
        "threats": threats,
        "rule_version": RULE_VERSION,
    }
