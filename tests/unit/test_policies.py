import pytest
from pydantic import ValidationError

from sentinel_security.config import Settings
from sentinel_security.policies import (
    AuthenticationRule,
    EndpointPolicy,
    RateLimitRule,
    default_policies,
    validate_policies,
)


@pytest.mark.parametrize(
    "model,values",
    [
        (RateLimitRule, {"requests": 0}),
        (RateLimitRule, {"requests": 10001}),
        (RateLimitRule, {"window_seconds": 0}),
        (RateLimitRule, {"window_seconds": float("nan")}),
        (RateLimitRule, {"exceed_action": "surprise"}),
        (RateLimitRule, {"exceed_action": "block", "window_seconds": 30, "block_seconds": 2}),
        (AuthenticationRule, {"failures": 1}),
        (AuthenticationRule, {"block_seconds": 0}),
        (EndpointPolicy, {"id": "bad id", "path_prefix": "/api"}),
        (EndpointPolicy, {"id": "p", "path_prefix": "/api?secret"}),
        (EndpointPolicy, {"id": "p", "path_prefix": "//api"}),
        (EndpointPolicy, {"id": "p", "path_prefix": "/api", "unknown": True}),
    ],
)
def test_invalid_policies_rejected(model, values):
    with pytest.raises(ValidationError):
        model(**values)


def test_defaults_are_explicit_immutable_and_grouped():
    policies = validate_policies(default_policies())
    assert len(policies) == 3
    assert policies[0].failure_mode == "open"
    assert policies[2].failure_mode == "closed"
    with pytest.raises(ValidationError):
        policies[0].enabled = False


def test_duplicate_ids_and_ambiguous_methods_rejected():
    a = EndpointPolicy(id="a", path_prefix="/api")
    with pytest.raises(ValueError):
        validate_policies((a, a))
    with pytest.raises(ValueError):
        validate_policies((a, EndpointPolicy(id="b", path_prefix="/api", methods=("GET",))))
    valid = (
        a.model_copy(update={"methods": ("POST",)}),
        EndpointPolicy(id="b", path_prefix="/api", methods=("GET",)),
    )
    assert validate_policies(valid) == valid
    with pytest.raises(ValueError):
        validate_policies(
            tuple(EndpointPolicy(id=f"p{i}", path_prefix=f"/p{i}") for i in range(33))
        )


def test_prefix_matching_is_segment_and_method_sensitive():
    policy = EndpointPolicy(id="p", path_prefix="/api/", methods=("POST",))
    assert policy.path_prefix == "/api"
    assert policy.matches("/api/login", "POST")
    assert not policy.matches("/apiary", "POST")
    assert not policy.matches("/api", "GET")
    assert EndpointPolicy(id="root", path_prefix="/").matches("/anything", "GET")


def test_policy_fingerprints_change_when_behavior_changes():
    a = EndpointPolicy(id="p", path_prefix="/api")
    assert a.fingerprint == EndpointPolicy.model_validate_json(a.model_dump_json()).fingerprint
    assert a.fingerprint != a.model_copy(update={"enabled": False}).fingerprint


def test_settings_validate_protection_without_monitoring(settings):
    values = settings.model_dump()
    values.update(protection_enabled=True, monitoring_enabled=False)
    with pytest.raises(ValidationError):
        Settings(**values)
    configured = Settings(**{**values, "client_identity_key": "a" * 64, "protection_policies": []})
    assert configured.effective_policies == ()
    assert settings.effective_policies == default_policies()
