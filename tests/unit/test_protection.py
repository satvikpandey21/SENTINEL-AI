from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from sentinel_security.policies import AuthenticationRule, EndpointPolicy, RateLimitRule
from sentinel_security.protection import RedisProtectionStore, SecurityEngine, record_verified_login


def scope(path="/api", method="GET"):
    return {"path": path, "method": method, "state": {"request_id": "a" * 32}}


def engine(result=None, **policy_changes):
    policy = EndpointPolicy(
        id="p",
        path_prefix="/api",
        rate=RateLimitRule(requests=2, window_seconds=1),
        authentication=AuthenticationRule(failures=3),
        **policy_changes,
    )
    store = MagicMock(execute=AsyncMock(return_value=result or [1, 1, 2, 0, 1000000, "rate"]))
    return SecurityEngine(store, "test-service", (policy,)), store, policy


async def test_normal_acceptance_and_policy_resolution():
    security, store, policy = engine()
    assert (await security.before_request(scope(), "b" * 64)).action == "allow"
    store.execute.assert_awaited_once()
    store.execute.reset_mock()
    assert (await security.before_request(scope("/else"), "b" * 64)).action == "allow"
    store.execute.assert_not_awaited()
    specific = EndpointPolicy(id="specific", path_prefix="/api/specific")
    security.policies = (specific, policy)
    assert security.policy_for(scope("/api/specific/a")).id == "specific"


async def test_disabled_or_empty_policy_does_not_touch_redis():
    security, store, policy = engine(enabled=False)
    await security.before_request(scope(), "b" * 64)
    store.execute.assert_not_awaited()
    security.policies = (
        policy.model_copy(update={"enabled": True, "rate": None, "authentication": None}),
    )
    await security.before_request(scope(), "b" * 64)
    store.execute.assert_not_awaited()


@pytest.mark.parametrize(
    "code,action,status", [(2, "record", None), (3, "rate_limit", 429), (4, "temporary_block", 429)]
)
async def test_rate_decision_and_retry_after_ceiling(code, action, status):
    security, _, _ = engine([code, 3, 2, 1001, 1000000, b"rate"])
    decision = await security.before_request(scope(), "b" * 64)
    assert (decision.action, decision.response_status) == (action, status)
    assert decision.retry_after_seconds == (None if action == "record" else 2)
    assert decision.counter_value == 3 and decision.threshold == 2
    assert decision.restriction_expires_at == (
        None if action == "record" else datetime.fromtimestamp(1001.001, UTC)
    )


@pytest.mark.parametrize("mode,status,action", [("open", None, "record"), ("closed", 503, "deny")])
async def test_redis_failures_are_explicit_and_policy_specific(mode, status, action):
    security, store, _ = engine(failure_mode=mode)
    store.execute.side_effect = RedisConnectionError("redis://private-password")
    decision = await security.before_request(scope(), "b" * 64)
    assert (decision.response_status, decision.action, decision.degraded) == (status, action, True)
    assert decision.rule_id == "redis.unavailable"


async def test_only_verified_login_results_increment_failure_state():
    security, store, _ = engine([4, 3, 3, 5000, 1000000, "auth"])
    request = scope()
    request["state"]["sentinel_authentication_outcome"] = "failed"
    assert (await security.after_authentication(request, "b" * 64)).action == "allow"
    store.execute.assert_not_awaited()
    record_verified_login(request, succeeded=False)
    decision = await security.after_authentication(request, "b" * 64)
    assert decision.action == "temporary_block"
    assert (
        decision.response_status is None
    )  # Current invalid login remains 401; future attempts are blocked.
    assert store.execute.call_args.args[0] == "auth_failures"
    assert store.execute.call_args.args[2][0] == "failed"
    record_verified_login(request, succeeded=True)
    await security.after_authentication(request, "b" * 64)
    assert store.execute.call_args.args[2][0] == "succeeded"


async def test_auth_state_failure_uses_fail_closed_policy():
    security, store, _ = engine(failure_mode="closed")
    store.execute.side_effect = TimeoutError()
    request = scope()
    record_verified_login(request, succeeded=True)
    assert (await security.after_authentication(request, "b" * 64)).response_status == 503


def test_key_names_have_no_raw_identity_and_share_cluster_slot():
    security, _, policy = engine()
    keys = security.keys(policy, "b" * 64)
    assert len({key.split("{")[1].split("}")[0] for key in keys}) == 1
    assert all("/api" not in key for key in keys)
    assert keys != security.keys(policy, "c" * 64)


async def test_script_cache_uses_async_registered_script():
    script = AsyncMock(return_value=[1, 1, 2, 0, 1000, "rate"])
    redis = MagicMock(register_script=MagicMock(return_value=script))
    store = RedisProtectionStore(lambda: redis, 0.1)
    assert await store.execute("rate_limit", ["a", "b"], [1])
    await store.execute("rate_limit", ["a", "b"], [1])
    redis.register_script.assert_called_once()
    script.assert_awaited_with(keys=["a", "b"], args=[1], client=redis)
