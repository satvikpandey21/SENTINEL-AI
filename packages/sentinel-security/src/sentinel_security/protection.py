"""Redis-only protection engine. No broker, persistence or demo imports are permitted here."""

import asyncio
import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError
from starlette.types import Scope

from sentinel_security.events import record_authentication_outcome
from sentinel_security.policies import EndpointPolicy


@dataclass(frozen=True)
class Decision:
    action: Literal["allow", "record", "rate_limit", "temporary_block", "deny"] = "allow"
    rule_id: str = "none"
    policy: EndpointPolicy | None = None
    counter_value: int | None = None
    threshold: int | None = None
    window_seconds: float | None = None
    retry_after_seconds: int | None = None
    restriction_expires_at: datetime | None = None
    response_status: int | None = None
    degraded: bool = False


class RedisProtectionStore:
    def __init__(self, redis_provider: Callable[[], Redis], timeout: float) -> None:
        self.redis_provider = redis_provider
        self.timeout = timeout
        self._scripts = {}
        self._sources = {
            name: Path(__file__).with_name(name + ".lua").read_text(encoding="utf-8")
            for name in ("rate_limit", "auth_failures")
        }

    async def execute(self, name: str, keys: list[str], args: list) -> list:
        redis = self.redis_provider()
        if name not in self._scripts:
            self._scripts[name] = redis.register_script(self._sources[name])
        async with asyncio.timeout(self.timeout):
            return await self._scripts[name](keys=keys, args=args, client=redis)


class SecurityEngine:
    def __init__(
        self, store: RedisProtectionStore, service: str, policies: tuple[EndpointPolicy, ...]
    ):
        self.store = store
        self.service_hash = hashlib.sha256(service.encode()).hexdigest()[:16]
        self.policies = tuple(
            sorted(policies, key=lambda policy: len(policy.path_prefix), reverse=True)
        )

    def policy_for(self, scope: Scope) -> EndpointPolicy | None:
        return next(
            (
                policy
                for policy in self.policies
                if policy.matches(scope.get("path", ""), scope["method"])
            ),
            None,
        )

    def keys(self, policy: EndpointPolicy, identity: str) -> tuple[str, str, str]:
        # Cluster-compatible hash tag; group/fingerprint cardinality is configuration-bounded.
        tag = f"{{{self.service_hash}:{policy.fingerprint}:{identity}}}"
        prefix = f"sentinel:protection:{tag}"
        return prefix + ":rate", prefix + ":block", prefix + ":auth"

    def degraded(self, policy: EndpointPolicy, error: Exception) -> Decision:
        structlog.get_logger().warning(
            "protection_degraded",
            policy_id=policy.id,
            error_type=type(error).__name__,
            failure_mode=policy.failure_mode,
        )
        closed = policy.failure_mode == "closed"
        return Decision(
            action="deny" if closed else "record",
            rule_id="redis.unavailable",
            policy=policy,
            response_status=503 if closed else None,
            retry_after_seconds=1 if closed else None,
            degraded=True,
        )

    def _decision(self, result, policy: EndpointPolicy, *, after_login=False) -> Decision:
        code, counter, threshold, retry_ms, now_ms, source = result
        if int(code) == 1:
            return Decision(policy=policy)
        if isinstance(source, bytes):
            source = source.decode("ascii")
        action = {2: "record", 3: "rate_limit", 4: "temporary_block"}[int(code)]
        rule = "auth_failures" if source == "auth" else "rate"
        window = (
            policy.authentication.window_seconds if source == "auth" else policy.rate.window_seconds
        )
        restricted = action in ("rate_limit", "temporary_block") and not after_login
        timed_restriction = action in ("rate_limit", "temporary_block")
        retry = (
            max(1, math.ceil(int(retry_ms) / 1000))
            if timed_restriction and int(retry_ms) > 0
            else None
        )
        return Decision(
            action=action,
            rule_id=f"{policy.id}.{rule}",
            policy=policy,
            counter_value=int(counter),
            threshold=int(threshold),
            window_seconds=float(window),
            retry_after_seconds=retry,
            restriction_expires_at=(
                datetime.fromtimestamp((int(now_ms) + int(retry_ms)) / 1000, UTC)
                if retry is not None
                else None
            ),
            response_status=429 if restricted else None,
        )

    async def before_request(self, scope: Scope, identity: str) -> Decision:
        policy = self.policy_for(scope)
        if (
            policy is None
            or not policy.enabled
            or (policy.rate is None and policy.authentication is None)
        ):
            return Decision(policy=policy)
        rate_key, block_key, _ = self.keys(policy, identity)
        rule = policy.rate
        try:
            result = await self.store.execute(
                "rate_limit",
                [rate_key, block_key],
                [
                    rule.requests if rule else 0,
                    round(rule.window_seconds * 1000) if rule else 1,
                    scope["state"]["request_id"],
                    rule.exceed_action if rule else "record",
                    round(rule.block_seconds * 1000) if rule else 1,
                ],
            )
            return self._decision(result, policy)
        except (RedisError, OSError, TimeoutError) as error:
            return self.degraded(policy, error)

    async def after_authentication(self, scope: Scope, identity: str) -> Decision:
        policy = self.policy_for(scope)
        outcome = scope.get("state", {}).get("sentinel_verified_login")
        if (
            policy is None
            or not policy.enabled
            or policy.authentication is None
            or outcome not in ("succeeded", "failed")
        ):
            return Decision(policy=policy)
        _, block_key, auth_key = self.keys(policy, identity)
        rule = policy.authentication
        try:
            result = await self.store.execute(
                "auth_failures",
                [auth_key, block_key],
                [
                    outcome,
                    rule.failures,
                    round(rule.window_seconds * 1000),
                    scope["state"]["request_id"],
                    round(rule.block_seconds * 1000),
                    "1" if rule.clear_on_success else "0",
                    rule.exceed_action,
                ],
            )
            return self._decision(result, policy, after_login=True)
        except (RedisError, OSError, TimeoutError) as error:
            return self.degraded(policy, error)


def record_verified_login(scope: Scope, *, succeeded: bool) -> None:
    """Only an application that checked credentials may call this; a generic 401 is insufficient."""
    outcome = "succeeded" if succeeded else "failed"
    record_authentication_outcome(scope, outcome)
    scope["state"]["sentinel_verified_login"] = outcome
