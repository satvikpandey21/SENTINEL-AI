"""Redis-only protection engine. No broker, persistence or demo imports are permitted here."""

import asyncio
import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Literal

import structlog
from redis.asyncio import Redis
from redis.exceptions import RedisError
from starlette.types import Scope

from sentinel_security.events import record_authentication_outcome
from sentinel_security.policies import EndpointPolicy
from sentinel_security.policy_runtime import PolicyUnavailable


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
    def __init__(self, redis_provider: Callable[[], Redis], timeout: float, metrics=None) -> None:
        self.redis_provider = redis_provider
        self.timeout = timeout
        self.metrics = metrics
        self._scripts = {}
        self._sources = {
            name: Path(__file__).with_name(name + ".lua").read_text(encoding="utf-8")
            for name in ("rate_limit", "auth_failures")
        }

    async def execute(self, name: str, keys: list[str], args: list) -> list:
        redis = self.redis_provider()
        if name not in self._scripts:
            self._scripts[name] = redis.register_script(self._sources[name])
        started, outcome = monotonic(), "error"
        try:
            async with asyncio.timeout(self.timeout):
                result = await self._scripts[name](keys=keys, args=args, client=redis)
            outcome = "success"
            return result
        finally:
            if self.metrics is not None:
                self.metrics.observe(
                    "enforcement_redis_duration_seconds",
                    monotonic() - started,
                    operation=name,
                    outcome=outcome,
                )
                if outcome == "error":
                    self.metrics.inc("enforcement_errors", operation=name)


class SecurityEngine:
    def __init__(
        self,
        store: RedisProtectionStore,
        service: str,
        policies: tuple[EndpointPolicy, ...],
        policy_loader=None,
        metrics=None,
    ):
        self.metrics = metrics
        self.policy_loader = policy_loader
        self.store = store
        self.service_hash = hashlib.sha256(service.encode()).hexdigest()[:16]
        self.policies = tuple(
            sorted(policies, key=lambda policy: len(policy.path_prefix), reverse=True)
        )

    def policy_for(self, scope: Scope, policies=None) -> EndpointPolicy | None:
        return next(
            (
                policy
                for policy in (
                    self.policies
                    if policies is None
                    else sorted(policies, key=lambda p: len(p.path_prefix), reverse=True)
                )
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

    async def _before_request(self, scope: Scope, identity: str) -> Decision:
        try:
            policies = await self.policy_loader() if self.policy_loader is not None else None
        except (PolicyUnavailable, RedisError, OSError, TimeoutError):
            if self.metrics is not None:
                self.metrics.inc("policy_operations", operation="read", outcome="error")
            return Decision(
                action="deny",
                rule_id="policy.unavailable",
                response_status=503,
                retry_after_seconds=1,
                degraded=True,
            )
        policy = self.policy_for(scope, policies)
        scope.setdefault("state", {})["sentinel_effective_policy"] = policy
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

    async def _after_authentication(self, scope: Scope, identity: str) -> Decision:
        policy = scope.get("state", {}).get("sentinel_effective_policy", self.policy_for(scope))
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

    def observe_decision(self, decision, stage):
        if self.metrics is not None:
            self.metrics.inc("security_actions", action=decision.action)
            rule = decision.rule_id
            source = (
                "rate"
                if rule.endswith(".rate")
                else "authentication"
                if rule.endswith(".auth_failures")
                else "policy"
                if rule.startswith("policy.")
                else "dependency"
                if decision.degraded
                else "other"
            )
            self.metrics.inc(
                "security_decisions",
                stage=stage,
                action=decision.action,
                source=source,
                degraded=str(decision.degraded).lower(),
            )
        return decision

    async def before_request(self, scope, identity):
        return self.observe_decision(await self._before_request(scope, identity), "admission")

    async def after_authentication(self, scope, identity):
        if self.metrics is not None and scope.get("state", {}).get("sentinel_verified_login"):
            self.metrics.inc(
                "security_authentication", outcome=scope["state"]["sentinel_verified_login"]
            )
        return self.observe_decision(
            await self._after_authentication(scope, identity), "authentication"
        )


def record_verified_login(scope: Scope, *, succeeded: bool) -> None:
    """Only an application that checked credentials may call this; a generic 401 is insufficient."""
    outcome = "succeeded" if succeeded else "failed"
    record_authentication_outcome(scope, outcome)
    scope["state"]["sentinel_verified_login"] = outcome
