"""Versioned policy control plane and non-sensitive administrative audit trail.

Redis is the enforcement authority. A write fence closes enforcement before PostgreSQL
commits; compare-and-set activation cannot overwrite a later writer. No process caches
an effective policy. Reconciliation repairs a pending write after a crash.
"""

import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_security.database import Base
from sentinel_security.policies import EndpointPolicy, validate_policies
from sentinel_security.policy_runtime import POLICY_KEY, PolicyUnavailable, snapshot

POLICY_LOCK = 517291405
ACTIVATE = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2]); return 1
end
return 0
"""


class AdminAudit(Base):
    __tablename__ = "admin_audit"
    __table_args__ = (
        Index("ix_admin_audit_time", "occurred_at", "id"),
        Index("ix_admin_audit_actor_time", "actor_id", "occurred_at"),
        CheckConstraint("outcome IN ('success','rejected')", name="ck_admin_audit_outcome"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(48))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    target: Mapped[str] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(10))
    summary: Mapped[dict] = mapped_column(JSONB)


class PolicyRevision(Base):
    __tablename__ = "policy_revisions"
    __table_args__ = (CheckConstraint("version > 0", name="ck_policy_version"),)
    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    policies: Mapped[list] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)


def audit(session, actor_id, action, target, outcome="success", summary=None):
    session.add(
        AdminAudit(
            id=uuid4(),
            actor_id=actor_id,
            action=action,
            target=target,
            outcome=outcome,
            summary=summary or {},
            occurred_at=datetime.now(UTC),
        )
    )


class PolicyConflict(Exception):
    pass


class PolicyCoordinator:
    def __init__(self, resources, defaults):
        self.resources, self.defaults = resources, defaults

    async def latest(self, session):
        return await session.scalar(
            select(PolicyRevision).order_by(PolicyRevision.version.desc()).limit(1)
        )

    async def write(self, *, policies=None, expected=None, actor=None):
        """Reconcile when policies is None; otherwise append a validated CAS revision."""
        if policies is not None:
            validate_policies(tuple(policies))
            if not policies or any(
                not p.enabled or (p.rate is None and p.authentication is None) for p in policies
            ):
                raise ValueError("managed policies must contain enabled protection rules")
        redis = self.resources.redis
        fence = json.dumps({"updating": uuid4().hex})
        async with self.resources.session_factory() as session, session.begin():
            await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": POLICY_LOCK})
            previous = await self.latest(session)
            if policies is not None and (previous is None or previous.version != expected):
                audit(
                    session,
                    actor,
                    "policy.update",
                    "policies",
                    "rejected",
                    {"reason": "version_conflict"},
                )
                conflict = True
            else:
                conflict = False
                if policies is not None and previous is not None:
                    replacements = {p.id: p for p in policies}
                    for original in previous.policies:
                        old = EndpointPolicy.model_validate(original)
                        new = replacements.get(old.id)
                        if (
                            new is None
                            or new.path_prefix != old.path_prefix
                            or new.methods != old.methods
                            or (old.rate is not None and new.rate is None)
                            or (old.authentication is not None and new.authentication is None)
                            or (old.failure_mode == "closed" and new.failure_mode != "closed")
                        ):
                            raise ValueError(
                                "managed updates must preserve existing protected scopes"
                            )
                    if any(
                        p.authentication
                        and p.authentication.block_seconds < p.authentication.window_seconds
                        for p in policies
                    ):
                        raise ValueError(
                            "authentication block duration must cover the failure window"
                        )
                if policies is not None or previous is None:
                    source = policies if policies is not None else self.defaults
                    validate_policies(tuple(source))
                    if not source or any(
                        not p.enabled or (p.rate is None and p.authentication is None)
                        for p in source
                    ):
                        raise ValueError("managed initialization requires enabled protection rules")
                    values = [p.model_dump(mode="json") for p in source]
                    current = PolicyRevision(
                        version=previous.version + 1 if previous else 1,
                        policies=values,
                        created_at=datetime.now(UTC),
                        actor_id=actor,
                    )
                    session.add(current)
                    audit(
                        session,
                        actor,
                        "policy.update" if previous else "policy.initialize",
                        "policies",
                        summary={
                            "version": current.version,
                            "policy_ids": [p["id"] for p in values],
                        },
                    )
                else:
                    current = previous
                # If Redis fails or the transaction rolls back, enforcement remains closed.
                await redis.set(POLICY_KEY, fence)
        if conflict:
            raise PolicyConflict
        activated = await redis.eval(
            ACTIVATE, 1, POLICY_KEY, fence, snapshot(current.version, current.policies)
        )
        if not activated:
            raise PolicyUnavailable
        return current
