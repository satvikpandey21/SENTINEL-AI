"""Authenticated monitoring, analytics, policy and account management routes."""

import asyncio
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from redis.exceptions import RedisError
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_api import queries
from sentinel_api.auth import HASHER, administrator, current_account, origin
from sentinel_api.auth_routes import AccountOut
from sentinel_api.models import AdminAccount, AdminSession
from sentinel_api.schemas import (
    AnalyticsOut,
    AssessmentFilter,
    AssessmentOut,
    ClientActivity,
    ClientID,
    EventFilter,
    EventOut,
    Page,
    Pagination,
    PublicModel,
    Window,
)
from sentinel_security.analysis_storage import RiskAssessment
from sentinel_security.database import get_session
from sentinel_security.management import (
    POLICY_KEY,
    AdminAudit,
    PolicyConflict,
    PolicyCoordinator,
    PolicyUnavailable,
    audit,
    snapshot,
)
from sentinel_security.policies import EndpointPolicy, validate_policies
from sentinel_security.policy_runtime import load_effective
from sentinel_security.protection import SecurityEngine
from sentinel_security.storage import SecurityEventRecord

router = APIRouter(dependencies=[Depends(current_account)])


@router.get("/events", response_model=Page[EventOut], tags=["events"])
async def events(
    query: Annotated[EventFilter, Query()], session: Annotated[AsyncSession, Depends(get_session)]
):
    return await queries.page(
        session,
        SecurityEventRecord,
        EventOut,
        queries.event_conditions(query),
        SecurityEventRecord.occurred_at,
        SecurityEventRecord.event_id,
        query,
    )


@router.get("/events/{event_id}", response_model=EventOut, tags=["events"])
async def event(event_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]):
    row = await session.get(SecurityEventRecord, event_id)
    if row is None:
        raise HTTPException(404, "Event not found")
    return EventOut.model_validate(row)


@router.get("/assessments", response_model=Page[AssessmentOut], tags=["assessments"])
async def assessments(
    query: Annotated[AssessmentFilter, Query()],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    return await queries.page(
        session,
        RiskAssessment,
        AssessmentOut,
        queries.risk_conditions(query),
        RiskAssessment.analyzed_at,
        RiskAssessment.assessment_id,
        query,
    )


@router.get("/assessments/{assessment_id}", response_model=AssessmentOut, tags=["assessments"])
async def assessment(assessment_id: UUID, session: Annotated[AsyncSession, Depends(get_session)]):
    row = await session.get(RiskAssessment, assessment_id)
    if row is None:
        raise HTTPException(404, "Assessment not found")
    return AssessmentOut.model_validate(row)


class AnalyticsFilter(Window):
    bucket: Literal["hour", "day"] = "hour"


@router.get("/analytics", response_model=AnalyticsOut, tags=["analytics"])
async def analytics(
    query: Annotated[AnalyticsFilter, Query()],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
    await session.execute(text("SET LOCAL statement_timeout = '5000ms'"))
    return await queries.analytics(session, query, query.bucket)


@router.get(
    "/clients/{client_identifier}/activity", response_model=ClientActivity, tags=["clients"]
)
async def client_activity(
    client_identifier: ClientID,
    query: Annotated[Window, Query()],
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    result = await queries.client_activity(session, client_identifier, query)
    conditions = queries.window_conditions(
        SecurityEventRecord, SecurityEventRecord.occurred_at, query
    )
    services = list(
        await session.scalars(
            select(SecurityEventRecord.service)
            .where(*conditions, SecurityEventRecord.client_identifier == client_identifier)
            .distinct()
            .order_by(SecurityEventRecord.service)
            .limit(20)
        )
    )
    redis = request.app.state.resources.redis
    policies = await load_effective(redis)
    entries = []
    async with redis.pipeline(transaction=False) as pipeline:
        for service in services:
            engine = SecurityEngine(None, service, policies)
            for policy in policies:
                entries.append((service, policy.id))
                pipeline.pttl(engine.keys(policy, client_identifier)[1])
        ttls = await pipeline.execute()
    observed = datetime.now(UTC)
    result["active_restrictions"] = [
        {
            "service": service,
            "policy_id": policy_id,
            "remaining_seconds": (ttl + 999) // 1000,
            "observed_at": observed,
        }
        for (service, policy_id), ttl in zip(entries, ttls, strict=True)
        if ttl > 0
    ]
    return result


class PolicyOut(BaseModel):
    version: int
    created_at: datetime
    policies: list[EndpointPolicy]
    enforcement_synchronized: bool


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_version: int = Field(ge=1)
    policies: tuple[EndpointPolicy, ...] = Field(min_length=1, max_length=32)


async def policy_document(request):
    coordinator = PolicyCoordinator(
        request.app.state.resources, request.app.state.settings.effective_policies
    )
    async with request.app.state.resources.session_factory() as session:
        row = await coordinator.latest(session)
    if row is None:
        raise HTTPException(503, "Policy system not initialized")
    effective = await request.app.state.resources.redis.get(POLICY_KEY)
    return PolicyOut(
        version=row.version,
        created_at=row.created_at,
        policies=row.policies,
        enforcement_synchronized=effective == snapshot(row.version, row.policies),
    )


@router.get("/policies", response_model=PolicyOut, tags=["policies"])
async def policies(request: Request):
    return await policy_document(request)


@router.get("/policies/{policy_id}", response_model=EndpointPolicy, tags=["policies"])
async def policy(
    policy_id: Annotated[str, Path(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,47}$")], request: Request
):
    document = await policy_document(request)
    for value in document.policies:
        if value.id == policy_id:
            return value
    raise HTTPException(404, "Policy not found")


@router.put(
    "/policies", response_model=PolicyOut, tags=["policies"], dependencies=[Depends(origin)]
)
async def update_policies(
    data: PolicyUpdate, request: Request, account: Annotated[AdminAccount, Depends(administrator)]
):
    coordinator = PolicyCoordinator(
        request.app.state.resources, request.app.state.settings.effective_policies
    )
    try:
        validate_policies(data.policies)
        row = await coordinator.write(
            policies=data.policies, expected=data.expected_version, actor=account.id
        )
    except ValueError:
        async with request.app.state.resources.session_factory() as session, session.begin():
            audit(
                session,
                account.id,
                "policy.update",
                "policies",
                "rejected",
                {"reason": "unsafe_configuration"},
            )
        raise HTTPException(422, "Unsafe or contradictory policy configuration") from None
    except PolicyConflict:
        raise HTTPException(409, "Policy version conflict; reload current policies") from None
    except (PolicyUnavailable, RedisError, OSError, TimeoutError):
        raise HTTPException(
            503, "Policy activation pending; enforcement is closed until reconciliation"
        ) from None
    return PolicyOut(
        version=row.version,
        created_at=row.created_at,
        policies=row.policies,
        enforcement_synchronized=True,
    )


@router.post(
    "/policies/reconcile",
    response_model=PolicyOut,
    tags=["policies"],
    dependencies=[Depends(origin)],
)
async def reconcile(request: Request, account: Annotated[AdminAccount, Depends(administrator)]):
    coordinator = PolicyCoordinator(
        request.app.state.resources, request.app.state.settings.effective_policies
    )
    await coordinator.write()
    async with request.app.state.resources.session_factory() as session, session.begin():
        audit(session, account.id, "policy.reconcile", "policies")
    return await policy_document(request)


class CreateAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    password: SecretStr = Field(min_length=15, max_length=128)
    role: Literal["ADMIN", "ANALYST"]


class UpdateAccount(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    role: Literal["ADMIN", "ANALYST"] | None = None
    active: bool | None = None
    password: SecretStr | None = Field(default=None, min_length=15, max_length=128)


@router.get(
    "/accounts",
    response_model=Page[AccountOut],
    tags=["accounts"],
    dependencies=[Depends(administrator)],
)
async def accounts(
    query: Annotated[Pagination, Query()], session: Annotated[AsyncSession, Depends(get_session)]
):
    return await queries.page(
        session, AdminAccount, AccountOut, [], AdminAccount.created_at, AdminAccount.id, query
    )


@router.post(
    "/accounts",
    response_model=AccountOut,
    status_code=201,
    tags=["accounts"],
    dependencies=[Depends(origin)],
)
async def create_account(
    data: CreateAccount, request: Request, account: Annotated[AdminAccount, Depends(administrator)]
):
    async with request.app.state.hash_slots:
        encoded = await asyncio.to_thread(HASHER.hash, data.password.get_secret_value())
    async with request.app.state.resources.session_factory() as session, session.begin():
        await session.execute(text("SELECT pg_advisory_xact_lock(517291406)"))
        existing = await session.scalar(
            select(AdminAccount.id).where(AdminAccount.username == data.username)
        )
        if existing:
            audit(
                session,
                account.id,
                "account.create",
                "accounts",
                "rejected",
                {"reason": "already_exists"},
            )
            result = None
        else:
            result = AdminAccount(
                id=uuid4(),
                username=data.username,
                password_hash=encoded,
                role=data.role,
                active=True,
                created_at=datetime.now(UTC),
            )
            session.add(result)
            audit(
                session, account.id, "account.create", str(result.id), summary={"role": data.role}
            )
    if result is None:
        raise HTTPException(409, "Account already exists")
    return AccountOut.model_validate(result)


@router.patch(
    "/accounts/{account_id}",
    response_model=AccountOut,
    tags=["accounts"],
    dependencies=[Depends(origin)],
)
async def update_account(
    account_id: UUID,
    data: UpdateAccount,
    request: Request,
    actor: Annotated[AdminAccount, Depends(administrator)],
):
    encoded = None
    if data.password is not None:
        async with request.app.state.hash_slots:
            encoded = await asyncio.to_thread(HASHER.hash, data.password.get_secret_value())
    rejection = None
    async with request.app.state.resources.session_factory() as session, session.begin():
        await session.execute(text("SELECT pg_advisory_xact_lock(517291406)"))
        account = await session.scalar(
            select(AdminAccount).where(AdminAccount.id == account_id).with_for_update()
        )
        if account is None:
            rejection = (404, "Account not found")
        elif (
            account.role == "ADMIN"
            and account.active
            and (data.role == "ANALYST" or data.active is False)
        ):
            admins = await session.scalar(
                select(func.count())
                .select_from(AdminAccount)
                .where(AdminAccount.active.is_(True), AdminAccount.role == "ADMIN")
            )
            if admins <= 1:
                rejection = (409, "Cannot disable or demote the last active administrator")
        if rejection:
            audit(
                session,
                actor.id,
                "account.update",
                str(account_id),
                "rejected",
                {"reason": "not_found_or_last_admin"},
            )
        else:
            if data.role is not None:
                account.role = data.role
            if data.active is not None:
                account.active = data.active
            if encoded:
                account.password_hash = encoded
            await session.execute(
                update(AdminSession)
                .where(AdminSession.account_id == account_id, AdminSession.revoked_at.is_(None))
                .values(revoked_at=datetime.now(UTC))
            )
            audit(
                session,
                actor.id,
                "account.update",
                str(account_id),
                summary={
                    "role": account.role,
                    "active": account.active,
                    "password_changed": encoded is not None,
                },
            )
    if rejection:
        raise HTTPException(*rejection)
    return AccountOut.model_validate(account)


class AuditSummary(PublicModel):
    reason: str | None = None
    version: int | None = None
    policy_ids: list[str] | None = None
    role: str | None = None
    active: bool | None = None
    password_changed: bool | None = None
    method: str | None = None


class AuditOut(PublicModel):
    id: UUID
    actor_id: UUID | None
    action: str
    occurred_at: datetime
    target: str
    outcome: Literal["success", "rejected"]
    summary: AuditSummary


class AuditFilter(Window, Pagination):
    # Audit records do not belong to a monitored service.
    service: None = None
    actor_id: UUID | None = None
    action: Annotated[str, Field(max_length=48, pattern=r"^[a-z_.]+$")] | None = None
    outcome: Literal["success", "rejected"] | None = None


@router.get(
    "/audit", response_model=Page[AuditOut], tags=["audit"], dependencies=[Depends(administrator)]
)
async def audit_records(
    query: Annotated[AuditFilter, Query()], session: Annotated[AsyncSession, Depends(get_session)]
):
    conditions = [AdminAudit.occurred_at >= query.start, AdminAudit.occurred_at < query.end]
    for name in ("actor_id", "action", "outcome"):
        if getattr(query, name) is not None:
            conditions.append(getattr(AdminAudit, name) == getattr(query, name))
    return await queries.page(
        session, AdminAudit, AuditOut, conditions, AdminAudit.occurred_at, AdminAudit.id, query
    )
