"""Bounded SQL queries; only version 1 records contribute to request metrics."""

from sqlalchemy import case, func, select, text

from sentinel_api.schemas import AssessmentOut, EventOut, Page
from sentinel_security.analysis_storage import RiskAssessment as Risk
from sentinel_security.storage import SecurityEventRecord as Event


def window_conditions(model, column, query):
    conditions = [column >= query.start, column < query.end]
    if query.service:
        conditions.append(model.service == query.service)
    return conditions


def event_conditions(query):
    conditions = window_conditions(Event, Event.occurred_at, query)
    for name in (
        "event_type",
        "severity",
        "security_action",
        "endpoint",
        "request_id",
        "client_identifier",
    ):
        value = getattr(query, name)
        if value is not None:
            conditions.append(getattr(Event, name) == value)
    return conditions


def risk_conditions(query):
    conditions = window_conditions(Risk, Risk.analyzed_at, query)
    for name in ("severity", "event_id", "client_identifier"):
        value = getattr(query, name)
        if value is not None:
            conditions.append(getattr(Risk, name) == value)
    for name, field in (("classification", "category"), ("detection_method", "detection_method")):
        if getattr(query, name):
            conditions.append(Risk.evidence.contains({"threats": [{field: getattr(query, name)}]}))
    conditions.append(Risk.risk_score >= query.min_risk)
    return conditions


async def page(session, model, schema, conditions, timestamp, key, query):
    total = await session.scalar(select(func.count()).select_from(model).where(*conditions))
    rows = await session.scalars(
        select(model)
        .where(*conditions)
        .order_by(timestamp.desc(), key.desc())
        .limit(query.limit)
        .offset(query.offset)
    )
    return Page(
        items=[schema.model_validate(row) for row in rows],
        total=total,
        limit=query.limit,
        offset=query.offset,
    )


async def recent(session, model, schema, conditions, timestamp, key, limit=20):
    rows = await session.scalars(
        select(model).where(*conditions).order_by(timestamp.desc(), key.desc()).limit(limit)
    )
    return [schema.model_validate(row) for row in rows]


async def analytics(session, query, bucket):
    ec = window_conditions(Event, Event.occurred_at, query)
    rc = window_conditions(Risk, Risk.analyzed_at, query)
    counters = (
        await session.execute(
            select(
                func.count().filter(Event.schema_version == 1),
                func.count().filter(Event.schema_version == 2),
                func.count().filter(
                    (Event.schema_version == 2) & (Event.security_action == "rate_limit")
                ),
                func.count().filter(
                    (Event.schema_version == 2) & (Event.security_action == "temporary_block")
                ),
            ).where(*ec)
        )
    ).one()

    async def grouped(model, expression, conditions, limit=100):
        count = func.count()
        rows = await session.execute(
            select(expression, count)
            .select_from(model)
            .where(*conditions)
            .group_by(expression)
            .order_by(count.desc(), expression)
            .limit(limit)
        )
        return [{"key": str(key), "count": count} for key, count in rows]

    timestamp = func.date_trunc(bucket, Event.occurred_at, "UTC")
    rows = await session.execute(
        select(timestamp, func.count())
        .where(*ec, Event.schema_version == 1)
        .group_by(timestamp)
        .order_by(timestamp)
    )
    timeline = [{"timestamp": stamp, "count": count} for stamp, count in rows]
    severity = await grouped(
        Risk, Risk.severity, [*rc, func.jsonb_array_length(Risk.evidence["threats"]) > 0]
    )
    distribution = case(
        (Risk.risk_score < 25, "0-24.99"),
        (Risk.risk_score < 50, "25-49.99"),
        (Risk.risk_score < 75, "50-74.99"),
        else_="75-100",
    )
    risk_distribution = await grouped(Risk, distribution, rc)
    # Parameters are bound; classification expands persisted allowlisted threat arrays.
    classifications = await session.execute(
        text("""
        SELECT threat->>'category' AS key, count(DISTINCT assessment_id) AS count
        FROM risk_assessments
        CROSS JOIN LATERAL jsonb_array_elements(evidence->'threats') AS threat
        WHERE analyzed_at >= :start AND analyzed_at < :end
        AND (CAST(:service AS text) IS NULL OR service = :service)
        GROUP BY key ORDER BY count DESC, key LIMIT 100
    """),
        {"start": query.start, "end": query.end, "service": query.service},
    )
    clients = await session.execute(
        select(
            Risk.client_identifier,
            Risk.service,
            func.count().label("assessment_count"),
            func.max(Risk.risk_score).label("max_risk"),
            func.max(Risk.analyzed_at).label("last_seen"),
        )
        .where(*rc, Risk.risk_score > 0)
        .group_by(Risk.client_identifier, Risk.service)
        .order_by(func.max(Risk.analyzed_at).desc(), Risk.client_identifier, Risk.service)
        .limit(20)
    )
    return {
        "start": query.start,
        "end": query.end,
        "bucket": bucket,
        "monitored_requests": counters[0],
        "security_decisions": counters[1],
        "rate_limit_violations": counters[2],
        "temporary_blocks": counters[3],
        "requests_over_time": timeline,
        "status_distribution": await grouped(
            Event, Event.status_code, [*ec, Event.schema_version == 1], 500
        ),
        "threats_by_severity": severity,
        "threats_by_classification": [dict(row._mapping) for row in classifications],
        "risk_distribution": risk_distribution,
        "targeted_routes": await grouped(
            Event, Event.endpoint, [*ec, Event.schema_version == 1], 20
        ),
        "recent_alerts": await recent(
            session,
            Risk,
            AssessmentOut,
            [*rc, Risk.risk_score > 0],
            Risk.analyzed_at,
            Risk.assessment_id,
        ),
        "suspicious_clients": [dict(row._mapping) for row in clients],
    }


async def client_activity(session, client_id, query):
    ec = [*window_conditions(Event, Event.occurred_at, query), Event.client_identifier == client_id]
    rc = [*window_conditions(Risk, Risk.analyzed_at, query), Risk.client_identifier == client_id]
    bounds = (
        await session.execute(
            select(func.min(Event.occurred_at), func.max(Event.occurred_at)).where(*ec)
        )
    ).one()
    return {
        "client_identifier": client_id,
        "start": query.start,
        "end": query.end,
        "first_seen": bounds[0],
        "last_seen": bounds[1],
        "recent_requests": await recent(
            session,
            Event,
            EventOut,
            [*ec, Event.schema_version == 1],
            Event.occurred_at,
            Event.event_id,
            50,
        ),
        "assessments": await recent(
            session, Risk, AssessmentOut, rc, Risk.analyzed_at, Risk.assessment_id, 50
        ),
        "violations": await recent(
            session,
            Event,
            EventOut,
            [
                *ec,
                Event.schema_version == 2,
                Event.security_action.in_(("rate_limit", "temporary_block", "deny")),
            ],
            Event.occurred_at,
            Event.event_id,
            50,
        ),
        "temporary_restrictions": await recent(
            session,
            Event,
            EventOut,
            [*ec, Event.security_action == "temporary_block"],
            Event.occurred_at,
            Event.event_id,
            50,
        ),
    }
