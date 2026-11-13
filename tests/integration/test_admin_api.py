"""Real PostgreSQL, Redis and HTTP administrative security integration."""

import asyncio
import json
import os
import secrets
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx2 as httpx
import pytest
from sqlalchemy import delete, func, select, update

from sentinel_api.auth import HASHER, digest
from sentinel_api.bootstrap import bootstrap
from sentinel_api.main import create_app
from sentinel_api.models import AdminAccount, AdminSession, RefreshToken
from sentinel_api.settings import AdminSettings
from sentinel_security.analysis_config import AnalysisPolicy
from sentinel_security.analysis_storage import AnalysisEngine, AnalysisState, RiskAssessment
from sentinel_security.config import Settings
from sentinel_security.events import DetectionEvent, SecurityEvent
from sentinel_security.infrastructure import Resources
from sentinel_security.management import AdminAudit, PolicyRevision
from sentinel_security.policy_runtime import POLICY_KEY, PolicyUnavailable, load_effective
from sentinel_security.protection import RedisProtectionStore, SecurityEngine
from sentinel_security.storage import EventStore, SecurityEventRecord

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run through Compose test profile"
    ),
]
ORIGIN = "https://dashboard.test"
BROWSER = {"Origin": ORIGIN, "X-CSRF-Intent": "sentinel-admin"}


@pytest.fixture
async def admin_env():
    settings = Settings().model_copy(update={"dynamic_policies": False})
    config = AdminSettings(signing_key=secrets.token_hex(32), allowed_origins=(ORIGIN,))
    password = secrets.token_urlsafe(24)
    username = "phase5-" + uuid4().hex
    async with Resources(settings) as resources:
        async with resources.session_factory() as session, session.begin():
            # Exercise genuine first-account provisioning whenever the database is unprovisioned.
            empty = await session.scalar(select(func.count()).select_from(AdminAccount)) == 0
        if empty:
            account_id = await bootstrap(resources, username, password)
        else:
            account_id = uuid4()
            async with resources.session_factory() as session, session.begin():
                session.add(
                    AdminAccount(
                        id=account_id,
                        username=username,
                        password_hash=HASHER.hash(password),
                        role="ADMIN",
                        active=True,
                        created_at=datetime.now(UTC),
                    )
                )

        @asynccontextmanager
        async def resource_factory(settings):
            yield resources

        app = create_app(settings, config, resource_factory)
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://admin.test",
                headers=BROWSER,
            ) as client:
                yield resources, client, username, password, config
        # Only accounts and sessions created by this test are removed. Audit history is retained.
        async with resources.session_factory() as session, session.begin():
            ids = select(AdminAccount.id).where(AdminAccount.username.like(username + "%"))
            families = select(AdminSession.id).where(AdminSession.account_id.in_(ids))
            await session.execute(delete(RefreshToken).where(RefreshToken.session_id.in_(families)))
            await session.execute(delete(AdminSession).where(AdminSession.account_id.in_(ids)))
            await session.execute(delete(AdminAccount).where(AdminAccount.id.in_(ids)))


async def login(env):
    _, client, username, password, _ = env
    response = await client.post(
        "/api/admin/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return data, {"Authorization": "Bearer " + data["access_token"]}


async def test_auth_rotation_reuse_and_logout(admin_env):
    resources, client, _, password, config = admin_env
    data, authorization = await login(admin_env)
    old = client.cookies.get(config.cookie_name)
    assert (await client.get("/api/admin/auth/me", headers=authorization)).status_code == 200
    cookie_header = (
        await client.post(
            "/api/admin/auth/login", json={"username": admin_env[2], "password": password}
        )
    ).headers["set-cookie"]
    assert (
        "HttpOnly" in cookie_header
        and "Secure" in cookie_header
        and "SameSite=strict" in cookie_header
    )
    # Restore first family, rotate it, then replay the original token with its original CSRF nonce.
    client.cookies.clear()
    client.cookies.set(config.cookie_name, old, domain="admin.test", path="/api/admin/auth")
    rotated = await client.post(
        "/api/admin/auth/refresh", headers={"X-CSRF-Token": data["csrf_token"]}
    )
    assert rotated.status_code == 200
    replacement = client.cookies.get(config.cookie_name)
    assert replacement != old
    client.cookies.clear()
    client.cookies.set(config.cookie_name, old, domain="admin.test", path="/api/admin/auth")
    assert (
        await client.post("/api/admin/auth/refresh", headers={"X-CSRF-Token": data["csrf_token"]})
    ).status_code == 401
    assert (
        await client.get(
            "/api/admin/auth/me",
            headers={"Authorization": "Bearer " + rotated.json()["access_token"]},
        )
    ).status_code == 401
    data, authorization = await login(admin_env)
    csrf = (await client.post("/api/admin/auth/csrf")).json()["csrf_token"]
    assert (
        await client.post("/api/admin/auth/logout", headers={"X-CSRF-Token": csrf})
    ).status_code == 204
    assert (await client.get("/api/admin/events", headers=authorization)).status_code == 401
    async with resources.session_factory() as session:
        tokens = list(await session.scalars(select(RefreshToken)))
        assert all(row.digest not in (old, replacement) for row in tokens)
        actions = list(await session.scalars(select(AdminAudit.action)))
        assert {"auth.login", "auth.refresh", "auth.refresh_reuse", "auth.logout"} <= set(actions)
        serialized = json.dumps([row.summary for row in await session.scalars(select(AdminAudit))])
        assert password not in serialized and old not in serialized


async def test_invalid_login_limits_disabled_and_csrf(admin_env):
    resources, client, username, password, _ = admin_env
    assert (await client.get("/api/admin/events")).status_code == 401
    assert (
        await client.post(
            "/api/admin/auth/login",
            json={"username": username, "password": password},
            headers={"Origin": "https://evil.test"},
        )
    ).status_code == 403
    response = await client.post(
        "/api/admin/auth/login", json={"username": username, "password": "wrong"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication failed"
    data, authorization = await login(admin_env)
    assert (await client.post("/api/admin/auth/refresh")).status_code == 403
    assert (
        await client.post("/api/admin/auth/logout", headers={"X-CSRF-Token": "invalid"})
    ).status_code == 403
    async with resources.session_factory() as session, session.begin():
        await session.execute(
            update(AdminAccount).where(AdminAccount.username == username).values(active=False)
        )
    assert (await client.get("/api/admin/events", headers=authorization)).status_code == 401
    assert (
        await client.post("/api/admin/auth/refresh", headers={"X-CSRF-Token": data["csrf_token"]})
    ).status_code == 401
    for _ in range(15):
        response = await client.post(
            "/api/admin/auth/login", json={"username": username, "password": password}
        )
        if response.status_code == 429:
            break
        assert response.status_code == 401
    assert response.status_code == 429
    assert "Retry-After" in response.headers


async def test_concurrent_refresh_revokes_family_and_expiration(admin_env):
    resources, client, _, _, config = admin_env
    data, authorization = await login(admin_env)
    token = client.cookies.get(config.cookie_name)
    headers = {
        **BROWSER,
        "Cookie": config.cookie_name + "=" + token,
        "X-CSRF-Token": data["csrf_token"],
    }
    responses = await asyncio.gather(
        *(client.post("/api/admin/auth/refresh", headers=headers) for _ in range(2))
    )
    assert sorted(r.status_code for r in responses) == [200, 401]
    assert (await client.get("/api/admin/auth/me", headers=authorization)).status_code == 401
    data, authorization = await login(admin_env)
    token = client.cookies.get(config.cookie_name)
    async with resources.session_factory() as session, session.begin():
        family_id = await session.scalar(
            select(RefreshToken.session_id).where(RefreshToken.digest == digest(token))
        )
        await session.execute(
            update(AdminSession)
            .where(AdminSession.id == family_id)
            .values(
                created_at=datetime.now(UTC) - timedelta(days=2),
                expires_at=datetime.now(UTC) - timedelta(days=1),
            )
        )
    assert (
        await client.post("/api/admin/auth/refresh", headers={"X-CSRF-Token": data["csrf_token"]})
    ).status_code == 401
    assert (await client.get("/api/admin/events", headers=authorization)).status_code == 401


async def test_accounts_rbac_validation_and_audit(admin_env):
    resources, client, username, password, _ = admin_env
    admin, authorization = await login(admin_env)
    response = await client.post(
        "/api/admin/accounts",
        headers=authorization,
        json={"username": username + "-analyst", "password": password, "role": "ANALYST"},
    )
    assert response.status_code == 201, response.text
    analyst_id = response.json()["id"]
    analyst = (
        await client.post(
            "/api/admin/auth/login", json={"username": username + "-analyst", "password": password}
        )
    ).json()
    analyst_auth = {"Authorization": "Bearer " + analyst["access_token"]}
    for path in ("/events", "/assessments", "/analytics", "/policies"):
        assert (await client.get("/api/admin" + path, headers=analyst_auth)).status_code == 200
    document = (await client.get("/api/admin/policies", headers=authorization)).json()
    assert (
        await client.put(
            "/api/admin/policies",
            headers=analyst_auth,
            json={"expected_version": document["version"], "policies": document["policies"]},
        )
    ).status_code == 403
    for path in ("/accounts", "/audit"):
        assert (await client.get("/api/admin" + path, headers=analyst_auth)).status_code == 403
    assert (
        await client.post(
            "/api/admin/accounts",
            headers=analyst_auth,
            json={"username": username + "-other", "password": password, "role": "ADMIN"},
        )
    ).status_code == 403
    updated = await client.patch(
        "/api/admin/accounts/" + analyst_id, headers=authorization, json={"active": False}
    )
    assert updated.status_code == 200
    assert (await client.get("/api/admin/events", headers=analyst_auth)).status_code == 401
    invalid = await client.post(
        "/api/admin/accounts",
        headers=authorization,
        json={"username": username + "-invalid", "password": "short-private", "role": "ADMIN"},
    )
    assert invalid.status_code == 422 and "short-private" not in invalid.text
    audit_response = await client.get("/api/admin/audit", headers=authorization)
    assert audit_response.status_code == 200
    assert any(row["action"] == "authorization.denied" for row in audit_response.json()["items"])
    assert "password_hash" not in audit_response.text and password not in audit_response.text
    with pytest.raises(ValueError, match="Bootstrap unavailable"):
        await bootstrap(resources, username + "-bootstrap", password)
    print(
        "phase5_rbac_audit",
        json.dumps({"analyst_policy_update": 403, "audit_rows": audit_response.json()["total"]}),
    )


@pytest.fixture
async def stored_events(admin_env):
    resources = admin_env[0]
    service = "phase5-" + uuid4().hex
    now = datetime.now(UTC) - timedelta(seconds=5)
    identity = secrets.token_hex(32)
    base = dict(
        schema_version=1,
        event_type="http.request.completed",
        event_id=uuid4(),
        request_id=uuid4().hex,
        occurred_at=now,
        service=service,
        method="GET",
        endpoint="/api/demo/items/{item_id}",
        status_code=200,
        duration_ms=1.0,
        client_identifier=identity,
        severity="info",
        authentication_outcome="not_provided",
        response_completed=True,
    )
    first = SecurityEvent(**base)
    second = SecurityEvent(
        **{
            **base,
            "event_id": uuid4(),
            "request_id": uuid4().hex,
            "status_code": 401,
            "severity": "warning",
            "authentication_outcome": "failed",
        }
    )
    decision = DetectionEvent(
        **{
            **second.model_dump(),
            "schema_version": 2,
            "event_type": "security.decision",
            "event_id": uuid4(),
            "rule_id": "demo.rate",
            "security_action": "rate_limit",
            "counter_value": 6,
            "threshold": 5,
        }
    )
    block = DetectionEvent(
        **{
            **decision.model_dump(),
            "event_id": uuid4(),
            "security_action": "temporary_block",
            "restriction_expires_at": now + timedelta(minutes=1),
        }
    )
    store = EventStore(resources.session_factory, AnalysisEngine(AnalysisPolicy()))
    for event in (first, second, decision, block):
        assert await store.persist(event)
    yield service, identity, (first, second, decision, block)
    async with resources.session_factory() as session, session.begin():
        await session.execute(
            delete(SecurityEventRecord).where(SecurityEventRecord.service == service)
        )
        await session.execute(delete(AnalysisState).where(AnalysisState.service == service))


async def test_events_assessments_analytics_and_privacy(admin_env, stored_events):
    resources, client, _, _, _ = admin_env
    service, identity, rows = stored_events
    _, authorization = await login(admin_env)
    response = await client.get(
        "/api/admin/events", headers=authorization, params={"service": service, "limit": 2}
    )
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 4 and len(page["items"]) == 2
    next_page = (
        await client.get(
            "/api/admin/events",
            headers=authorization,
            params={"service": service, "limit": 2, "offset": 2},
        )
    ).json()
    assert len({row["event_id"] for row in page["items"] + next_page["items"]}) == 4
    for params, expected in [
        ({"event_type": "http.request.completed"}, 2),
        ({"security_action": "rate_limit"}, 1),
        ({"severity": "warning"}, 3),
        ({"request_id": rows[1].request_id}, 3),
        ({"endpoint": "/api/demo/items/{item_id}"}, 4),
    ]:
        result = await client.get(
            "/api/admin/events", headers=authorization, params={"service": service, **params}
        )
        assert result.json()["total"] == expected
    detail = await client.get("/api/admin/events/" + str(rows[0].event_id), headers=authorization)
    assert detail.status_code == 200
    assert (
        await client.get("/api/admin/events/" + str(uuid4()), headers=authorization)
    ).status_code == 404
    for params in (
        {"limit": 101},
        {"offset": 10001},
        {"endpoint": "/api?password=secret"},
        {"unknown": "value"},
        {"start": "2020-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
    ):
        assert (
            await client.get("/api/admin/events", headers=authorization, params=params)
        ).status_code == 422
    risks = await client.get(
        "/api/admin/assessments", headers=authorization, params={"service": service}
    )
    assert risks.status_code == 200, risks.text
    assert risks.json()["total"] == 4
    assessment_id = risks.json()["items"][0]["assessment_id"]
    assert (
        await client.get("/api/admin/assessments/" + assessment_id, headers=authorization)
    ).status_code == 200
    filtered = await client.get(
        "/api/admin/assessments",
        headers=authorization,
        params={
            "service": service,
            "classification": "repeated_authentication_failures",
            "detection_method": "deterministic",
        },
    )
    assert filtered.json()["total"] == 3
    # Poison extra JSON keys to verify that public response models discard private extensions.
    async with resources.session_factory() as session, session.begin():
        risk = await session.scalar(
            select(RiskAssessment).where(RiskAssessment.service == service).limit(1)
        )
        risk.evidence = {
            **risk.evidence,
            "password": "must-never-leak",
            "raw_ip": "198.51.100.10",
            "cookie": "must-never-leak",
        }
    analytics = await client.get(
        "/api/admin/analytics", headers=authorization, params={"service": service}
    )
    assert analytics.status_code == 200, analytics.text
    metrics = analytics.json()
    assert metrics["monitored_requests"] == 2
    assert metrics["security_decisions"] == 2
    assert metrics["rate_limit_violations"] == 1 and metrics["temporary_blocks"] == 1
    assert sum(item["count"] for item in metrics["requests_over_time"]) == 2
    assert sum(item["count"] for item in metrics["status_distribution"]) == 2
    assert sum(item["count"] for item in metrics["threats_by_severity"]) == 3
    activity = await client.get(
        "/api/admin/clients/" + identity + "/activity",
        headers=authorization,
        params={"service": service},
    )
    assert activity.status_code == 200, activity.text
    assert len(activity.json()["recent_requests"]) == 2
    assert len(activity.json()["violations"]) == 2
    assert len(activity.json()["temporary_restrictions"]) == 1
    serialized = analytics.text + activity.text + risks.text
    for secret in ("must-never-leak", "raw_ip", "password_hash", "198.51.100.10", "cookie"):
        assert secret not in serialized
    empty = (
        await client.get(
            "/api/admin/analytics",
            headers=authorization,
            params={"service": "absent-" + uuid4().hex},
        )
    ).json()
    assert empty["monitored_requests"] == 0 and empty["recent_alerts"] == []
    print("phase5_real_analytics", json.dumps(metrics))


async def test_actual_policy_propagation_fencing_and_version_conflict(admin_env):
    resources, client, _, _, _ = admin_env
    data, authorization = await login(admin_env)
    original = (await client.get("/api/admin/policies", headers=authorization)).json()
    additions = deepcopy(original["policies"])
    target = next(p for p in additions if p["id"] == "demo-limited")
    target["rate"] = {
        "requests": 1,
        "window_seconds": 3,
        "exceed_action": "rate_limit",
        "block_seconds": 3,
    }
    response = await client.put(
        "/api/admin/policies",
        headers=authorization,
        json={"expected_version": original["version"], "policies": additions},
    )
    assert response.status_code == 200, response.text
    version = response.json()["version"]
    assert response.json()["enforcement_synchronized"]
    store = RedisProtectionStore(lambda: resources.redis, 1)

    async def loader():
        return await load_effective(resources.redis)

    first = SecurityEngine(store, "phase5-propagation", (), policy_loader=loader)
    second = SecurityEngine(store, "phase5-propagation", (), policy_loader=loader)
    scope = {
        "path": target["path_prefix"],
        "method": "GET",
        "state": {"request_id": uuid4().hex},
    }
    identity = secrets.token_hex(32)
    assert (await first.before_request(scope, identity)).response_status is None
    scope["state"]["request_id"] = uuid4().hex
    assert (await second.before_request(scope, identity)).response_status == 429
    # The same centrally managed version is also consumed by the separately running demo API.
    async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as demo:
        for _ in range(2):
            result = await demo.get(target["path_prefix"])
        assert result.status_code == 429
    conflict = await client.put(
        "/api/admin/policies",
        headers=authorization,
        json={"expected_version": original["version"], "policies": additions},
    )
    assert conflict.status_code == 409
    unsafe = await client.put(
        "/api/admin/policies",
        headers=authorization,
        json={"expected_version": version, "policies": []},
    )
    assert unsafe.status_code == 422
    await resources.redis.set(POLICY_KEY, '{"updating":"simulated-crash"}')
    assert (await first.before_request(scope, identity)).response_status == 503
    assert (
        await client.post("/api/admin/policies/reconcile", headers=authorization)
    ).status_code == 200
    async with resources.session_factory() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(PolicyRevision)
                .where(PolicyRevision.version == version)
            )
            == 1
        )
        actions = list(
            await session.scalars(
                select(AdminAudit).where(AdminAudit.actor_id == data["account"]["id"])
            )
        )
        assert any(row.action == "policy.update" and row.outcome == "success" for row in actions)
        assert any(row.action == "policy.update" and row.outcome == "rejected" for row in actions)
    assert (
        await client.put(
            "/api/admin/policies",
            headers=authorization,
            json={"expected_version": version, "policies": original["policies"]},
        )
    ).status_code == 200
    print(
        "phase5_policy_enforcement",
        json.dumps(
            {
                "version": version,
                "second_instance_status": 429,
                "running_demo_status": 429,
                "fenced_status": 503,
            }
        ),
    )


async def test_http_claim_tampering_origin_cors_and_last_admin(admin_env):
    import jwt

    resources, client, username, password, config = admin_env
    data, authorization = await login(admin_env)
    key = bytes.fromhex(config.signing_key.get_secret_value())
    claims = jwt.decode(data["access_token"], key, algorithms=["HS256"], audience=config.audience)
    for altered in (
        {**claims, "exp": 1},
        {**claims, "aud": "other"},
        {**claims, "token_type": "refresh"},
    ):
        token = jwt.encode(altered, key, algorithm="HS256", headers={"typ": "at+jwt"})
        assert (
            await client.get("/api/admin/events", headers={"Authorization": "Bearer " + token})
        ).status_code == 401
    unsigned = jwt.encode(claims, "", algorithm="none")
    assert (
        await client.get("/api/admin/events", headers={"Authorization": "Bearer " + unsigned})
    ).status_code == 401
    wrong = jwt.encode(
        claims, secrets.token_bytes(32), algorithm="HS256", headers={"typ": "at+jwt"}
    )
    assert (
        await client.get("/api/admin/events", headers={"Authorization": "Bearer " + wrong})
    ).status_code == 401
    preflight = await client.options(
        "/api/admin/events",
        headers={
            "Origin": ORIGIN,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    assert preflight.headers["access-control-allow-origin"] == ORIGIN
    evil = await client.options(
        "/api/admin/events",
        headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in evil.headers
    missing_origin = await client.post(
        "/api/admin/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": ""},
    )
    assert missing_origin.status_code == 403
    invalid = await client.post(
        "/api/admin/auth/login",
        json={"username": username, "password": password, "token": "never-echo-this"},
    )
    assert invalid.status_code == 422 and "never-echo-this" not in invalid.text
    response = await client.patch(
        "/api/admin/accounts/" + data["account"]["id"],
        headers=authorization,
        json={"active": False},
    )
    # The fixture is the sole active account on an unprovisioned local stack. If a real
    # administrator exists, the test may disable only its own ephemeral fixture account.
    if response.status_code == 409:
        assert "last active administrator" in response.json()["detail"]
    else:
        assert response.status_code == 200
    assert (await client.get("/health/live")).status_code == 200


async def test_account_changes_duplicate_and_password_revocation(admin_env):
    _, client, username, password, _ = admin_env
    data, authorization = await login(admin_env)
    body = {"username": username + "-managed", "password": password, "role": "ANALYST"}
    created = await client.post("/api/admin/accounts", headers=authorization, json=body)
    assert created.status_code == 201
    identifier = created.json()["id"]
    assert (
        await client.post("/api/admin/accounts", headers=authorization, json=body)
    ).status_code == 409
    login_response = await client.post(
        "/api/admin/auth/login", json={"username": body["username"], "password": password}
    )
    old = {"Authorization": "Bearer " + login_response.json()["access_token"]}
    replacement = secrets.token_urlsafe(24)
    changed = await client.patch(
        "/api/admin/accounts/" + identifier,
        headers=authorization,
        json={"password": replacement, "role": "ADMIN"},
    )
    assert changed.status_code == 200 and changed.json()["role"] == "ADMIN"
    assert (await client.get("/api/admin/events", headers=old)).status_code == 401
    assert (
        await client.post(
            "/api/admin/auth/login", json={"username": body["username"], "password": password}
        )
    ).status_code == 401
    assert (
        await client.post(
            "/api/admin/auth/login", json={"username": body["username"], "password": replacement}
        )
    ).status_code == 200
    assert (
        await client.patch(
            "/api/admin/accounts/" + str(uuid4()), headers=authorization, json={"active": False}
        )
    ).status_code == 404
    assert (
        await client.get("/api/admin/accounts", headers=authorization, params={"limit": 1})
    ).json()["limit"] == 1


async def test_policy_unsafe_updates_and_concurrent_writers(admin_env):
    resources, client, _, _, _ = admin_env
    _, authorization = await login(admin_env)
    original = (await client.get("/api/admin/policies", headers=authorization)).json()
    assert (
        await client.get("/api/admin/policies/demo-login", headers=authorization)
    ).status_code == 200
    assert (
        await client.get("/api/admin/policies/missing", headers=authorization)
    ).status_code == 404
    for change in (
        "remove",
        "overlap",
        "disable",
        "scope",
        "remove_auth",
        "open_login",
        "short_block",
    ):
        values = deepcopy(original["policies"])
        target = next(p for p in values if p["id"] == "demo-login")
        if change == "remove":
            values = [p for p in values if p["id"] != "demo-login"]
        elif change == "overlap":
            values.append({**target, "id": "conflicting"})
        elif change == "disable":
            target["enabled"] = False
        elif change == "scope":
            target["path_prefix"] = "/different"
        elif change == "remove_auth":
            target["authentication"] = None
        elif change == "open_login":
            target["failure_mode"] = "open"
        else:
            target["authentication"]["block_seconds"] = 1
        response = await client.put(
            "/api/admin/policies",
            headers=authorization,
            json={"expected_version": original["version"], "policies": values},
        )
        assert response.status_code == 422
    results = await asyncio.gather(
        *(
            client.put(
                "/api/admin/policies",
                headers=authorization,
                json={"expected_version": original["version"], "policies": original["policies"]},
            )
            for _ in range(2)
        )
    )
    assert sorted(r.status_code for r in results) == [200, 409]
    current = (await client.get("/api/admin/policies", headers=authorization)).json()
    assert current["enforcement_synchronized"] and current["version"] == original["version"] + 1
    assert tuple(p.id for p in await load_effective(resources.redis)) == tuple(
        p["id"] for p in original["policies"]
    )


async def test_live_client_restrictions_and_assessment_filters(admin_env, stored_events):
    resources, client, _, _, _ = admin_env
    service, identity, rows = stored_events
    _, authorization = await login(admin_env)
    policy = next(p for p in await load_effective(resources.redis) if p.id == "demo-limited")
    engine = SecurityEngine(None, service, (policy,))
    key = engine.keys(policy, identity)[1]
    await resources.redis.set(key, "test-only-restriction", px=10000)
    try:
        response = await client.get(
            "/api/admin/clients/" + identity + "/activity",
            headers=authorization,
            params={"service": service},
        )
        assert response.status_code == 200
        assert any(
            r["policy_id"] == policy.id and 0 < r["remaining_seconds"] <= 10
            for r in response.json()["active_restrictions"]
        )
        result = await client.get(
            "/api/admin/assessments",
            headers=authorization,
            params={
                "service": service,
                "client_identifier": identity,
                "severity": "low",
                "min_risk": 0,
                "event_id": str(rows[0].event_id),
            },
        )
        assert result.status_code == 200 and result.json()["total"] == 1
        assert (
            await client.get("/api/admin/assessments/" + str(uuid4()), headers=authorization)
        ).status_code == 404
        audits = await client.get(
            "/api/admin/audit",
            headers=authorization,
            params={"action": "auth.login", "outcome": "success"},
        )
        assert audits.status_code == 200
    finally:
        await resources.redis.delete(key)


async def test_interrupted_policy_activation_is_closed_and_recoverable(admin_env, monkeypatch):
    from redis.exceptions import RedisError

    resources, client, _, _, _ = admin_env
    _, authorization = await login(admin_env)
    original = (await client.get("/api/admin/policies", headers=authorization)).json()

    async def unavailable(*args, **kwargs):
        raise RedisError("private-redis-error-value")

    with monkeypatch.context() as patch:
        patch.setattr(resources.redis, "eval", unavailable)
        response = await client.put(
            "/api/admin/policies",
            headers=authorization,
            json={"expected_version": original["version"], "policies": original["policies"]},
        )
        assert response.status_code == 503 and "private-redis-error-value" not in response.text
    current = (await client.get("/api/admin/policies", headers=authorization)).json()
    assert current["version"] == original["version"] + 1
    assert not current["enforcement_synchronized"]
    with pytest.raises(PolicyUnavailable):
        await load_effective(resources.redis)
    assert (
        await client.post("/api/admin/policies/reconcile", headers=authorization)
    ).status_code == 200
    assert (await client.get("/api/admin/policies", headers=authorization)).json()[
        "enforcement_synchronized"
    ]
