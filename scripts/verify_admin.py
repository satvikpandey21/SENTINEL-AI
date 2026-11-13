# ruff: noqa: S101 - executable acceptance checks, never a production authorization boundary
"""Repeatable real HTTP A-J verification with ephemeral accounts and no printed secrets.

Run in the Compose test container. The local HTTP deployment must explicitly permit
--origin; HTTPS deployments should supply their TLS administrative URL.
"""

import argparse
import asyncio
import json
import secrets
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import uuid4

import httpx2 as httpx
from sqlalchemy import delete, func, select

from sentinel_api.auth import HASHER
from sentinel_api.bootstrap import bootstrap
from sentinel_api.models import AdminAccount, AdminSession, RefreshToken
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.management import audit
from sentinel_security.storage import SecurityEventRecord


async def verify(base_url, origin):
    username, password = "verify5-" + uuid4().hex, secrets.token_urlsafe(24)
    evidence = {}
    original = None
    changed = False
    authorization = None
    async with Resources(Settings()) as resources:
        async with resources.session_factory() as session:
            empty = await session.scalar(select(func.count()).select_from(AdminAccount)) == 0
        if empty:
            identifier = await bootstrap(resources, username, password)
            evidence["provisioning"] = "first-account bootstrap"
        else:
            identifier = uuid4()
            async with resources.session_factory() as session, session.begin():
                session.add(
                    AdminAccount(
                        id=identifier,
                        username=username,
                        password_hash=HASHER.hash(password),
                        role="ADMIN",
                        active=True,
                        created_at=datetime.now(UTC),
                    )
                )
                audit(
                    session,
                    identifier,
                    "account.verification",
                    str(identifier),
                    summary={"role": "ADMIN"},
                )
            evidence["provisioning"] = "ephemeral verification account; existing accounts preserved"
        headers = {"Origin": origin, "X-CSRF-Intent": "sentinel-admin"}
        try:
            async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=15) as client:
                response = await client.get("/api/admin/events")
                assert response.status_code == 401
                evidence["B_unauthenticated_events"] = response.status_code
                response = await client.post(
                    "/api/admin/auth/login", json={"username": username, "password": password}
                )
                assert response.status_code == 200, response.status_code
                authenticated = response.json()
                authorization = {"Authorization": "Bearer " + authenticated["access_token"]}
                evidence["A_administrator_login"] = response.status_code
                response = await client.post(
                    "/api/admin/accounts",
                    headers=authorization,
                    json={
                        "username": username + "-analyst",
                        "password": password,
                        "role": "ANALYST",
                    },
                )
                assert response.status_code == 201
                original = (await client.get("/api/admin/policies", headers=authorization)).json()
                async with httpx.AsyncClient(
                    base_url=base_url, headers=headers, timeout=15
                ) as analyst:
                    login = await analyst.post(
                        "/api/admin/auth/login",
                        json={"username": username + "-analyst", "password": password},
                    )
                    assert login.status_code == 200
                    denied = await analyst.put(
                        "/api/admin/policies",
                        headers={"Authorization": "Bearer " + login.json()["access_token"]},
                        json={
                            "expected_version": original["version"],
                            "policies": original["policies"],
                        },
                    )
                    assert denied.status_code == 403
                    evidence["C_analyst_policy_update"] = denied.status_code
                start = datetime.now(UTC) - timedelta(seconds=1)
                async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as demo:
                    ping = await demo.get("/api/demo/ping?verification=not-persisted")
                    assert ping.status_code == 200
                    request_id = ping.headers["X-Request-ID"]
                    evidence["J_existing_monitoring"] = ping.status_code
                    end = datetime.now(UTC) + timedelta(seconds=1)
                    deadline = monotonic() + 15
                    while monotonic() < deadline:
                        events = await client.get(
                            "/api/admin/events",
                            headers=authorization,
                            params={"request_id": request_id},
                        )
                        assert events.status_code == 200
                        if events.json()["items"]:
                            break
                        await asyncio.sleep(0.1)
                    event = events.json()["items"][0]
                    evidence["D_stored_event"] = {
                        k: event[k]
                        for k in (
                            "event_id",
                            "request_id",
                            "schema_version",
                            "service",
                            "endpoint",
                            "status_code",
                        )
                    }
                    risks = await client.get(
                        "/api/admin/assessments",
                        headers=authorization,
                        params={"event_id": event["event_id"]},
                    )
                    assert risks.status_code == 200 and risks.json()["total"] == 1
                    risk = risks.json()["items"][0]
                    evidence["E_persisted_assessment"] = {
                        k: risk[k]
                        for k in (
                            "assessment_id",
                            "event_id",
                            "risk_score",
                            "severity",
                            "rule_version",
                            "model_version",
                        )
                    }
                    params = {
                        "service": "sentinel-demo-api",
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                    }
                    metrics = await client.get(
                        "/api/admin/analytics", headers=authorization, params=params
                    )
                    assert metrics.status_code == 200
                    async with resources.session_factory() as session:
                        conditions = [
                            SecurityEventRecord.service == "sentinel-demo-api",
                            SecurityEventRecord.occurred_at >= start,
                            SecurityEventRecord.occurred_at < end,
                        ]
                        requests = await session.scalar(
                            select(func.count())
                            .select_from(SecurityEventRecord)
                            .where(*conditions, SecurityEventRecord.schema_version == 1)
                        )
                        decisions = await session.scalar(
                            select(func.count())
                            .select_from(SecurityEventRecord)
                            .where(*conditions, SecurityEventRecord.schema_version == 2)
                        )
                    assert metrics.json()["monitored_requests"] == requests
                    assert metrics.json()["security_decisions"] == decisions
                    evidence["F_sql_matched_analytics"] = {
                        "monitored_requests": requests,
                        "security_decisions": decisions,
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                    }
                    policies = deepcopy(original["policies"])
                    target = next(p for p in policies if p["id"] == "demo-limited")
                    target["rate"] = {
                        "requests": 1,
                        "window_seconds": 2,
                        "exceed_action": "rate_limit",
                        "block_seconds": 2,
                    }
                    updated = await client.put(
                        "/api/admin/policies",
                        headers=authorization,
                        json={"expected_version": original["version"], "policies": policies},
                    )
                    assert updated.status_code == 200
                    changed = True
                    # This fingerprint has a distinct Redis counter from the baseline policy.
                    first = await demo.get("/api/demo/limited")
                    second = await demo.get("/api/demo/limited")
                    assert first.status_code == 200 and second.status_code == 429
                    evidence["G_live_enforcement"] = {
                        "version": updated.json()["version"],
                        "first_status": first.status_code,
                        "second_status": second.status_code,
                    }
                audits = await client.get(
                    "/api/admin/audit", headers=authorization, params={"actor_id": str(identifier)}
                )
                assert audits.status_code == 200
                evidence["H_audit_actions"] = sorted({r["action"] for r in audits.json()["items"]})
                assert "policy.update" in evidence["H_audit_actions"]
                # Restore policy before logging out; compare against the current committed revision.
                current = (await client.get("/api/admin/policies", headers=authorization)).json()
                restored = await client.put(
                    "/api/admin/policies",
                    headers=authorization,
                    json={"expected_version": current["version"], "policies": original["policies"]},
                )
                assert restored.status_code == 200
                changed = False
                logout = await client.post(
                    "/api/admin/auth/logout", headers={"X-CSRF-Token": authenticated["csrf_token"]}
                )
                assert logout.status_code == 204
                revoked = await client.get("/api/admin/events", headers=authorization)
                assert revoked.status_code == 401
                evidence["I_logout_and_revocation"] = {
                    "logout": logout.status_code,
                    "old_access_token": revoked.status_code,
                }
        finally:
            if changed and original and authorization:
                async with httpx.AsyncClient(
                    base_url=base_url, headers=headers, timeout=15
                ) as client:
                    current = (
                        await client.get("/api/admin/policies", headers=authorization)
                    ).json()
                    restore = await client.put(
                        "/api/admin/policies",
                        headers=authorization,
                        json={
                            "expected_version": current["version"],
                            "policies": original["policies"],
                        },
                    )
                    if restore.status_code != 200:
                        raise RuntimeError("Verification policy restoration failed")
            async with resources.session_factory() as session, session.begin():
                ids = select(AdminAccount.id).where(AdminAccount.username.like(username + "%"))
                families = select(AdminSession.id).where(AdminSession.account_id.in_(ids))
                await session.execute(
                    delete(RefreshToken).where(RefreshToken.session_id.in_(families))
                )
                await session.execute(delete(AdminSession).where(AdminSession.account_id.in_(ids)))
                await session.execute(delete(AdminAccount).where(AdminAccount.id.in_(ids)))
    print(json.dumps(evidence, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://admin-api:8000")
    parser.add_argument("--origin", default="http://localhost:5173")
    args = parser.parse_args()
    asyncio.run(verify(args.base_url, args.origin))


if __name__ == "__main__":
    main()
