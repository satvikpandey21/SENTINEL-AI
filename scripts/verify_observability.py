# ruff: noqa: S101, ASYNC110 - bounded acceptance polls against the owned Compose stack
"""Verify private scraping, real metric changes, Grafana provisioning and every panel query."""

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx2 as httpx
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import delete, func, select
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from sentinel_api.auth import HASHER
from sentinel_api.models import AdminAccount, AdminSession, RefreshToken
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.storage import SecurityEventRecord


def samples(body):
    return [sample for family in text_string_to_metric_families(body) for sample in family.samples]


def total(body, name, **labels):
    return sum(
        s.value
        for s in samples(body)
        if s.name == "sentinel_" + name and all(s.labels.get(k) == v for k, v in labels.items())
    )


async def verify():
    token = (await asyncio.to_thread(Path("/run/secrets/metrics_token").read_text)).strip()
    password = (await asyncio.to_thread(Path("/run/secrets/grafana_password").read_text)).strip()
    auth = {"Authorization": "Bearer " + token}
    results = {}
    async with httpx.AsyncClient(timeout=15) as client:

        async def scrape(service):
            response = await client.get(f"http://{service}:9100/metrics", headers=auth)
            assert response.status_code == 200
            return response.text

        async def query(expr):
            response = await client.get(
                "http://prometheus:9090/api/v1/query", params={"query": expr}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success" and not data.get("warnings"), expr
            return data["data"]["result"]

        for service in ("admin-api", "demo-api", "event-worker"):
            url = f"http://{service}:9100/metrics"
            assert (await client.get(url)).status_code == 401
            assert (
                await client.get(url, headers={"Authorization": "Bearer wrong"})
            ).status_code == 401
            assert (
                await client.get(url, headers=[("Authorization", "Bearer " + token)] * 2)
            ).status_code == 401
            if service != "event-worker":
                assert (await client.get(f"http://{service}:8000/metrics")).status_code == 404
                assert (await client.get(f"http://{service}:8000/health/ready")).status_code == 200
        assert (await client.get("http://rabbitmq:15692/metrics")).status_code == 401
        results["private_access"] = (
            "App listeners and RabbitMQ reject unauthenticated scrapes; public APIs return 404"
        )

        before = await scrape("demo-api")
        worker_before = await scrape("event-worker")
        request_ids = []
        for _ in range(3):
            response = await client.get("http://demo-api:8000/api/demo/ping")
            assert response.status_code == 200
            request_ids.append(response.headers["X-Request-ID"])
        statuses = [
            (await client.get("http://demo-api:8000/api/demo/limited")).status_code
            for _ in range(12)
        ]
        assert 429 in statuses
        marker = "phase8-private-" + uuid4().hex
        await client.get(
            "http://demo-api:8000/" + marker,
            params={"password": marker},
            headers={"Cookie": "secret=" + marker},
        )
        after = await scrape("demo-api")
        for name in ("http_requests_total", "http_duration_seconds_count"):
            delta = total(after, name, route="/api/demo/ping") - total(
                before, name, route="/api/demo/ping"
            )
            assert delta == 3, (name, delta)
        action_deltas = {
            action: total(after, "security_actions_total", action=action)
            - total(before, "security_actions_total", action=action)
            for action in ("rate_limit", "temporary_block")
        }
        assert sum(action_deltas.values()) > 0
        assert total(after, "publisher_accepted_total") > total(before, "publisher_accepted_total")
        results["http"] = {
            "ping_counter_delta": 3,
            "ping_histogram_count_delta": 3,
            "rate_limited_responses": statuses.count(429),
            "security_action_deltas": action_deltas,
        }
        # Poll only in acceptance verification. The production scrape handler does no DB work.
        async with Resources(Settings()) as resources:
            async with asyncio.timeout(45):
                while True:
                    async with resources.session_factory() as session:
                        count = await session.scalar(
                            select(func.count())
                            .select_from(SecurityEventRecord)
                            .where(SecurityEventRecord.request_id.in_(request_ids))
                        )
                    worker_after = await scrape("event-worker")
                    if count == 3 and total(worker_after, "assessments_committed_total") > total(
                        worker_before, "assessments_committed_total"
                    ):
                        break
                    await asyncio.sleep(0.25)
            for name in (
                "worker_deliveries_total",
                "persistence_events_total",
                "analysis_operations_total",
                "analysis_duration_seconds_count",
            ):
                assert total(worker_after, name) > total(worker_before, name), name
            results["pipeline"] = {
                "owned_requests_committed": count,
                "worker_persistence_analysis_increased": True,
            }

            # An ephemeral account exercises the actual ticket and network upgrade, then is removed.
            account_id = uuid4()
            username, account_password = "verify8-" + uuid4().hex[:16], uuid4().hex + uuid4().hex
            async with resources.session_factory() as session, session.begin():
                session.add(
                    AdminAccount(
                        id=account_id,
                        username=username,
                        role="ANALYST",
                        active=True,
                        password_hash=HASHER.hash(account_password),
                        created_at=datetime.now(UTC),
                    )
                )
            try:
                ws_before = await scrape("admin-api")
                origin = "http://localhost:5173"
                headers = {"Origin": origin, "X-CSRF-Intent": "sentinel-admin"}
                login = await client.post(
                    "http://admin-api:8000/api/admin/auth/login",
                    headers=headers,
                    json={"username": username, "password": account_password},
                )
                assert login.status_code == 200
                bearer = login.json()["access_token"]
                ticket = await client.post(
                    "http://admin-api:8000/api/admin/ws/v1/ticket",
                    headers={**headers, "Authorization": "Bearer " + bearer},
                )
                assert ticket.status_code == 200
                ws_url = "ws://admin-api:8000/api/admin/ws/v1/security"
                async with connect(
                    ws_url,
                    origin=origin,
                    subprotocols=[
                        "sentinel.security.v1",
                        "sentinel.ticket." + ticket.json()["ticket"],
                    ],
                    compression=None,
                ) as socket:
                    assert json.loads(await socket.recv())["type"] == "connection.ready"
                    active = await scrape("admin-api")
                    assert total(active, "ws_active") == total(ws_before, "ws_active") + 1
                    response = await client.get("http://demo-api:8000/api/demo/ping")
                    async with asyncio.timeout(10):
                        while True:
                            frame = json.loads(await socket.recv())
                            if frame["type"].startswith("security."):
                                break
                    assert total(await scrape("admin-api"), "notification_sent_total") > total(
                        ws_before, "notification_sent_total"
                    )
                async with asyncio.timeout(5):
                    while total(await scrape("admin-api"), "ws_active") != total(
                        ws_before, "ws_active"
                    ):
                        await asyncio.sleep(0.05)
                try:
                    async with connect(ws_url, origin=origin):
                        raise AssertionError("unauthenticated upgrade accepted")
                except InvalidStatus as error:
                    assert error.response.status_code == 403
                ws_after = await scrape("admin-api")
                assert total(
                    ws_after, "ws_connections_total", outcome="rejected", reason="invalid_ticket"
                ) > total(
                    ws_before, "ws_connections_total", outcome="rejected", reason="invalid_ticket"
                )
                assert total(ws_after, "ws_lifetime_seconds_count") > total(
                    ws_before, "ws_lifetime_seconds_count"
                )
                results["websocket"] = (
                    "Active gauge +1 then baseline; delivery, rejection and lifetime measured"
                )
            finally:
                async with resources.session_factory() as session, session.begin():
                    sessions = select(AdminSession.id).where(AdminSession.account_id == account_id)
                    await session.execute(
                        delete(RefreshToken).where(RefreshToken.session_id.in_(sessions))
                    )
                    await session.execute(
                        delete(AdminSession).where(AdminSession.account_id == account_id)
                    )
                    await session.execute(delete(AdminAccount).where(AdminAccount.id == account_id))

        # Validate live labels and payloads, not only the source configuration.
        series_counts = {}
        for service in ("admin-api", "demo-api", "event-worker"):
            body = await scrape(service)
            observed = samples(body)
            assert len(observed) < 20000
            for secret in (
                token,
                password,
                marker,
                account_password,
                bearer,
                ticket.json()["ticket"],
                *request_ids,
            ):
                assert secret not in body
            assert all(
                set(s.labels).isdisjoint(
                    {"ip", "client_identifier", "account", "session", "event_id", "request_id"}
                )
                for s in observed
            )
            assert all(
                s.labels.get("route") == "unmatched" or marker not in s.labels.get("route", "")
                for s in observed
            )
            assert "/health/" not in body
            series_counts[service] = len(observed)
        results["privacy_sample_counts"] = series_counts

        async with asyncio.timeout(60):
            while True:
                targets = (await client.get("http://prometheus:9090/api/v1/targets")).json()[
                    "data"
                ]["activeTargets"]
                if len(targets) == 6 and all(t["health"] == "up" for t in targets):
                    break
                await asyncio.sleep(1)
        results["scrapes"] = [
            {"job": t["labels"]["job"], "instance": t["labels"]["instance"], "health": t["health"]}
            for t in targets
        ]
        expected_http = total(
            await scrape("demo-api"), "http_requests_total", route="/api/demo/ping"
        )
        async with asyncio.timeout(45):
            while True:
                observed_http = await query(
                    'sum(sentinel_http_requests_total{service="sentinel-demo-api",route="/api/demo/ping"})'
                )
                if observed_http and float(observed_http[0]["value"][1]) >= expected_http:
                    break
                await asyncio.sleep(1)
        results["prometheus_http_counter"] = float(observed_http[0]["value"][1])
        assert await query(
            'rabbitmq_detailed_queue_messages_ready{queue="sentinel.security.events.v1"}'
        )
        rules = (await client.get("http://prometheus:9090/api/v1/rules")).json()["data"]["groups"]
        assert sum(len(g["rules"]) for g in rules) == 9
        assert all(r["health"] == "ok" for g in rules for r in g["rules"])
        results["alert_rules"] = "9 loaded and evaluating without errors"

        grafana_auth = httpx.BasicAuth("sentinel-ops", password)
        assert (await client.get("http://grafana:3000/api/search")).status_code == 401
        health = await client.get(
            "http://grafana:3000/api/datasources/uid/sentinel-prometheus/health", auth=grafana_auth
        )
        assert health.status_code == 200 and health.json()["status"] == "OK"
        dashboards = (await client.get("http://grafana:3000/api/search", auth=grafana_auth)).json()
        dashboards = [d for d in dashboards if d["type"] == "dash-db"]
        assert len(dashboards) == 5
        queries = 0
        for dashboard in dashboards:
            provisioned = (
                await client.get(
                    "http://grafana:3000/api/dashboards/uid/" + dashboard["uid"], auth=grafana_auth
                )
            ).json()
            assert provisioned["meta"]["provisioned"]
            for panel in provisioned["dashboard"]["panels"]:
                for target in panel.get("targets", []):
                    await query(target["expr"])
                    queries += 1
        results["grafana"] = {
            "dashboards": [d["title"] for d in dashboards],
            "valid_panel_queries": queries,
            "datasource_health": "OK",
        }
    return results


if __name__ == "__main__":
    print(json.dumps(asyncio.run(verify()), indent=2))
