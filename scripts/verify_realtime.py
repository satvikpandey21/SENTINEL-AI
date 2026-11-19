# ruff: noqa: S101 - controlled acceptance checks against the owned Compose demo
"""Real worker -> commit -> Redis -> authenticated network WebSockets acceptance/latency."""

import argparse
import asyncio
import json
import secrets
from datetime import UTC, datetime
from statistics import median
from time import monotonic
from uuid import uuid4

import httpx2 as httpx
from sqlalchemy import delete, func, select
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from sentinel_api.auth import HASHER
from sentinel_api.models import AdminAccount, AdminSession, RefreshToken
from sentinel_security.analysis_storage import RiskAssessment
from sentinel_security.config import Settings
from sentinel_security.events import parse_event
from sentinel_security.infrastructure import Resources
from sentinel_security.messaging import EVENT_QUEUE, event_message
from sentinel_security.storage import SecurityEventRecord


async def run(base, origin):
    prefix, password = "verify7-" + uuid4().hex[:16], secrets.token_urlsafe(24)
    results = {}
    headers = {"Origin": origin, "X-CSRF-Intent": "sentinel-admin"}
    async with Resources(Settings()) as resources:
        async with resources.session_factory() as session, session.begin():
            for suffix, role in (("", "ADMIN"), ("-analyst", "ANALYST")):
                session.add(
                    AdminAccount(
                        id=uuid4(),
                        username=prefix + suffix,
                        role=role,
                        active=True,
                        password_hash=HASHER.hash(password),
                        created_at=datetime.now(UTC),
                    )
                )
        sockets, receivers = [], []
        try:
            async with httpx.AsyncClient(base_url=base, headers=headers, timeout=15) as client:
                tokens = []
                for suffix in ("", "-analyst"):
                    result = await client.post(
                        "/api/admin/auth/login",
                        json={"username": prefix + suffix, "password": password},
                    )
                    assert result.status_code == 200
                    tokens.append(result.json()["access_token"])
                ws_url = (
                    base.replace("http://", "ws://").replace("https://", "wss://")
                    + "/api/admin/ws/v1/security"
                )
                try:
                    async with connect(ws_url, origin=origin):
                        raise AssertionError("unauthenticated upgrade accepted")
                except InvalidStatus as error:
                    assert error.response.status_code == 403
                    results["unauthenticated_rejected"] = True

                async def open_socket(token):
                    result = await client.post(
                        "/api/admin/ws/v1/ticket", headers={"Authorization": "Bearer " + token}
                    )
                    assert result.status_code == 200
                    socket = await connect(
                        ws_url,
                        origin=origin,
                        subprotocols=[
                            "sentinel.security.v1",
                            "sentinel.ticket." + result.json()["ticket"],
                        ],
                        max_size=4096,
                        compression=None,
                    )
                    assert socket.subprotocol == "sentinel.security.v1"
                    assert json.loads(await socket.recv())["type"] == "connection.ready"
                    return socket

                for token in (tokens[0], tokens[0], tokens[1]):
                    sockets.append(await open_socket(token))
                frames = [[] for _ in sockets]
                latencies = []
                arrivals = {}

                async def collect(socket, output):
                    async for raw in socket:
                        frame = json.loads(raw)
                        if frame["type"] == "connection.heartbeat":
                            await socket.send('{"type":"connection.pong"}')
                        elif frame["type"].startswith("security."):
                            output.append(frame)
                            arrivals.setdefault(frame["event_id"], []).append(monotonic())
                            latencies.append(
                                (
                                    datetime.now(UTC)
                                    - datetime.fromisoformat(frame["committed_at"])
                                ).total_seconds()
                                * 1000
                            )

                receivers = [
                    asyncio.create_task(collect(s, f)) for s, f in zip(sockets, frames, strict=True)
                ]
                started = monotonic()
                request_ids = []
                async with httpx.AsyncClient(base_url="http://demo-api:8000", timeout=10) as demo:
                    for _ in range(5):
                        response = await demo.post(
                            "/api/demo/login",
                            json={
                                "username": "verification-invalid",
                                "password": "verification-invalid",
                            },
                        )
                        request_ids.append(response.headers["x-request-id"])
                    for _ in range(8):
                        response = await demo.get("/api/demo/limited")
                        request_ids.append(response.headers["x-request-id"])
                    for _ in range(30):
                        response = await demo.get("/api/demo/ping?privacy_probe=must-not-stream")
                        request_ids.append(response.headers["x-request-id"])
                async with asyncio.timeout(30):
                    while True:  # noqa: ASYNC110 - bounded real-worker drain
                        async with resources.session_factory() as session:
                            count = await session.scalar(
                                select(func.count())
                                .select_from(SecurityEventRecord)
                                .where(
                                    SecurityEventRecord.request_id.in_(request_ids),
                                    SecurityEventRecord.event_type == "http.request.completed",
                                )
                            )
                        if count == len(request_ids) and any(
                            f["severity"] in ("high", "critical") for f in frames[0]
                        ):
                            break
                        await asyncio.sleep(0.1)
                await asyncio.sleep(0.3)
                first_ids = {f["event_id"] for f in frames[0]}
                assert first_ids and all(
                    {f["event_id"] for f in rows} == first_ids for rows in frames
                )
                assert any(f["type"] == "security.decision.created" for f in frames[0])
                assert any(f["security_action"] == "temporary_block" for f in frames[0])
                assert any(f["severity"] in ("high", "critical") for f in frames[0])
                authorization = {"Authorization": "Bearer " + tokens[0]}
                sample = frames[0][-1]
                assert (
                    await client.get(
                        "/api/admin/events/" + sample["event_id"], headers=authorization
                    )
                ).status_code == 200
                serialized = json.dumps(frames)
                for sensitive in (password, *tokens, "must-not-stream", "verification-invalid"):
                    assert sensitive not in serialized
                # Republish the actual persisted event, preserving its event UUID.
                async with resources.session_factory() as session:
                    record = await session.get(SecurityEventRecord, sample["event_id"])
                    body = {
                        column.name: getattr(record, column.name)
                        for column in record.__table__.columns
                        if column.name != "ingested_at" and getattr(record, column.name) is not None
                    }
                    original = parse_event(
                        json.dumps(body, default=str).encode(), Settings().event_max_bytes
                    )
                    before = await session.scalar(
                        select(func.count())
                        .select_from(RiskAssessment)
                        .where(RiskAssessment.event_id == original.event_id)
                    )
                import aio_pika

                from sentinel_security.messaging import declare_topology

                connection = await aio_pika.connect(Settings().rabbitmq_url.get_secret_value())
                try:
                    channel = await connection.channel(publisher_confirms=True)
                    await declare_topology(channel, Settings())
                    await channel.default_exchange.publish(
                        event_message(original.model_dump_json().encode()),
                        routing_key=EVENT_QUEUE,
                        mandatory=True,
                    )
                    await asyncio.sleep(0.5)
                finally:
                    await connection.close()
                assert sum(f["event_id"] == sample["event_id"] for f in frames[0]) == 1
                async with resources.session_factory() as session:
                    after = await session.scalar(
                        select(func.count())
                        .select_from(RiskAssessment)
                        .where(RiskAssessment.event_id == original.event_id)
                    )
                assert before == after == 1
                # Fresh-ticket reconnect plus authoritative REST reconciliation.
                recovery = monotonic()
                resumed = await open_socket(tokens[0])
                await resumed.close()
                assert (
                    await client.get(
                        "/api/admin/events/" + sample["event_id"], headers=authorization
                    )
                ).status_code == 200
                results.update(
                    {
                        "clients": 3,
                        "roles": ["ADMIN", "ANALYST"],
                        "controlled_requests": len(request_ids),
                        "unique_notifications": len(first_ids),
                        "high_or_critical": sum(
                            f["severity"] in ("high", "critical") for f in frames[0]
                        ),
                        "duplicate_broker_delivery_suppressed": True,
                        "privacy_checks": True,
                        "duration_seconds": round(monotonic() - started, 3),
                        "post_commit_to_receipt_ms": {
                            "samples": len(latencies),
                            "median": round(median(latencies), 3),
                            "max": round(max(latencies), 3),
                            "min": round(min(latencies), 3),
                        },
                        "fanout_receipt_spread_ms": {
                            "samples": len(arrivals),
                            "median": round(
                                median((max(v) - min(v)) * 1000 for v in arrivals.values()), 3
                            ),
                            "max": round(
                                max((max(v) - min(v)) * 1000 for v in arrivals.values()), 3
                            ),
                        },
                        "ticket_reconnect_and_rest_ms": round((monotonic() - recovery) * 1000, 3),
                    }
                )
                # The cookie belongs to the analyst login (the final login above).
                csrf = (await client.post("/api/admin/auth/csrf")).json()["csrf_token"]
                assert (
                    await client.post("/api/admin/auth/logout", headers={"X-CSRF-Token": csrf})
                ).status_code == 204
                async with asyncio.timeout(22):
                    await sockets[2].wait_closed()
                assert sockets[2].close_code == 4401
                results["server_logout_close_code"] = sockets[2].close_code
        finally:
            for task in receivers:
                task.cancel()
            await asyncio.gather(*receivers, return_exceptions=True)
            await asyncio.gather(*(s.close() for s in sockets), return_exceptions=True)
            async with resources.session_factory() as session, session.begin():
                ids = select(AdminAccount.id).where(
                    AdminAccount.username.in_([prefix, prefix + "-analyst"])
                )
                families = select(AdminSession.id).where(AdminSession.account_id.in_(ids))
                await session.execute(
                    delete(RefreshToken).where(RefreshToken.session_id.in_(families))
                )
                await session.execute(delete(AdminSession).where(AdminSession.account_id.in_(ids)))
                await session.execute(delete(AdminAccount).where(AdminAccount.id.in_(ids)))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://admin-api:8000")
    parser.add_argument("--origin", default="http://localhost:5173")
    args = parser.parse_args()
    asyncio.run(run(args.base, args.origin))
