"""Run inside the demo container to verify real HTTP-to-database persistence without event APIs."""

import asyncio
import json
from time import monotonic
from urllib.request import Request, urlopen
from uuid import uuid4

from sqlalchemy import select

from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.storage import SecurityEventRecord


def request(marker: str) -> str:
    outgoing = Request(
        f"http://127.0.0.1:8000/api/demo/ping?password=query-{marker}",
        data=json.dumps({"password": f"body-{marker}"}).encode(),
        method="GET",
        headers={
            "Authorization": f"Bearer token-{marker}",
            "Cookie": f"session=cookie-{marker}",
            "X-Forwarded-For": "198.51.100.77",
        },
    )
    with urlopen(outgoing, timeout=5) as response:  # noqa: S310 - fixed owned localhost API
        if response.status != 200 or json.load(response) != {"message": "pong"}:
            raise RuntimeError("demo request failed")
        return response.headers["X-Request-ID"]


async def main() -> None:
    marker = uuid4().hex
    identifiers = [await asyncio.to_thread(request, marker) for _ in range(3)]
    async with Resources(Settings()) as resources:
        deadline = monotonic() + 15
        while monotonic() < deadline:
            async with resources.session_factory() as session:
                records = (
                    await session.scalars(
                        select(SecurityEventRecord).where(
                            SecurityEventRecord.request_id.in_(identifiers)
                        )
                    )
                ).all()
            if len(records) == len(identifiers):
                break
            await asyncio.sleep(0.1)
        else:
            raise RuntimeError("timed out waiting for event persistence")
        evidence = []
        for event in records:
            stored = {
                column.name: getattr(event, column.name) for column in event.__table__.columns
            }
            if marker in json.dumps(stored, default=str) or "198.51.100.77" in json.dumps(
                stored, default=str
            ):
                raise RuntimeError("sensitive verification sentinel was persisted")
            evidence.append(
                {
                    key: stored[key]
                    for key in (
                        "event_id",
                        "request_id",
                        "service",
                        "endpoint",
                        "status_code",
                        "duration_ms",
                        "occurred_at",
                        "ingested_at",
                        "schema_version",
                    )
                }
            )
        print(
            json.dumps(
                {
                    "verification": "passed",
                    "requests_sent": 3,
                    "persisted_count": len(records),
                    "sensitive_sentinels_persisted": False,
                    "events": evidence,
                },
                default=str,
                indent=2,
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
