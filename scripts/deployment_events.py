# ruff: noqa: ASYNC110 - bounded acceptance polling of the asynchronous event pipeline
"""Read-only database evidence for real traffic in the isolated deployment check.

Executed over stdin inside a production-test app container, on its private network.
Only the demo HTTP endpoint creates events; this probe never writes database rows.
"""

import argparse
import asyncio
import json
import re
import urllib.request
from uuid import UUID

from sqlalchemy import func, select

from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.storage import SecurityEventRecord


def demo_request():
    with urllib.request.urlopen("http://demo-api:8000/api/demo/ping", timeout=10) as response:
        if response.status != 200 or json.load(response) != {"message": "pong"}:
            raise RuntimeError("Deployment demo request did not return HTTP 200 pong")
        request_id = response.headers.get("X-Request-ID", "")
    if not re.fullmatch(r"[0-9a-f]{32}", request_id):
        raise RuntimeError("Deployment demo response is missing a valid server request ID")
    return request_id


async def snapshot(resources, request_id, event_id=None):
    async with resources.session_factory() as session:
        query = select(SecurityEventRecord).where(
            SecurityEventRecord.request_id == request_id,
            SecurityEventRecord.event_type == "http.request.completed",
        )
        if event_id is not None:
            query = query.where(SecurityEventRecord.event_id == UUID(event_id))
        event = (await session.scalars(query)).one_or_none()
        sample = None
        if event is not None:
            sample = {
                name: getattr(event, name)
                for name in (
                    "request_id",
                    "service",
                    "method",
                    "endpoint",
                    "status_code",
                    "response_completed",
                )
            }
            sample["event_id"] = str(event.event_id)
        # Read totals after the sample: under READ COMMITTED the worker may commit
        # between statements. Seeing the sample must never return an earlier zero count.
        count = await session.scalar(select(func.count()).select_from(SecurityEventRecord))
        first = await session.scalar(
            select(SecurityEventRecord.event_id).order_by(SecurityEventRecord.event_id).limit(1)
        )
        return {
            "events": count,
            "first_event": str(first) if first is not None else None,
            "sample": sample,
        }


async def wait_for_event(
    resources, request_id, event_id=None, *, deadline_seconds=60, interval=0.25
):
    last, error_type = None, None
    try:
        async with asyncio.timeout(deadline_seconds):
            while True:
                try:
                    last = await snapshot(resources, request_id, event_id)
                    error_type = None
                except Exception as error:
                    # Database errors can include credentials; report only the exception type.
                    error_type = type(error).__name__
                else:
                    if last["sample"] is not None:
                        expected = {
                            "request_id": request_id,
                            "service": "sentinel-demo-api",
                            "method": "GET",
                            "endpoint": "/api/demo/ping",
                            "status_code": 200,
                            "response_completed": True,
                        }
                        sample = last["sample"]
                        if any(sample[key] != value for key, value in expected.items()):
                            raise RuntimeError(f"Unexpected persisted demo event: {sample}")
                        if event_id is not None and sample["event_id"] != event_id:
                            raise RuntimeError(f"Persisted event identifier changed: {sample}")
                        return last
                await asyncio.sleep(interval)
    except TimeoutError:
        raise TimeoutError(
            f"Timed out after {deadline_seconds}s waiting for PostgreSQL demo event "
            f"request_id={request_id}, event_id={event_id}; "
            f"last_snapshot={last}, last_error_type={error_type}. "
            "Inspect the production-test demo-api publisher, RabbitMQ, event-worker and "
            "PostgreSQL health/logs; the RabbitMQ -> worker -> PostgreSQL pipeline "
            "must commit this exact request before restart and preserve it afterwards."
        ) from None


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("seed", "check"))
    parser.add_argument("--request-id")
    parser.add_argument("--event-id")
    args = parser.parse_args()
    if args.operation == "seed":
        request_id = await asyncio.to_thread(demo_request)
    else:
        if not args.request_id or not args.event_id:
            parser.error("check requires the recorded --request-id and --event-id")
        request_id = args.request_id
    async with Resources(Settings()) as resources:
        result = await wait_for_event(resources, request_id, args.event_id)
    print(json.dumps(result))


if __name__ == "__main__":
    asyncio.run(main())
