# ruff: noqa: S310
# Network targets are fixed to the two names of our own demonstration API.
"""Companion executed via stdin by verify_protection.py, never saved with credentials."""

import asyncio
import json
import urllib.error
import urllib.request
from time import monotonic

from sqlalchemy import select

from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.storage import SecurityEventRecord


def request(path, *, body=None, alternate=False):
    base = "http://demo-api:8000" if alternate else "http://127.0.0.1:8000"
    outgoing = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-Forwarded-For": "198.51.100.250"},
    )
    try:
        response = urllib.request.urlopen(outgoing, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return (response.status, response.headers, json.load(response))


async def persisted(resources, identifier, *, rule=None):
    deadline = monotonic() + 15
    while monotonic() < deadline:
        async with resources.session_factory() as session:
            query = select(SecurityEventRecord).where(SecurityEventRecord.request_id == identifier)
            query = (
                query.where(SecurityEventRecord.rule_id == rule)
                if rule
                else query.where(SecurityEventRecord.schema_version == 1)
            )
            record = await session.scalar(query)
        if record:
            return record
        await asyncio.sleep(0.05)
    raise RuntimeError("Expected protection event was not persisted")


def evidence(event):
    return {
        key: getattr(event, key)
        for key in (
            "event_id",
            "request_id",
            "schema_version",
            "rule_id",
            "security_action",
            "threshold",
            "counter_value",
            "restriction_expires_at",
        )
    }


async def main(configuration):

    def call(*args, **kwargs):
        return asyncio.to_thread(request, *args, **kwargs)

    normal = [await call("/api/demo/limited") for _ in range(3)]
    if not [result[0] for result in normal] == [200, 200, 200]:
        raise RuntimeError("Protection verification check failed")
    restricted = await call("/api/demo/limited")
    if not restricted[0] == 429:
        raise RuntimeError("Protection verification check failed")
    retry = int(restricted[1]["Retry-After"])
    if not 1 <= retry <= 2:
        raise RuntimeError("Protection verification check failed")
    if not (await call("/api/demo/limited"))[0] == 429:
        raise RuntimeError("Protection verification check failed")
    unrelated = await call("/api/demo/limited", alternate=True)
    if not unrelated[0] == 200:
        raise RuntimeError("Protection verification check failed")
    await asyncio.sleep(retry + 0.1)
    if not (await call("/api/demo/limited"))[0] == 200:
        raise RuntimeError("Protection verification check failed")
    good = {"username": configuration["username"], "password": configuration["password"]}
    bad = {**good, "password": "invalid-" + configuration["password"]}
    if not (await call("/api/demo/login", body=good))[0] == 200:
        raise RuntimeError("Protection verification check failed")
    failures = [await call("/api/demo/login", body=bad) for _ in range(3)]
    if not [result[0] for result in failures] == [401, 401, 401]:
        raise RuntimeError("Protection verification check failed")
    login_block = await call("/api/demo/login", body=good)
    if not login_block[0] == 429:
        raise RuntimeError("Protection verification check failed")
    if not (await call("/api/demo/login", body=good, alternate=True))[0] == 200:
        raise RuntimeError("Protection verification check failed")
    await asyncio.sleep(int(login_block[1]["Retry-After"]) + 0.1)
    if not (await call("/api/demo/login", body=good))[0] == 200:
        raise RuntimeError("Protection verification check failed")
    async with Resources(Settings()) as resources:
        rate_event = await persisted(
            resources, restricted[1]["X-Request-ID"], rule=configuration["rate_rule"]
        )
        login_event = await persisted(
            resources, failures[-1][1]["X-Request-ID"], rule=configuration["login_rule"]
        )
        unrelated_event = await persisted(resources, unrelated[1]["X-Request-ID"])
        if not rate_event.client_identifier != unrelated_event.client_identifier:
            raise RuntimeError("Protection verification check failed")
        for event in (rate_event, login_event):
            if not event.security_action == "temporary_block":
                raise RuntimeError("Protection verification check failed")
            if not event.restriction_expires_at is not None:
                raise RuntimeError("Protection verification check failed")
            stored = json.dumps(
                {column.name: getattr(event, column.name) for column in event.__table__.columns},
                default=str,
            )
            if not configuration["password"] not in stored:
                raise RuntimeError("Protection verification check failed")
            if not configuration["username"] not in stored:
                raise RuntimeError("Protection verification check failed")
            if not "198.51.100.250" not in stored:
                raise RuntimeError("Protection verification check failed")
        print(
            json.dumps(
                {
                    "verification": "passed",
                    "rate_limit": {
                        "accepted_statuses": [200, 200, 200],
                        "restricted_status": 429,
                        "retry_after_seconds": retry,
                        "recovered_status": 200,
                        "unrelated_client_status": 200,
                        "client_identities_distinct": True,
                        "event": evidence(rate_event),
                    },
                    "brute_force": {
                        "initial_success_status": 200,
                        "failed_attempt_statuses": [401, 401, 401],
                        "restricted_status": 429,
                        "recovered_status": 200,
                        "unrelated_client_status": 200,
                        "event": evidence(login_event),
                    },
                    "sensitive_sentinels_persisted": False,
                },
                default=str,
                indent=2,
            )
        )


if __name__ == "__main__":
    if "CONFIG" not in globals():
        raise SystemExit("Run scripts/verify_protection.py from the host")
    asyncio.run(main(globals()["CONFIG"]))
