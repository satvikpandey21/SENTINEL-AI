# ruff: noqa: S101 - controlled local Compose acceptance verification
"""Run sequentially after other tests. Restore every stopped service/Redis permission."""

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKER = shutil.which("docker")
if DOCKER is None:
    raise RuntimeError("Docker CLI is required")


def compose(*args, code=None):
    result = subprocess.run(
        [DOCKER, "compose", *args],
        cwd=ROOT,
        input=code,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def remote(code):
    return compose("exec", "-T", "admin-api", "python", "-", code=code)


BASE = """
import asyncio, json
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
"""


def publish_permission(allow):
    remote(
        BASE
        + """
async def main():
    async with Resources(Settings()) as r:
        await r.redis.execute_command('ACL','SETUSER','default',PERMISSION)
asyncio.run(main())
""".replace("PERMISSION", repr("+publish" if allow else "-publish"))
    )


def demo(path="/api/demo/ping", count=1):
    code = """
import json, urllib.request, urllib.error
rows=[]
for _ in range(COUNT):
    try:
        response=urllib.request.urlopen('http://demo-api:8000'+PATH, timeout=10)
    except urllib.error.HTTPError as error:
        response=error
    rows.append({'status':response.code,'request_id':response.headers['X-Request-ID']})
    response.close()
print(json.dumps(rows))
""".replace("COUNT", str(count)).replace("PATH", repr(path))
    return json.loads(remote(code))


def persisted(rows):
    ids = [row["request_id"] for row in rows]
    result = remote(
        BASE
        + """
from sqlalchemy import select, func
from sentinel_security.storage import SecurityEventRecord
async def main():
    async with Resources(Settings()) as r:
        for _ in range(150):
            async with r.session_factory() as s:
                count=await s.scalar(select(func.count()).select_from(SecurityEventRecord).where(
                    SecurityEventRecord.request_id.in_(IDS),
                    SecurityEventRecord.event_type=='http.request.completed'))
            if count==len(IDS):
                print(count)
                return
            await asyncio.sleep(.1)
        raise AssertionError('owned demo records did not reconcile')
asyncio.run(main())
""".replace("IDS", repr(ids))
    )
    assert int(result) == len(ids)


def main():
    results = {}
    stopped = set()
    try:
        # Deny ONLY the optional notification command: EVAL/GET/SET enforcement stays available.
        publish_permission(False)
        rows = demo("/api/demo/limited", 8)
        assert any(row["status"] == 429 for row in rows)
        persisted(rows)
        results["publish_denied"] = {"persisted_http_events": len(rows), "protection_429": True}
        publish_permission(True)
        # A total Redis outage invokes existing managed-policy fail-closed protection.
        compose("stop", "redis")
        stopped.add("redis")
        assert demo("/api/demo/login")[0]["status"] == 503
        results["redis_outage"] = "managed policy protection failed closed with 503"
        compose("start", "redis")
        stopped.remove("redis")
        compose("up", "-d", "--wait", "--wait-timeout", "180")
        persisted(demo())
        # A broker outage must not bypass available Redis restrictions.
        compose("stop", "rabbitmq")
        stopped.add("rabbitmq")
        rows = demo("/api/demo/limited", 8)
        assert any(row["status"] == 429 for row in rows)
        results["rabbitmq_outage"] = "Redis continued returning 429 restrictions"
        compose("start", "rabbitmq")
        stopped.remove("rabbitmq")
        compose("up", "-d", "--wait", "--wait-timeout", "180")
        persisted(demo())
        # Hold the worker while PostgreSQL is interrupted: confirmed broker data stays queued.
        compose("stop", "event-worker")
        stopped.add("event-worker")
        compose("stop", "postgres")
        stopped.add("postgres")
        rows = demo(count=5)
        assert all(row["status"] == 200 for row in rows)
        compose("start", "postgres")
        stopped.remove("postgres")
        compose("up", "-d", "--wait", "--wait-timeout", "180")
        stopped.discard("event-worker")
        persisted(rows)
        results["postgres_and_worker_restart"] = {"queued_requests_reconciled": len(rows)}
        results["final_recovery"] = "new owned requests persisted after each recovery"
        print(json.dumps(results, indent=2))
    finally:
        for service in stopped:
            compose("start", service)
        compose("up", "-d", "--wait", "--wait-timeout", "180")
        publish_permission(True)


if __name__ == "__main__":
    main()
