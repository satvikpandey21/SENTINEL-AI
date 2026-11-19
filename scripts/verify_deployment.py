# ruff: noqa: S101 - owned local deployment acceptance only
"""Verify owned local TLS, proxy privacy, redacted failures and persistent restart."""

import argparse
import json
import os
import secrets
import ssl
import subprocess
import urllib.error
import urllib.request

from deploy import ROOT, command, validate


def main(faults=False):
    base = command(ROOT / ".env.production-test", "sentinel-production-test", "local-test")

    def run(*args, binary=False):
        return subprocess.check_output(
            [*base, *args], cwd=ROOT, text=not binary, stderr=subprocess.PIPE
        )

    config = json.loads(run("config", "--format", "json"))
    report = validate(config, "local-test")
    output = ROOT / ".artifacts/day9-local-root.crt"
    run("cp", "ingress:/data/caddy/pki/authorities/local/root.crt", str(output))
    context = ssl.create_default_context(cafile=str(output))

    def get(path, headers=None):
        request = urllib.request.Request("https://localhost:8443" + path, headers=headers or {})
        try:
            response = urllib.request.urlopen(request, context=context, timeout=15)  # noqa: S310 - fixed owned loopback
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers

    status, html, headers = get("/events")
    assert status == 200 and b'<div id="root">' in html
    assert "object-src 'none'" in headers["Content-Security-Policy"]
    assert get("/api/admin/events")[0] == 401
    for path in ("/metrics", "/api/admin/metrics", "/api/demo/ping", "/health/ready"):
        assert get(path)[0] == 404
    report["tls"] = "verified using the isolated Caddy CA; not publicly trusted HTTPS"
    report["spa_routing"] = True
    report["private_routes_denied"] = True
    config_env = dict(
        os.environ,
        SENTINEL_HOST="review.example.com",
        SENTINEL_PUBLIC_ORIGIN="https://review.example.com",
    )
    for mode in ("production", "tunnel"):
        args = command(ROOT / ".env.production-test", "sentinel-review", mode)
        resolved = json.loads(
            subprocess.check_output(
                [*args, "config", "--format", "json"], cwd=ROOT, env=config_env, text=True
            )
        )
        validate(resolved, mode)
    report["production_and_tunnel_config_valid"] = True
    archive = run("exec", "-T", "ingress", "tar", "-cf", "-", "/srv", binary=True)
    values = dict(
        line.split("=", 1)
        for line in (ROOT / ".env.production-test").read_text().splitlines()
        if "=" in line
    )
    candidates = [v for v in values.values() if len(v) >= 32]
    candidates += [p.read_text().strip() for p in (ROOT / ".secrets/production-test").iterdir()]
    assert all(value.encode() not in archive for value in candidates)
    report["compiled_assets_no_deployment_secrets"] = True
    # Production variants are parsed in an offline container, without requesting ACME certificates.
    for file in ("Caddyfile", "Caddyfile.tunnel"):
        run(
            "exec",
            "-T",
            "-e",
            "SENTINEL_HOST=review.example.com",
            "ingress",
            "caddy",
            "adapt",
            "--config",
            "/etc/caddy/" + file,
            "--adapter",
            "caddyfile",
        )
    report["proxy_configs_parse"] = True

    def snapshot():
        code = """import asyncio,json
from sqlalchemy import select,func
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.storage import SecurityEventRecord
async def main():
 async with Resources(Settings()) as r:
  async with r.session_factory() as s:
   rows=await s.scalar(select(func.count()).select_from(SecurityEventRecord))
   query=select(SecurityEventRecord.event_id).order_by(SecurityEventRecord.event_id).limit(1)
   first=await s.scalar(query)
   print(json.dumps({'events':rows,'first_event':str(first)}))
asyncio.run(main())"""
        return json.loads(run("exec", "-T", "admin-api", "python", "-c", code))

    if faults:
        marker = "phase9-canary-" + secrets.token_hex(12)
        try:
            run("stop", "admin-api")
            assert (
                get(
                    "/api/admin/ws/v1/security?private=" + marker,
                    {
                        "Authorization": "Bearer " + marker,
                        "Cookie": "private=" + marker,
                        "Sec-WebSocket-Protocol": "sentinel.ticket." + marker,
                    },
                )[0]
                == 502
            )
        finally:
            run("start", "admin-api")
            run("up", "-d", "--wait", "--wait-timeout", "180")
        assert marker not in run("logs", "--tail", "100", "ingress")
        report["failed_proxy_log_redaction"] = True
        before = snapshot()
        assert before["events"] > 0
        run("restart", "postgres", "redis", "rabbitmq", "event-worker", "admin-api")
        run("up", "-d", "--wait", "--wait-timeout", "180")
        after = snapshot()
        assert after["events"] >= before["events"] and after["first_event"] == before["first_event"]
        report["persistent_restart"] = {
            "events_before": before["events"],
            "events_after": after["events"],
            "sample_preserved": True,
        }
    report["public_deployment"] = False
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fault-check",
        action="store_true",
        help="Interrupt only the isolated production-test stack",
    )
    args = parser.parse_args()
    main(args.fault_check)
