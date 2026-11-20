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

    def run(*args, binary=False, input=None, timeout=240):
        return subprocess.check_output(
            [*base, *args],
            cwd=ROOT,
            text=not binary,
            stderr=subprocess.PIPE,
            input=input,
            timeout=timeout,
        )

    config = json.loads(run("config", "--format", "json"))
    report = validate(config, "local-test")
    output = ROOT / ".artifacts/day9-local-root.crt"
    output.parent.mkdir(parents=True, exist_ok=True)
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

    def event_probe(*args):
        try:
            return json.loads(
                run(
                    "exec",
                    "-T",
                    "admin-api",
                    "python",
                    "-",
                    *args,
                    input=(ROOT / "scripts/deployment_events.py").read_text(),
                    timeout=90,
                )
            )
        except subprocess.CalledProcessError as error:
            # The probe emits only identifiers/counts and sanitized database error types.
            raise RuntimeError(f"Deployment event probe failed: {error.stderr}") from None
        except subprocess.TimeoutExpired:
            raise RuntimeError("Deployment event probe exceeded its 90s process deadline") from None

    if faults:
        # Seed through the private demo API and wait for the worker's committed row before
        # interrupting any service. Each invocation receives a fresh server request ID.
        before = event_probe("seed")
        assert before["events"] > 0, "The generated demo event must be persisted before faults"
        sample = before["sample"]
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
        run("restart", "postgres", "redis", "rabbitmq", "event-worker", "admin-api")
        run("up", "-d", "--wait", "--wait-timeout", "180")
        after = event_probe(
            "check", "--request-id", sample["request_id"], "--event-id", sample["event_id"]
        )
        assert after["events"] >= before["events"], "Persisted event count fell after restart"
        assert after["first_event"] == before["first_event"], "Original first event lost on restart"
        assert after["sample"] == sample, "Generated event changed or disappeared after restart"
        report["persistent_restart"] = {
            "events_before": before["events"],
            "events_after": after["events"],
            "sample_preserved": True,
            "request_id": sample["request_id"],
            "event_id": sample["event_id"],
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
