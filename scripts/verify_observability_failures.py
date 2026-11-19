# ruff: noqa: S101 - controlled local availability acceptance
"""Stop only observability; prove application readiness, event commits and WebSocket delivery."""

import json

from verify_realtime_failures import compose, demo, persisted


def main():
    try:
        compose("stop", "grafana", "prometheus")
        rows = demo(count=3)
        assert all(row["status"] == 200 for row in rows)
        persisted(rows)
        realtime = compose(
            "--profile",
            "test",
            "run",
            "--rm",
            "--no-deps",
            "tests",
            "python",
            "scripts/verify_realtime.py",
        )
        readiness = compose(
            "exec",
            "-T",
            "admin-api",
            "python",
            "-c",
            "import urllib.request; "
            "print([urllib.request.urlopen('http://'+s+':8000/health/ready').status "
            "for s in ('admin-api','demo-api')])",
        )
        assert readiness == "[200, 200]"
        result = {
            "prometheus_grafana_stopped": True,
            "owned_requests_persisted": len(rows),
            "api_readiness": [200, 200],
            "websockets_without_observability": json.loads(realtime),
        }
    finally:
        compose("up", "-d", "--wait", "--wait-timeout", "180", "prometheus", "grafana")
    result["observability_recovered"] = True
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
