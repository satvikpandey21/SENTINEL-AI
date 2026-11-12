"""Container health from a worker-maintained heartbeat, without exposing an HTTP API."""

import json
from pathlib import Path
from time import time

HEARTBEAT_PATH = Path("/tmp/sentinel-worker-health.json")  # noqa: S108


def write_health(ready: bool) -> None:
    temporary = HEARTBEAT_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps({"ready": ready, "checked_at": time()}), encoding="utf-8")
    temporary.replace(HEARTBEAT_PATH)


def is_healthy() -> bool:
    try:
        state = json.loads(HEARTBEAT_PATH.read_text(encoding="utf-8"))
        return state["ready"] is True and 0 <= time() - state["checked_at"] <= 20
    except (OSError, ValueError, KeyError, TypeError):
        return False


if __name__ == "__main__":
    raise SystemExit(0 if is_healthy() else 1)
