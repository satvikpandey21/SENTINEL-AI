"""Real private listeners, broker observations, worker, WebSockets and provisioned Grafana."""

import os

import pytest
from scripts.verify_observability import verify

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run via Compose test profile"
    ),
]


async def test_live_observability_stack():
    result = await verify()
    assert len(result["scrapes"]) == 6
    assert result["grafana"]["valid_panel_queries"] >= 40
