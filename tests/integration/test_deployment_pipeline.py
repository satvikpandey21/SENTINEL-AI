"""Deployment probe regression using real private HTTP, RabbitMQ, worker and database."""

import asyncio
import os
from uuid import uuid4

import pytest
from scripts.deployment_events import demo_request, snapshot, wait_for_event

from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("SENTINEL_RUN_INTEGRATION") != "1", reason="Run via Compose test profile"
    ),
]


async def test_probe_tracks_new_real_events_on_repeated_runs_and_rejects_unrelated_rows():
    async with Resources(Settings()) as resources:
        absent_id = uuid4().hex
        assert (await snapshot(resources, absent_id))["sample"] is None
        identifiers = []
        for _ in range(2):
            request_id = await asyncio.to_thread(demo_request)
            before = await wait_for_event(resources, request_id)
            sample = before["sample"]
            assert before["events"] > 0
            assert sample["request_id"] == request_id
            after = await wait_for_event(resources, request_id, sample["event_id"])
            assert after["sample"] == sample
            assert (await snapshot(resources, absent_id, sample["event_id"]))["sample"] is None
            identifiers.append(sample["event_id"])
        assert identifiers[0] != identifiers[1]
        with pytest.raises(TimeoutError, match=absent_id):
            await wait_for_event(resources, absent_id, deadline_seconds=0.1, interval=0.01)
