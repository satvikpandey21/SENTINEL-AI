"""Idempotently provision a read-only native metrics identity via RabbitMQ management."""

import base64
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


def main():
    password = Path("/run/secrets/rabbitmq_management_password").read_text().strip()
    metrics_password = Path("/run/secrets/rabbitmq_metrics_password").read_text().strip()
    username = os.environ.get("RABBITMQ_USER", "sentinel")
    authorization = base64.b64encode(f"{username}:{password}".encode()).decode()
    body = json.dumps({"password": metrics_password, "tags": "monitoring"}).encode()
    # No vhost permissions are granted: the identity cannot publish or consume AMQP messages.
    for attempt in range(20):
        request = urllib.request.Request(
            "http://rabbitmq:15672/api/users/sentinel-metrics",
            data=body,
            method="PUT",
            headers={"Authorization": "Basic " + authorization, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - fixed internal URL
                if response.status not in (201, 204):
                    raise RuntimeError("Metrics identity provisioning failed")
            print("RabbitMQ monitoring identity provisioned without AMQP permissions.")
            return
        except (urllib.error.URLError, TimeoutError):
            if attempt == 19:
                raise RuntimeError("RabbitMQ metrics provisioning unavailable") from None
            time.sleep(1)


if __name__ == "__main__":
    main()
