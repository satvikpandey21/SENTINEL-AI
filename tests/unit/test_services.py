from fastapi.testclient import TestClient

from sentinel_api.main import create_app as create_admin_app
from sentinel_demo.main import create_app as create_demo_app


def test_both_independently_packaged_services_start(settings, monkeypatch):
    for key in ("database_url", "redis_url", "rabbitmq_url"):
        monkeypatch.setenv(f"SENTINEL_{key.upper()}", getattr(settings, key).get_secret_value())
    monkeypatch.setenv("SENTINEL_ENVIRONMENT", "test")
    import secrets

    monkeypatch.setenv("SENTINEL_ADMIN_SIGNING_KEY", secrets.token_hex(32))
    monkeypatch.setenv("SENTINEL_DYNAMIC_POLICIES", "false")
    for factory, service in (
        (create_admin_app, "sentinel-admin-api"),
        (create_demo_app, "sentinel-demo-api"),
    ):
        with TestClient(factory()) as client:
            assert client.get("/health/live").json()["service"] == service
            if service == "sentinel-demo-api":
                assert client.get("/api/demo/ping").json() == {"message": "pong"}
            else:
                assert client.get("/api/demo/ping").status_code == 404
