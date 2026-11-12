import asyncio
import threading
from unittest.mock import MagicMock

import httpx2 as httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from sentinel_demo.auth import DemoAuthSettings, install_login
from sentinel_demo.credentials import hash_password, verify_password
from sentinel_demo.main import create_app


@pytest.fixture(scope="module")
def credential_hash():
    return hash_password("unit-only-private-password")


def configured(encoded):
    return DemoAuthSettings(auth_enabled=True, username="test-demo", password_hash=encoded)


def test_salted_hash_and_constant_cost_verification(credential_hash):
    assert verify_password("unit-only-private-password", credential_hash)
    assert not verify_password("wrong-password", credential_hash)
    assert hash_password("unit-only-private-password") != credential_hash
    with pytest.raises(ValueError):
        verify_password("x", "bad-hash")


def test_success_and_verified_failure_are_explicit(monkeypatch, credential_hash):
    app = FastAPI()
    install_login(app, configured(credential_hash))
    outcome = MagicMock()
    monkeypatch.setattr("sentinel_demo.auth.record_verified_login", outcome)
    with TestClient(app) as client:
        assert client.post(
            "/api/demo/login",
            json={"username": "test-demo", "password": "unit-only-private-password"},
        ).json() == {"authenticated": True}
        assert outcome.call_args.kwargs["succeeded"] is True
        response = client.post(
            "/api/demo/login",
            json={"username": "wrong-user", "password": "unit-only-private-password"},
        )
        assert response.status_code == 401
        assert outcome.call_args.kwargs["succeeded"] is False
        assert "unit-only-private-password" not in response.text


@pytest.mark.parametrize(
    "body,headers,status",
    [
        (b"password=secret", {"content-type": "text/plain"}, 415),
        (b"x" * 2049, {"content-type": "application/json"}, 413),
        (b'{"password":"must-not-echo"}', {"content-type": "application/json"}, 422),
        (b'{"username":"test-demo","password":""}', {"content-type": "application/json"}, 422),
    ],
)
def test_invalid_login_input_is_bounded_redacted_and_not_counted(
    monkeypatch, credential_hash, body, headers, status
):
    app = FastAPI()
    install_login(app, configured(credential_hash))
    outcome = MagicMock()
    monkeypatch.setattr("sentinel_demo.auth.record_verified_login", outcome)
    with TestClient(app) as client:
        response = client.post("/api/demo/login", content=body, headers=headers)
    assert response.status_code == status
    assert "must-not-echo" not in response.text
    outcome.assert_not_called()


@pytest.mark.parametrize(
    "changes", [{"username": "bad username"}, {"password_hash": "bad"}, {"username": None}]
)
def test_authentication_settings_require_valid_hashes(credential_hash, changes):
    with pytest.raises(ValidationError):
        DemoAuthSettings(
            auth_enabled=True,
            username=changes.get("username", "test-demo"),
            password_hash=changes.get("password_hash", credential_hash),
        )


def test_demo_authentication_is_not_enabled_in_production(settings, credential_hash):
    with pytest.raises(ValueError):
        create_app(
            settings.model_copy(update={"environment": "production"}), configured(credential_hash)
        )


async def test_password_work_has_bounded_concurrency(monkeypatch, credential_hash):
    app = FastAPI()
    install_login(app, configured(credential_hash))
    release = threading.Event()
    started = []
    both_started = asyncio.Event()
    loop = asyncio.get_running_loop()

    def paused(*args):
        started.append(True)
        if len(started) == 2:
            loop.call_soon_threadsafe(both_started.set)
        release.wait(timeout=2)
        return True

    monkeypatch.setattr("sentinel_demo.auth.verify_password", paused)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        payload = {"username": "test-demo", "password": "unit-only-private-password"}
        first = [
            asyncio.create_task(client.post("/api/demo/login", json=payload)) for _ in range(2)
        ]
        try:
            await asyncio.wait_for(both_started.wait(), timeout=1)
            assert (await client.post("/api/demo/login", json=payload)).status_code == 503
        finally:
            release.set()
        assert all(response.status_code == 200 for response in await asyncio.gather(*first))
