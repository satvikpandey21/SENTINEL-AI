"""Pure security boundary checks; integration tests exercise actual persistence."""

import secrets
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from sentinel_api.auth import HASHER, access_token, decode_access
from sentinel_api.schemas import EventFilter, Window
from sentinel_api.settings import AdminSettings
from sentinel_security.policies import default_policies
from sentinel_security.policy_runtime import POLICY_KEY, PolicyUnavailable, load_effective, snapshot
from sentinel_security.protection import SecurityEngine


@pytest.fixture
def admin_settings():
    return AdminSettings(signing_key=secrets.token_hex(32))


def test_password_hashes_are_salted_argon2id():
    password = secrets.token_urlsafe(24)
    first, second = HASHER.hash(password), HASHER.hash(password)
    assert first != second
    assert first.startswith("$argon2id$")
    assert HASHER.verify(first, password)


def test_access_token_and_required_claims(admin_settings):
    account, family = SimpleNamespace(id=uuid4()), SimpleNamespace(id=uuid4())
    token = access_token(admin_settings, account, family)
    claims = decode_access(admin_settings, token)
    assert claims["sub"] == str(account.id)
    assert claims["sid"] == str(family.id)
    assert claims["exp"] - claims["iat"] == 300
    assert "role" not in claims


@pytest.mark.parametrize(
    "change",
    [
        {"exp": 1},
        {"iss": "other"},
        {"aud": "other"},
        {"token_type": "refresh"},
        {"sub": "invalid"},
        {"sid": "invalid"},
        {"jti": "invalid"},
        {"iat": "1"},
        {"exp": int(datetime.now(UTC).timestamp()) + 3600},
        {"nbf": int(datetime.now(UTC).timestamp()) + 3600},
        {"aud": ["sentinel-dashboard", "other"]},
    ],
)
def test_modified_claims_rejected(admin_settings, change):
    token = access_token(admin_settings, SimpleNamespace(id=uuid4()), SimpleNamespace(id=uuid4()))
    key = bytes.fromhex(admin_settings.signing_key.get_secret_value())
    claims = jwt.decode(token, key, algorithms=["HS256"], audience=admin_settings.audience)
    claims.update(change)
    altered = jwt.encode(claims, key, algorithm="HS256", headers={"typ": "at+jwt"})
    with pytest.raises(HTTPException) as result:
        decode_access(admin_settings, altered)
    assert result.value.status_code == 401


@pytest.mark.parametrize(
    "removed", ["sub", "sid", "jti", "iat", "nbf", "exp", "iss", "aud", "token_type"]
)
def test_missing_claims_rejected(admin_settings, removed):
    key = bytes.fromhex(admin_settings.signing_key.get_secret_value())
    claims = decode_access(
        admin_settings,
        access_token(admin_settings, SimpleNamespace(id=uuid4()), SimpleNamespace(id=uuid4())),
    )
    del claims[removed]
    with pytest.raises(HTTPException):
        decode_access(
            admin_settings, jwt.encode(claims, key, algorithm="HS256", headers={"typ": "at+jwt"})
        )


@pytest.mark.parametrize(
    "algorithm,header", [("HS256", "JWT"), ("HS384", "at+jwt"), ("none", "at+jwt")]
)
def test_algorithm_header_and_bad_signature(admin_settings, algorithm, header):
    key = bytes.fromhex(admin_settings.signing_key.get_secret_value())
    claims = decode_access(
        admin_settings,
        access_token(admin_settings, SimpleNamespace(id=uuid4()), SimpleNamespace(id=uuid4())),
    )
    encoded = jwt.encode(
        claims,
        (secrets.token_bytes(48) if algorithm == "HS384" else key) if algorithm != "none" else "",
        algorithm=algorithm,
        headers={"typ": header},
    )
    with pytest.raises(HTTPException):
        decode_access(admin_settings, encoded)
    encoded = jwt.encode(
        claims, secrets.token_bytes(32), algorithm="HS256", headers={"typ": "at+jwt"}
    )
    with pytest.raises(HTTPException):
        decode_access(admin_settings, encoded)
    with pytest.raises(HTTPException):
        decode_access(admin_settings, "a" * 2049)


@pytest.mark.parametrize(
    "values",
    [
        {"signing_key": "short"},
        {"cookie_secure": False},
        {"allowed_origins": ["*"]},
        {"allowed_origins": ["http://dashboard.test"]},
        {"allowed_origins": ["https://dashboard.test/path"]},
        {"allowed_origins": []},
        {"access_seconds": 3600},
    ],
)
def test_unsafe_admin_config_rejected(values):
    defaults = {"signing_key": secrets.token_hex(32)}
    defaults.update(values)
    with pytest.raises(ValidationError):
        AdminSettings(**defaults)


def test_bounded_filters():
    now = datetime.now(UTC)
    for values in (
        {"start": now, "end": now},
        {"start": now - timedelta(days=32), "end": now},
        {"start": now.replace(tzinfo=None)},
        {"limit": 101},
        {"offset": 10001},
        {"endpoint": "/api?token=secret"},
        {"severity": "critical"},
        {"unexpected": "field"},
    ):
        with pytest.raises(ValidationError):
            EventFilter(**values)
    assert Window().end > Window().start


async def test_policy_unavailability_is_closed():
    async def unavailable():
        raise PolicyUnavailable

    engine = SecurityEngine(None, "test", default_policies(), policy_loader=unavailable)
    decision = await engine.before_request(
        {"state": {}, "path": "/api/demo/ping", "method": "GET"}, "a" * 64
    )
    assert decision.response_status == 503
    assert decision.degraded


@pytest.mark.parametrize(
    "value", [None, "{}", '{"updating":"fence"}', '{"version":1,"policies":[{}]}', "invalid"]
)
async def test_invalid_redis_policy_fails_closed(value):
    class Redis:
        async def get(self, key):
            assert key == POLICY_KEY
            return value

    with pytest.raises(PolicyUnavailable):
        await load_effective(Redis())


async def test_policy_runtime_roundtrip():
    policies = default_policies()

    class Redis:
        async def get(self, key):
            return snapshot(1, [p.model_dump(mode="json") for p in policies])

    assert await load_effective(Redis()) == policies
