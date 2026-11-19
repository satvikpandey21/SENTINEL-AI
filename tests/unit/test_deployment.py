"""Production environment and deployment boundary regressions without external services."""

import json
from copy import deepcopy

import pytest
from scripts import init_production
from scripts.deploy import validate


@pytest.mark.parametrize(
    "origin",
    [
        "http://demo.example.com",
        "https://user:secret@example.com",
        "https://example.com/path",
        "https://example.invalid",
        "https://localhost",
        "https://bad host.example",
    ],
)
def test_production_origin_rejects_unsafe_or_placeholder_values(origin, tmp_path, monkeypatch):
    monkeypatch.setattr(init_production, "ROOT", tmp_path)
    with pytest.raises(ValueError):
        init_production.initialize(origin)
    assert not (tmp_path / ".env.production").exists()


def test_production_initializer_is_private_independent_idempotent(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init_production, "ROOT", tmp_path)
    (tmp_path / ".env").write_text("existing-local-environment")
    path = init_production.initialize("https://sentinel.example.com")
    before = path.read_bytes()
    init_production.initialize("https://sentinel.example.com")
    assert path.read_bytes() == before
    assert (tmp_path / ".env").read_text() == "existing-local-environment"
    assert b"\r" not in before
    values = dict(line.split("=", 1) for line in before.decode().splitlines())
    assert (
        len(
            {
                values[k]
                for k in (
                    "POSTGRES_PASSWORD",
                    "REDIS_PASSWORD",
                    "RABBITMQ_PASSWORD",
                    "SENTINEL_ADMIN_SIGNING_KEY",
                    "SENTINEL_CLIENT_IDENTITY_KEY",
                )
            }
        )
        == 5
    )
    output = capsys.readouterr().out
    assert all(
        values[k] not in output
        for k in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "SENTINEL_ADMIN_SIGNING_KEY")
    )
    secrets = tmp_path / ".secrets/production"
    assert (secrets / "rabbitmq_management_password").read_text().strip() == values[
        "RABBITMQ_PASSWORD"
    ]


def test_partial_production_secrets_are_never_rotated(tmp_path, monkeypatch):
    monkeypatch.setattr(init_production, "ROOT", tmp_path)
    directory = tmp_path / ".secrets/production"
    directory.mkdir(parents=True)
    (directory / "metrics_token").write_text("preserved")
    with pytest.raises(ValueError, match="Partial"):
        init_production.initialize("https://sentinel.example.com")
    assert (directory / "metrics_token").read_text() == "preserved"
    assert not (tmp_path / ".env.production").exists()


@pytest.fixture
def deployment(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("private-test-value")
    services = {
        n: {}
        for n in (
            "admin-api",
            "demo-api",
            "event-worker",
            "postgres",
            "redis",
            "rabbitmq",
            "prometheus",
            "grafana",
        )
    }
    services["admin-api"]["environment"] = {
        "SENTINEL_ENVIRONMENT": "production",
        "SENTINEL_ADMIN_DEPLOYMENT": "production",
        "SENTINEL_ADMIN_COOKIE_SECURE": "true",
        "SENTINEL_ADMIN_ALLOWED_ORIGINS": json.dumps(["https://sentinel.example.com"]),
        "SENTINEL_TRUSTED_PROXY_CIDRS": '["172.30.90.2/32"]',
    }
    services["demo-api"]["environment"] = {"SENTINEL_DEMO_AUTH_ENABLED": "false"}
    services["ingress"] = {
        "user": "10001:10001",
        "read_only": True,
        "ports": [{"published": 80}, {"published": 443}],
    }
    return {
        "services": services,
        "networks": {"edge": {"internal": True}},
        "secrets": {"token": {"file": str(secret)}},
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "public_db",
        "insecure_cookie",
        "wildcard_origin",
        "untrusted_proxy",
        "root_ingress",
        "public_grafana",
        "demo_login",
    ],
)
def test_production_validator_rejects_security_regressions(deployment, mutation):
    config = deepcopy(deployment)
    services = config["services"]
    env = services["admin-api"]["environment"]
    if mutation == "public_db":
        services["postgres"]["ports"] = [{"published": 5432}]
    if mutation == "insecure_cookie":
        env["SENTINEL_ADMIN_COOKIE_SECURE"] = "false"
    if mutation == "wildcard_origin":
        env["SENTINEL_ADMIN_ALLOWED_ORIGINS"] = '["*"]'
    if mutation == "untrusted_proxy":
        env["SENTINEL_TRUSTED_PROXY_CIDRS"] = '["0.0.0.0/0"]'
    if mutation == "root_ingress":
        services["ingress"]["user"] = "0:0"
    if mutation == "public_grafana":
        services["grafana"]["ports"] = [
            {"host_ip": "0.0.0.0", "published": 3000}  # noqa: S104 - rejected configuration
        ]
    if mutation == "demo_login":
        services["demo-api"]["environment"]["SENTINEL_DEMO_AUTH_ENABLED"] = "true"
    with pytest.raises(ValueError):
        validate(config)


def test_production_validator_accepts_secure_topology(deployment):
    assert validate(deployment)["non_root_ingress"]
