import pytest
from scripts import init_env

SECRET_KEYS = (
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
    "RABBITMQ_PASSWORD",
    "SENTINEL_CLIENT_IDENTITY_KEY",
)


def test_new_environment_has_distinct_random_secrets(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(init_env, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["init_env.py"])
    (tmp_path / ".env.example").write_text("\n".join(f"{key}=" for key in SECRET_KEYS) + "\n")
    init_env.main()
    values = dict(line.split("=", 1) for line in (tmp_path / ".env").read_text().splitlines())
    assert len(set(values.values())) == 4
    output = capsys.readouterr().out
    for value in values.values():
        assert len(value) == 64
        assert set(value) <= set("0123456789abcdef")
        assert value not in output


def test_new_environment_never_overwrites_existing_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(init_env, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["init_env.py"])
    (tmp_path / ".env.example").write_text("POSTGRES_PASSWORD=\n")
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=preserve-me\n")
    with pytest.raises(SystemExit):
        init_env.main()
    assert (tmp_path / ".env").read_text() == "POSTGRES_PASSWORD=preserve-me\n"


@pytest.mark.parametrize(
    "suffix",
    [
        "",
        "SENTINEL_CLIENT_IDENTITY_KEY=\n",
        "SENTINEL_CLIENT_IDENTITY_KEY=   \n",
        "SENTINEL_CLIENT_IDENTITY_KEY=",
    ],
)
def test_upgrade_preserves_service_credentials_and_handles_blank_key(tmp_path, monkeypatch, suffix):
    monkeypatch.setattr(init_env, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["init_env.py", "--add-monitoring-key"])
    existing = (
        "POSTGRES_PASSWORD=preserve-db\n"
        "REDIS_PASSWORD=preserve-redis\n"
        "RABBITMQ_PASSWORD=preserve-amqp\n"
    )
    (tmp_path / ".env").write_text(existing + suffix)
    init_env.main()
    updated = (tmp_path / ".env").read_text()
    assert updated.startswith(existing)
    values = dict(line.split("=", 1) for line in updated.splitlines())
    assert len(values["SENTINEL_CLIENT_IDENTITY_KEY"]) == 64
    assert not (tmp_path / ".env.monitoring.tmp").exists()


def test_existing_identity_key_is_stable_across_upgrades(tmp_path, monkeypatch):
    monkeypatch.setattr(init_env, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["init_env.py", "--add-monitoring-key"])
    existing = "SENTINEL_CLIENT_IDENTITY_KEY=" + "c" * 64 + "\n"
    (tmp_path / ".env").write_text(existing)
    init_env.main()
    assert (tmp_path / ".env").read_text() == existing


@pytest.mark.parametrize("existing", ["", "SENTINEL_ADMIN_SIGNING_KEY=\n"])
def test_admin_key_upgrade_is_independent_and_preserves_credentials(
    tmp_path, monkeypatch, existing
):
    monkeypatch.setattr(init_env, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["init_env.py", "--add-admin-key"])
    baseline = "POSTGRES_PASSWORD=preserved-db\nSENTINEL_CLIENT_IDENTITY_KEY=" + "a" * 64 + "\n"
    (tmp_path / ".env").write_text(baseline + existing)
    init_env.main()
    value = (tmp_path / ".env").read_text()
    assert value.startswith(baseline)
    settings = dict(line.split("=", 1) for line in value.splitlines())
    assert len(settings["SENTINEL_ADMIN_SIGNING_KEY"]) == 64
    assert settings["SENTINEL_ADMIN_SIGNING_KEY"] != settings["SENTINEL_CLIENT_IDENTITY_KEY"]
    init_env.main()
    assert (tmp_path / ".env").read_text() == value
    assert not (tmp_path / ".env.admin.tmp").exists()
