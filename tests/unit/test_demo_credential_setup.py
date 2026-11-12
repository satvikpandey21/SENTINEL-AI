import pytest
from scripts import configure_demo_auth


def setup(tmp_path, monkeypatch, arguments):
    monkeypatch.setattr(configure_demo_auth, "ROOT", tmp_path)
    monkeypatch.setattr("sys.argv", ["configure_demo_auth.py", *arguments])
    path = tmp_path / ".env"
    path.write_text("POSTGRES_PASSWORD=preserve-existing\nSENTINEL_DEMO_PASSWORD_HASH=\n")
    return path


def test_initialization_only_stores_a_hash_and_preserves_credentials(tmp_path, monkeypatch, capsys):
    path = setup(tmp_path, monkeypatch, ["--initialize"])
    configure_demo_auth.main()
    original = path.read_text()
    values = dict(line.split("=", 1) for line in original.splitlines())
    assert values["POSTGRES_PASSWORD"] == "preserve-existing"
    assert configure_demo_auth.credentials.PATTERN.fullmatch(values["SENTINEL_DEMO_PASSWORD_HASH"])
    configure_demo_auth.main()
    assert path.read_text() == original
    assert values["SENTINEL_DEMO_PASSWORD_HASH"] not in capsys.readouterr().out
    assert not (tmp_path / ".env.demo-auth.tmp").exists()


def test_interactive_configuration_never_persists_or_prints_plaintext(
    tmp_path, monkeypatch, capsys
):
    path = setup(tmp_path, monkeypatch, [])
    password = "private-password-for-test-only"
    monkeypatch.setattr(configure_demo_auth.getpass, "getpass", lambda _: password)
    configure_demo_auth.main()
    encoded = dict(line.split("=", 1) for line in path.read_text().splitlines())[
        "SENTINEL_DEMO_PASSWORD_HASH"
    ]
    assert configure_demo_auth.credentials.verify_password(password, encoded)
    assert password not in path.read_text()
    assert password not in capsys.readouterr().out


def test_short_password_is_rejected_without_changing_existing_file(tmp_path, monkeypatch):
    path = setup(tmp_path, monkeypatch, [])
    before = path.read_text()
    monkeypatch.setattr(configure_demo_auth.getpass, "getpass", lambda _: "short")
    with pytest.raises(SystemExit):
        configure_demo_auth.main()
    assert path.read_text() == before
