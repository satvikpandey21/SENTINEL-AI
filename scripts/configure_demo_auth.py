"""Store only a salted hash for the development-only demo login; never print passwords."""

import argparse
import getpass
import importlib.util
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "apps/demo-api/src/sentinel_demo/credentials.py"
if source.exists():
    spec = importlib.util.spec_from_file_location("demo_credentials", source)
    credentials = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(credentials)
else:
    from sentinel_demo import credentials


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--initialize",
        action="store_true",
        help="Create a missing random hash without retaining its password",
    )
    arguments = parser.parse_args()
    path = ROOT / ".env"
    existing = path.read_text(encoding="utf-8")
    key = "SENTINEL_DEMO_PASSWORD_HASH"
    matches = [line for line in existing.splitlines() if line.startswith(key + "=")]
    if arguments.initialize and matches and matches[0].split("=", 1)[1].strip():
        print("Demo credential hash already exists; preserving it.")
        return
    password = (
        secrets.token_urlsafe(32)
        if arguments.initialize
        else getpass.getpass("New demo password (minimum 12 characters): ")
    )
    if len(password) < 12 or len(password) > 128:
        raise SystemExit("Demo password must contain 12-128 characters.")
    generated = key + "=" + credentials.hash_password(password)
    lines = [generated if line.startswith(key + "=") else line for line in existing.splitlines()]
    if not matches:
        lines.append(generated)
    if not any(line.startswith("SENTINEL_DEMO_USERNAME=") for line in lines):
        lines.append("SENTINEL_DEMO_USERNAME=sentinel-demo")
    temporary = ROOT / ".env.demo-auth.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write("\n".join(lines) + "\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    print("Stored a salted demo password hash. No raw password was stored or printed.")


if __name__ == "__main__":
    main()
