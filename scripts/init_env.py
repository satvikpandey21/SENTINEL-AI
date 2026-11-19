"""Create a local .env with URL-safe random credentials; refuse to overwrite existing secrets."""

import argparse
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--add-monitoring-key",
        action="store_true",
        help="Add only a missing monitoring key to an existing Day 1 .env",
    )
    parser.add_argument(
        "--add-admin-key",
        action="store_true",
        help="Add a missing independent administrative signing key",
    )
    arguments = parser.parse_args()
    if arguments.add_admin_key:
        path = ROOT / ".env"
        existing = path.read_text(encoding="utf-8")
        key = "SENTINEL_ADMIN_SIGNING_KEY"
        lines = existing.splitlines()
        if any(line.startswith(key + "=") and line.split("=", 1)[1].strip() for line in lines):
            print("Administrative signing key exists; preserving it.")
            return
        generated = key + "=" + secrets.token_hex(32)
        found = any(line.startswith(key + "=") for line in lines)
        lines = [generated if line.startswith(key + "=") else line for line in lines]
        if not found:
            lines.append(generated)
        temporary = ROOT / ".env.admin.tmp"
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                output.write("\n".join(lines) + "\n")
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        print("Added administrative signing key; existing credentials preserved.")
        return
    if arguments.add_monitoring_key:
        path = ROOT / ".env"
        existing = path.read_text(encoding="utf-8")
        key = "SENTINEL_CLIENT_IDENTITY_KEY"
        matching = [line for line in existing.splitlines() if line.startswith(key + "=")]
        if matching and matching[0].split("=", 1)[1].strip():
            print("Monitoring key already exists; preserving it.")
            return
        generated = f"{key}={secrets.token_hex(32)}"
        if matching:
            updated = (
                "\n".join(
                    generated if line.startswith(key + "=") else line
                    for line in existing.splitlines()
                )
                + "\n"
            )
        else:
            updated = existing.rstrip() + "\n" + generated + "\n"
        temporary = ROOT / ".env.monitoring.tmp"
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                output.write(updated)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
        print("Added monitoring key; existing service credentials were preserved.")
        return
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    for key in (
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "RABBITMQ_PASSWORD",
        "SENTINEL_CLIENT_IDENTITY_KEY",
        "SENTINEL_ADMIN_SIGNING_KEY",
    ):
        template = template.replace(f"{key}=\n", f"{key}={secrets.token_hex(32)}\n")
    try:
        descriptor = os.open(ROOT / ".env", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(template)
    except FileExistsError:
        raise SystemExit(".env already exists; refusing to overwrite credentials.") from None
    try:
        from scripts.init_observability import initialize
    except ModuleNotFoundError:
        from init_observability import initialize
    initialize(ROOT)
    print("Created .env with random local credentials. Keep it private.")


if __name__ == "__main__":
    main()
