"""Create private observability secrets without changing any existing platform credential."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def initialize(root=ROOT):
    directory = root / ".secrets" / "observability"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("metrics_token", "grafana_password", "rabbitmq_metrics_password"):
        path = directory / name
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if not path.read_text(encoding="utf-8").strip():
                raise ValueError("An observability secret is empty; repair it explicitly") from None
        else:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                output.write(secrets.token_hex(32) + "\n")
    directory.chmod(0o700)
    # The one-shot broker metrics bootstrap uses current local management credentials.
    values = {}
    for line in (root / ".env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"').strip("'")
    password = values.get("RABBITMQ_PASSWORD", "")
    if not password:
        raise ValueError("Initialize the existing platform .env before observability")
    path = directory / "rabbitmq_management_password"
    # Deliberately synchronize this copy if the platform credential was rotated.
    descriptor = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(password + "\n")
    # Plain Compose secrets bind existing inodes. The private 0700 parent protects host
    # access; readable files allow unprivileged container UIDs on Linux and Windows.
    for secret in directory.iterdir():
        if secret.is_file():
            # Docker entrypoint command substitution strips LF, but preserves Windows CR.
            # Normalize in place so existing bind mounts retain their original inode.
            value = secret.read_text(encoding="utf-8").strip()
            with secret.open("w", encoding="utf-8", newline="\n") as output:
                output.write(value + "\n")
            secret.chmod(0o644)
    print("Private observability files prepared; existing generated secrets preserved.")
    print("Grafana username: sentinel-ops; password file: .secrets/observability/grafana_password")


if __name__ == "__main__":
    initialize()
