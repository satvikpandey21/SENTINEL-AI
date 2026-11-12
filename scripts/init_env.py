"""Create a local .env with URL-safe random credentials; refuse to overwrite existing secrets."""

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "RABBITMQ_PASSWORD"):
        template = template.replace(f"{key}=\n", f"{key}={secrets.token_hex(32)}\n")
    try:
        descriptor = os.open(ROOT / ".env", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(template)
    except FileExistsError:
        raise SystemExit(".env already exists; refusing to overwrite credentials.") from None
    print("Created .env with random local credentials. Keep it private.")


if __name__ == "__main__":
    main()
