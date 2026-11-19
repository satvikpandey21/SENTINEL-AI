"""Generate an independent production environment; never overwrite a populated deployment."""

import argparse
import hashlib
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def initialize(origin, local_test=False):
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.hostname.endswith(".invalid")
    ):
        raise ValueError("Use an exact HTTPS origin with a real hostname and no path/credentials")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", parsed.hostname):
        raise ValueError("Use a valid DNS hostname")
    suffix = "production-test" if local_test else "production"
    if local_test and origin != "https://localhost:8443":
        raise ValueError("Local TLS acceptance uses https://localhost:8443")
    if not local_test and (parsed.hostname == "localhost" or parsed.port not in (None, 443)):
        raise ValueError("Public production requires a DNS hostname on standard HTTPS port 443")
    path = ROOT / (".env." + suffix)
    if path.exists():
        print("Existing deployment environment preserved; validate it before starting.")
        return path
    directory = ROOT / ".secrets" / suffix
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(directory.iterdir()):
        raise ValueError(
            "Partial deployment secrets exist; repair explicitly without rotating them"
        )
    values = {
        "SENTINEL_HOST": parsed.hostname,
        "SENTINEL_PUBLIC_ORIGIN": origin,
        "SENTINEL_ENVIRONMENT": "production",
        "SENTINEL_ADMIN_DEPLOYMENT": "production",
        "SENTINEL_ADMIN_COOKIE_SECURE": "true",
        "SENTINEL_DEMO_AUTH_ENABLED": "false",
        "SENTINEL_DEPLOYMENT_SECRETS_DIR": "./.secrets/" + suffix,
        "POSTGRES_USER": "sentinel",
        "POSTGRES_DB": "sentinel",
        "RABBITMQ_USER": "sentinel",
    }
    for name in (
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "RABBITMQ_PASSWORD",
        "SENTINEL_ADMIN_SIGNING_KEY",
        "SENTINEL_CLIENT_IDENTITY_KEY",
    ):
        values[name] = secrets.token_hex(32)
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(
        secrets.token_bytes(32), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=67108864
    )
    values["SENTINEL_DEMO_PASSWORD_HASH"] = "scrypt-v1:" + salt.hex() + ":" + hashed.hex()
    for name in (
        "metrics_token",
        "grafana_password",
        "rabbitmq_metrics_password",
        "rabbitmq_management_password",
    ):
        value = (
            values["RABBITMQ_PASSWORD"]
            if name == "rabbitmq_management_password"
            else secrets.token_hex(32)
        )
        secret = directory / name
        # Never replace a credential left by an interrupted initializer.
        descriptor = os.open(secret, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(value + "\n")
        secret.chmod(0o644)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write("".join(key + "=" + value + "\n" for key, value in values.items()))
    print("Independent deployment environment and secrets created; values not displayed.")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--local-test", action="store_true")
    args = parser.parse_args()
    initialize(args.origin, args.local_test)
