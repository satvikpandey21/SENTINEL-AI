"""Verify the real demo service with temporary hash-only settings; restore it in finally."""

import importlib.util
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "demo_credentials", ROOT / "apps/demo-api/src/sentinel_demo/credentials.py"
)
credentials = importlib.util.module_from_spec(spec)
spec.loader.exec_module(credentials)


def command(arguments, *, stdin=None):
    result = subprocess.run(
        arguments, cwd=ROOT, input=stdin, text=True, capture_output=True, check=False, timeout=120
    )
    if result.returncode:
        # Never print the stdin program: it contains the ephemeral verification credential.
        raise RuntimeError(
            f"Verification command failed with exit {result.returncode}: {' '.join(arguments[:3])}"
        )
    return result.stdout


def main() -> None:
    artifacts = ROOT / ".artifacts"
    artifacts.mkdir(exist_ok=True)
    token = uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    configuration = {
        "username": "verification-user",
        "password": password,
        "rate_rule": f"verify-rate-{token}.rate",
        "login_rule": f"verify-login-{token}.auth_failures",
    }
    policies = [
        {
            "id": f"verify-rate-{token}",
            "path_prefix": "/api/demo/limited",
            "rate": {
                "requests": 3,
                "window_seconds": 1,
                "exceed_action": "block",
                "block_seconds": 2,
            },
        },
        {
            "id": f"verify-login-{token}",
            "path_prefix": "/api/demo/login",
            "failure_mode": "closed",
            "rate": {"requests": 30, "window_seconds": 10},
            "authentication": {"failures": 3, "window_seconds": 10, "block_seconds": 2},
        },
    ]
    override = {
        "services": {
            "demo-api": {
                "environment": {
                    "SENTINEL_DEMO_USERNAME": configuration["username"],
                    "SENTINEL_DEMO_PASSWORD_HASH": credentials.hash_password(password),
                    "SENTINEL_PROTECTION_ENABLED": "true",
                    "SENTINEL_PROTECTION_POLICIES": json.dumps(policies),
                }
            }
        }
    }
    descriptor, filename = tempfile.mkstemp(dir=artifacts, prefix="phase3-", suffix=".json")
    temporary = Path(filename)
    if not temporary.resolve().is_relative_to(artifacts.resolve()):
        raise RuntimeError("verification override escaped workspace")
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(
            override, output
        )  # Only a salted hash is written; plaintext stays in memory/stdin.
    base = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]
    result = None
    try:
        command(
            [
                *base,
                "-f",
                str(temporary),
                "up",
                "-d",
                "--no-deps",
                "--wait",
                "--wait-timeout",
                "60",
                "demo-api",
            ]
        )
        runtime = (ROOT / "scripts/verify_protection_runtime.py").read_text(encoding="utf-8")
        program = (
            "import json\nCONFIG = json.loads(" + repr(json.dumps(configuration)) + ")\n" + runtime
        )
        result = command([*base, "exec", "-T", "demo-api", "python", "-"], stdin=program)
    finally:
        try:
            command([*base, "up", "-d", "--no-deps", "--wait", "--wait-timeout", "60", "demo-api"])
        finally:
            temporary.unlink(missing_ok=True)
    print(result, end="")
    print("Normal demo credentials and policies restored.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error)) from None
