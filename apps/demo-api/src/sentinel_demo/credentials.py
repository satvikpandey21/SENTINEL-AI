"""Fixed-cost salted scrypt hashes for the explicitly test-only demo login."""

import hashlib
import hmac
import re
import secrets

PATTERN = re.compile(r"scrypt-v1:([0-9a-f]{32}):([0-9a-f]{64})")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=67108864
    )
    return f"scrypt-v1:{salt.hex()}:{digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    match = PATTERN.fullmatch(encoded)
    if match is None:
        raise ValueError("invalid demo credential hash")
    salt, expected = (bytes.fromhex(part) for part in match.groups())
    actual = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=67108864
    )
    return hmac.compare_digest(actual, expected)
