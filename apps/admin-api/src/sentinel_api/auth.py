"""Strict JWT validation and database-backed revocable session families."""

import asyncio
import hashlib
import hmac
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.exceptions import RedisError
from sqlalchemy import select

from sentinel_api.models import AdminAccount, AdminSession, RefreshToken
from sentinel_security.management import audit

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
BEARER = HTTPBearer(auto_error=False)
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
LIMIT_SCRIPT = """
local denied = 0
for i, key in ipairs(KEYS) do
    local n = redis.call('INCR', key)
    if n == 1 then redis.call('EXPIRE', key, ARGV[1]) end
    if n > tonumber(ARGV[i+1]) then denied = 1 end
end
return denied
"""


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def unauthorized():
    return HTTPException(401, "Authentication failed", headers={"WWW-Authenticate": "Bearer"})


def origin(request: Request):
    settings = request.app.state.admin_settings
    if request.headers.get("origin") not in settings.allowed_origins:
        raise HTTPException(403, "Origin not permitted")
    if request.headers.get("x-csrf-intent") != "sentinel-admin":
        raise HTTPException(403, "CSRF protection required")


async def auth_limit(request: Request, username: str | None = None):
    settings = request.app.state.admin_settings
    key = bytes.fromhex(settings.signing_key.get_secret_value())
    peer = getattr(request.state, "client_ip", "unknown")

    def pseudonym(value):
        return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()

    namespace = "login" if username is not None else "session"
    keys = [f"sentinel:admin:{namespace}:ip:{pseudonym(peer)}"]
    limits = [settings.login_attempts * 5 if username is not None else 120]
    if username is not None:
        keys.append("sentinel:admin:login:account:" + pseudonym(username))
        limits.append(settings.login_attempts)
    try:
        denied = await request.app.state.resources.redis.eval(
            LIMIT_SCRIPT, len(keys), *keys, settings.login_window_seconds, *limits
        )
    except (OSError, TimeoutError, RedisError):
        # Dependency errors can embed service credentials; only a fixed response leaves here.
        raise HTTPException(503, "Authentication temporarily unavailable") from None
    if denied:
        async with request.app.state.resources.session_factory() as session, session.begin():
            audit(session, None, "auth.rate_limit", "authentication", "rejected")
        raise HTTPException(
            429,
            "Authentication temporarily restricted",
            headers={"Retry-After": str(settings.login_window_seconds)},
        )


def access_token(settings, account, family):
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(account.id),
            "sid": str(family.id),
            "jti": uuid4().hex,
            "iss": settings.issuer,
            "aud": settings.audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=settings.access_seconds)).timestamp()),
            "token_type": "access",
        },
        bytes.fromhex(settings.signing_key.get_secret_value()),
        algorithm="HS256",
        headers={"typ": "at+jwt"},
    )


def decode_access(settings, token):
    if len(token) > 2048:
        raise unauthorized()
    try:
        value = jwt.decode(
            token,
            bytes.fromhex(settings.signing_key.get_secret_value()),
            algorithms=["HS256"],
            issuer=settings.issuer,
            audience=settings.audience,
            options={
                "require": ["sub", "sid", "jti", "iss", "aud", "iat", "nbf", "exp", "token_type"],
                "strict_aud": True,
            },
        )
        if (
            jwt.get_unverified_header(token).get("typ") != "at+jwt"
            or value["token_type"] != "access"  # noqa: S105 - JWT type marker
        ):
            raise ValueError
        if any(type(value[k]) is not int for k in ("iat", "nbf", "exp")):
            raise ValueError
        if (
            value["exp"] - value["iat"] > settings.access_seconds
            or value["exp"] <= value["iat"]
            or value["nbf"] != value["iat"]
        ):
            raise ValueError
        UUID(value["sub"])
        UUID(value["sid"])
        if not isinstance(value["jti"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["jti"]):
            raise ValueError
        return value
    except (jwt.InvalidTokenError, ValueError, TypeError, KeyError, AttributeError):
        raise unauthorized() from None


async def current_account(
    request: Request, credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(BEARER)]
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized()
    claims = decode_access(request.app.state.admin_settings, credentials.credentials)
    async with request.app.state.resources.session_factory() as session:
        account = await session.scalar(
            select(AdminAccount)
            .join(AdminSession, AdminSession.account_id == AdminAccount.id)
            .where(
                AdminAccount.id == UUID(claims["sub"]),
                AdminAccount.active.is_(True),
                AdminSession.id == UUID(claims["sid"]),
                AdminSession.revoked_at.is_(None),
                AdminSession.expires_at > datetime.now(UTC),
            )
        )
    if account is None:
        raise unauthorized()
    request.state.admin_session_id = UUID(claims["sid"])
    request.state.admin_account_id = account.id
    return account


async def administrator(
    request: Request, account: Annotated[AdminAccount, Depends(current_account)]
):
    if account.role != "ADMIN":
        async with request.app.state.resources.session_factory() as session, session.begin():
            audit(
                session,
                account.id,
                "authorization.denied",
                request.scope["route"].path,
                "rejected",
                {"method": request.method},
            )
        raise HTTPException(403, "Administrator role required")
    return account


async def verify_password(request, password, encoded):
    async with request.app.state.hash_slots:
        try:
            return await asyncio.to_thread(HASHER.verify, encoded, password)
        except VerificationError:
            return False


def new_refresh(session, family):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    session.add(
        RefreshToken(
            digest=digest(token),
            session_id=family.id,
            csrf_digest=digest(csrf),
            created_at=datetime.now(UTC),
        )
    )
    return token, csrf


def refresh_cookie(request):
    token = request.cookies.get(request.app.state.admin_settings.cookie_name, "")
    if not TOKEN_PATTERN.fullmatch(token):
        raise unauthorized()
    return token


async def locked_refresh(session, token):
    # Family lock serializes rotation/replay/logout even for different token generations.
    family_id = await session.scalar(
        select(RefreshToken.session_id).where(RefreshToken.digest == digest(token))
    )
    if family_id is None:
        return None, None, None
    family = await session.scalar(
        select(AdminSession).where(AdminSession.id == family_id).with_for_update()
    )
    row = await session.get(RefreshToken, digest(token))
    account = await session.get(AdminAccount, family.account_id)
    return family, row, account


def csrf_matches(request, row):
    supplied = request.headers.get("x-csrf-token", "")
    return TOKEN_PATTERN.fullmatch(supplied) and hmac.compare_digest(
        digest(supplied), row.csrf_digest
    )
