"""Authentication endpoints. No public provisioning or registration exists."""

import asyncio
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from sentinel_api.auth import (
    HASHER,
    access_token,
    auth_limit,
    csrf_matches,
    current_account,
    digest,
    locked_refresh,
    new_refresh,
    origin,
    refresh_cookie,
    unauthorized,
    verify_password,
)
from sentinel_api.models import AdminAccount, AdminSession
from sentinel_security.management import audit

router = APIRouter(prefix="/auth", tags=["authentication"])


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    password: SecretStr = Field(min_length=1, max_length=128)


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    username: str
    role: Literal["ADMIN", "ANALYST"]
    active: bool
    created_at: datetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "Bearer"  # noqa: S105 - HTTP authentication scheme
    expires_in: int
    csrf_token: str
    account: AccountOut


class CsrfOut(BaseModel):
    csrf_token: str


def token_response(request, response, account, family, token, csrf):
    settings = request.app.state.admin_settings
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=max(0, int((family.expires_at - datetime.now(UTC)).total_seconds())),
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
        path="/api/admin/auth",
    )
    return TokenOut(
        access_token=access_token(settings, account, family),
        expires_in=settings.access_seconds,
        csrf_token=csrf,
        account=AccountOut.model_validate(account),
    )


@router.post("/login", response_model=TokenOut, dependencies=[Depends(origin)])
async def login(data: Login, request: Request, response: Response):
    await auth_limit(request, data.username)
    resources = request.app.state.resources
    async with resources.session_factory() as session:
        account = await session.scalar(
            select(AdminAccount).where(AdminAccount.username == data.username)
        )
    encoded = account.password_hash if account else request.app.state.dummy_password_hash
    valid = await verify_password(request, data.password.get_secret_value(), encoded)
    now = datetime.now(UTC)
    async with resources.session_factory() as session, session.begin():
        # Re-read under lock so account deactivation/password reset cannot race login.
        if account:
            account = await session.scalar(
                select(AdminAccount).where(AdminAccount.id == account.id).with_for_update()
            )
        if not account or not valid or not account.active or account.password_hash != encoded:
            audit(
                session, account.id if account else None, "auth.login", "authentication", "rejected"
            )
            result = None
        else:
            if HASHER.check_needs_rehash(encoded):
                async with request.app.state.hash_slots:
                    account.password_hash = await asyncio.to_thread(
                        HASHER.hash, data.password.get_secret_value()
                    )
            family = AdminSession(
                id=uuid4(),
                account_id=account.id,
                created_at=now,
                expires_at=now
                + timedelta(seconds=request.app.state.admin_settings.session_seconds),
            )
            session.add(family)
            await session.flush()
            token, csrf = new_refresh(session, family)
            audit(session, account.id, "auth.login", str(family.id))
            result = (account, family, token, csrf)
    if result is None:
        raise unauthorized()
    return token_response(request, response, *result)


@router.post("/csrf", response_model=CsrfOut, dependencies=[Depends(origin)])
async def prepare_csrf(request: Request):
    """Reload handshake: Origin + custom header protect issuance of a fresh CSRF nonce."""
    await auth_limit(request)
    token = refresh_cookie(request)
    async with request.app.state.resources.session_factory() as session, session.begin():
        family, row, account = await locked_refresh(session, token)
        if (
            not family
            or family.revoked_at
            or family.expires_at <= datetime.now(UTC)
            or not account.active
            or row.used_at
        ):
            raise unauthorized()
        csrf = secrets.token_urlsafe(32)
        row.csrf_digest = digest(csrf)
    return CsrfOut(csrf_token=csrf)


@router.post("/refresh", response_model=TokenOut, dependencies=[Depends(origin)])
async def refresh(request: Request, response: Response):
    await auth_limit(request)
    token = refresh_cookie(request)
    now = datetime.now(UTC)
    result = None
    async with request.app.state.resources.session_factory() as session, session.begin():
        family, row, account = await locked_refresh(session, token)
        if family and family.revoked_at is None and family.expires_at > now and account.active:
            if not csrf_matches(request, row):
                raise HTTPException(403, "CSRF validation failed")
            if row.used_at is not None:
                family.revoked_at = now
                audit(session, account.id, "auth.refresh_reuse", str(family.id), "rejected")
            else:
                row.used_at = now
                replacement, csrf = new_refresh(session, family)
                audit(session, account.id, "auth.refresh", str(family.id))
                result = (account, family, replacement, csrf)
        else:
            audit(
                session,
                account.id if account else None,
                "auth.refresh",
                "authentication",
                "rejected",
            )
    if result is None:
        raise unauthorized()
    return token_response(request, response, *result)


@router.post("/logout", status_code=204, dependencies=[Depends(origin)])
async def logout(request: Request, response: Response):
    await auth_limit(request)
    token = refresh_cookie(request)
    async with request.app.state.resources.session_factory() as session, session.begin():
        family, row, account = await locked_refresh(session, token)
        if family is None:
            raise unauthorized()
        if not csrf_matches(request, row):
            raise HTTPException(403, "CSRF validation failed")
        family.revoked_at = datetime.now(UTC)
        audit(session, account.id, "auth.logout", str(family.id))
    response.delete_cookie(
        request.app.state.admin_settings.cookie_name,
        path="/api/admin/auth",
        secure=request.app.state.admin_settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


@router.get("/me", response_model=AccountOut)
async def me(account: Annotated[AdminAccount, Depends(current_account)]):
    return account
