"""Bounded demo-only credential checking; no tokens, accounts, or administrative access."""

import asyncio
import hmac
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinel_demo.credentials import PATTERN, verify_password
from sentinel_security.protection import record_verified_login


class DemoAuthSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_DEMO_", frozen=True, extra="ignore", hide_input_in_errors=True
    )
    auth_enabled: bool = False
    username: SecretStr | None = None
    password_hash: SecretStr | None = None

    @field_validator("username")
    @classmethod
    def username_format(cls, value):
        if value is not None and not re.fullmatch(
            r"[a-zA-Z0-9_.-]{1,64}", value.get_secret_value()
        ):
            raise ValueError("invalid demo username")
        return value

    @field_validator("password_hash")
    @classmethod
    def hash_format(cls, value):
        if value is not None and not PATTERN.fullmatch(value.get_secret_value()):
            raise ValueError("invalid demo credential hash")
        return value

    @model_validator(mode="after")
    def required_credentials(self):
        if self.auth_enabled and (self.username is None or self.password_hash is None):
            raise ValueError("enabled demo login requires a username and password hash")
        return self


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)
    username: SecretStr
    password: SecretStr

    @field_validator("username", "password")
    @classmethod
    def bounded_credential(cls, value):
        if not 1 <= len(value.get_secret_value()) <= 128:
            raise ValueError("invalid credential length")
        return value


def install_login(app: FastAPI, settings: DemoAuthSettings) -> None:
    semaphore = asyncio.Semaphore(2)

    @app.post("/api/demo/login", tags=["test-only authentication"])
    async def login(request: Request):
        if (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            return JSONResponse({"detail": "JSON login required"}, status_code=415)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 2048:
                return JSONResponse({"detail": "Login request too large"}, status_code=413)
            body.extend(chunk)
        try:
            credentials = LoginBody.model_validate_json(bytes(body))
        except ValidationError:
            return JSONResponse({"detail": "Invalid login request"}, status_code=422)
        finally:
            body.clear()
        try:
            async with asyncio.timeout(0.2):
                await semaphore.acquire()
        except TimeoutError:
            return JSONResponse(
                {"detail": "Service temporarily unavailable"},
                status_code=503,
                headers={"Retry-After": "1"},
            )
        try:
            task = asyncio.create_task(
                asyncio.to_thread(
                    verify_password,
                    credentials.password.get_secret_value(),
                    settings.password_hash.get_secret_value(),
                )
            )
            try:
                password_ok = await asyncio.shield(task)
            except asyncio.CancelledError:
                await asyncio.gather(task, return_exceptions=True)
                raise
            username_ok = hmac.compare_digest(
                credentials.username.get_secret_value().encode(),
                settings.username.get_secret_value().encode(),
            )
            verified = password_ok and username_ok
        finally:
            semaphore.release()
        record_verified_login(request.scope, succeeded=verified)
        if not verified:
            return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
        return {"authenticated": True}
