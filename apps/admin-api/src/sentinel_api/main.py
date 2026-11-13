"""Administrative API assembly; demo authentication has no dependency on this module."""

import asyncio
import secrets
from contextlib import asynccontextmanager

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError

from sentinel_api.auth import HASHER
from sentinel_api.auth_routes import router as auth_router
from sentinel_api.routes import router
from sentinel_api.schemas import ErrorOut
from sentinel_api.settings import AdminSettings
from sentinel_security.application import create_application
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.management import audit
from sentinel_security.policy_runtime import PolicyUnavailable


def create_app(settings=None, admin_settings=None, resource_factory=Resources):
    settings = settings or Settings()
    admin_settings = admin_settings or AdminSettings()
    if settings.environment == "production" and admin_settings.deployment != "production":
        raise ValueError("production service requires production administrative settings")
    app = create_application("sentinel-admin-api", settings, resource_factory)
    app.state.admin_settings = admin_settings
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        application.state.hash_slots = asyncio.Semaphore(2)
        application.state.dummy_password_hash = await asyncio.to_thread(
            HASHER.hash, secrets.token_urlsafe(32)
        )
        async with original_lifespan(application):
            yield

    app.router.lifespan_context = lifespan
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(admin_settings.allowed_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-CSRF-Intent"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError):
        actor = getattr(request.state, "admin_account_id", None)
        if actor and request.method in ("POST", "PUT", "PATCH", "DELETE"):
            async with request.app.state.resources.session_factory() as session, session.begin():
                audit(
                    session,
                    actor,
                    "request.invalid",
                    request.scope["route"].path,
                    "rejected",
                    {"reason": "invalid_input"},
                )
        # Never echo Pydantic input/context: validation errors can contain credentials.
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Request validation failed",
                "errors": [
                    {"location": list(item["loc"]), "type": item["type"]} for item in error.errors()
                ],
            },
        )

    async def unavailable(request: Request, error: Exception):
        return JSONResponse(
            status_code=503,
            content={"detail": "Security dependency temporarily unavailable"},
            headers={"Cache-Control": "no-store"},
        )

    app.add_exception_handler(RedisError, unavailable)
    app.add_exception_handler(PolicyUnavailable, unavailable)
    errors = {code: {"model": ErrorOut} for code in (401, 403, 404, 409, 422, 429, 503)}
    app.include_router(auth_router, prefix="/api/admin", responses=errors)
    app.include_router(router, prefix="/api/admin", responses=errors)
    return app
