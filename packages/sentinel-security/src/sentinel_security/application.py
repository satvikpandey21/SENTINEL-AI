"""Shared lifecycle and operational endpoints; no administrative business routes yet."""

from collections.abc import Callable
from contextlib import AsyncExitStack, asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.logging import configure_logging
from sentinel_security.middleware import RequestContextMiddleware
from sentinel_security.protection import RedisProtectionStore, SecurityEngine
from sentinel_security.publisher import EventPublisher


def create_application(
    service: str,
    settings: Settings | None = None,
    resource_factory: Callable = Resources,
    publisher_factory: Callable = EventPublisher,
) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    publisher = publisher_factory(settings) if settings.monitoring_enabled else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with AsyncExitStack() as stack:
            resources = await stack.enter_async_context(resource_factory(settings))
            app.state.resources = resources
            if publisher is not None:
                await stack.enter_async_context(publisher)
                app.state.event_publisher = publisher
            structlog.get_logger().info("service_started", service=service)
            try:
                yield
            finally:
                structlog.get_logger().info("service_stopped", service=service)

    app = FastAPI(
        title=service,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment == "development" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment == "development" else None,
    )
    app.add_middleware(
        RequestContextMiddleware,
        trusted_proxy_cidrs=settings.trusted_proxy_cidrs,
        service=service,
        event_sink=publisher,
        security_engine=(
            SecurityEngine(
                RedisProtectionStore(
                    lambda: app.state.resources.redis, settings.protection_redis_timeout_seconds
                ),
                service,
                settings.effective_policies,
            )
            if settings.protection_enabled
            else None
        ),
        identity_key=(
            bytes.fromhex(settings.client_identity_key.get_secret_value())
            if settings.client_identity_key is not None
            else None
        ),
        excluded_paths=settings.monitoring_excluded_paths,
    )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, error: Exception):
        request_id = getattr(request.state, "request_id", "unknown")
        structlog.get_logger().error(
            "unhandled_exception", error_type=type(error).__name__, request_id=request_id
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
            headers={"X-Request-ID": request_id},
        )

    @app.get("/health/live", tags=["operations"])
    async def live():
        return {"status": "ok", "service": service}

    @app.get("/health/ready", tags=["operations"])
    async def ready(request: Request):
        dependencies = await request.app.state.resources.health()
        healthy = all(state == "up" for state in dependencies.values())
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={"status": "ready" if healthy else "not_ready", "dependencies": dependencies},
        )

    return app
