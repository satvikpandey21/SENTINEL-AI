"""Pure ASGI context middleware, independent of brokers and request body consumption."""

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from time import perf_counter
from uuid import uuid4

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel_security.events import DetectionEvent, EventSink, build_event, route_template
from sentinel_security.protection import SecurityEngine
from sentinel_security.protection_middleware import ProtectionMiddleware


def client_ip(scope: Scope, trusted_proxy_cidrs: tuple[str, ...]) -> str:
    """Trust X-Forwarded-For only from explicitly trusted peers, walking right to left."""
    peer = scope.get("client")
    if not peer:
        return "unknown"
    try:
        address = ip_address(peer[0])
    except ValueError:
        return "unknown"
    networks = tuple(ip_network(cidr) for cidr in trusted_proxy_cidrs)
    if not any(address in network for network in networks):
        return str(address)
    forwarded = [value for key, value in scope["headers"] if key.lower() == b"x-forwarded-for"]
    if len(forwarded) != 1 or len(forwarded[0]) > 2048:
        return str(address)
    try:
        hops = [ip_address(part.strip()) for part in forwarded[0].decode("ascii").split(",")]
    except (ValueError, UnicodeDecodeError):
        return str(address)
    for hop in reversed(hops):
        if not any(address in network for network in networks):
            break
        address = hop
    return str(address)


class RequestContextMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        trusted_proxy_cidrs: tuple[str, ...] = (),
        *,
        service: str = "asgi-api",
        event_sink: EventSink | None = None,
        security_engine: SecurityEngine | None = None,
        identity_key: bytes | None = None,
        metrics=None,
        excluded_paths: tuple[str, ...] = ("/health", "/docs", "/openapi.json"),
    ) -> None:
        if (event_sink is not None or security_engine is not None) and (
            identity_key is None or len(identity_key) < 32
        ):
            raise ValueError("monitoring requires a client identity key of at least 32 bytes")
        self.app = (
            ProtectionMiddleware(app, security_engine, identity_key, excluded_paths)
            if security_engine is not None
            else app
        )
        self.trusted_proxy_cidrs = trusted_proxy_cidrs
        self.service = service
        self.metrics = metrics
        self.event_sink = event_sink
        self.identity_key = identity_key
        self.excluded_paths = excluded_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid4().hex  # Do not trust a caller-supplied correlation identifier.
        tokens = structlog.contextvars.bind_contextvars(request_id=request_id)
        scope.setdefault("state", {}).update(
            request_id=request_id, client_ip=client_ip(scope, self.trusted_proxy_cidrs)
        )
        start = perf_counter()
        occurred_at = datetime.now(UTC)
        status = 500
        response_completed = False
        application_failed = False

        async def send_with_context(message: Message) -> None:
            nonlocal status, response_completed
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"
                ]
                message["headers"] = [*headers, (b"x-request-id", request_id.encode("ascii"))]
            await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                response_completed = True

        try:
            await self.app(scope, receive, send_with_context)
        except BaseException:
            application_failed = True
            raise
        finally:
            # Log the registered route template only: raw paths may contain sensitive values.
            elapsed_seconds = perf_counter() - start
            if self.metrics is not None:
                self.metrics.http(scope, status, elapsed_seconds, response_completed)
            elapsed_ms = round(elapsed_seconds * 1000, 3)
            structlog.get_logger().info(
                "http_request",
                method=scope["method"],
                route=route_template(scope),
                status=status,
                duration_ms=elapsed_ms,
            )
            path = scope.get("path", "")
            excluded = any(
                path == prefix or path.startswith(prefix.rstrip("/") + "/")
                for prefix in self.excluded_paths
            )
            if self.event_sink is not None and not excluded:
                try:
                    event = build_event(
                        scope=scope,
                        request_id=request_id,
                        occurred_at=occurred_at,
                        service=self.service,
                        duration_ms=elapsed_ms,
                        status_code=status,
                        client_ip=scope["state"]["client_ip"],
                        identity_key=self.identity_key,
                        response_completed=response_completed,
                        application_failed=application_failed,
                    )
                    self.event_sink.offer(event)
                    for decision in scope.get("state", {}).get("sentinel_decisions", ()):
                        self.event_sink.offer(
                            DetectionEvent(
                                **{
                                    **event.model_dump(),
                                    "schema_version": 2,
                                    "event_type": "security.decision",
                                    "event_id": uuid4(),
                                    "rule_id": decision.rule_id,
                                    "security_action": decision.action,
                                    "counter_value": decision.counter_value,
                                    "threshold": decision.threshold,
                                    "window_seconds": decision.window_seconds,
                                    "retry_after_seconds": decision.retry_after_seconds,
                                    "restriction_expires_at": decision.restriction_expires_at,
                                    "degraded": decision.degraded,
                                    "severity": "error" if decision.action == "deny" else "warning",
                                }
                            )
                        )
                except Exception as error:
                    structlog.get_logger().warning(
                        "monitoring_event_failed", error_type=type(error).__name__
                    )
            structlog.contextvars.reset_contextvars(**tokens)
