"""Pure ASGI context middleware, independent of brokers and request body consumption."""

from ipaddress import ip_address, ip_network
from time import perf_counter
from uuid import uuid4

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send


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
    def __init__(self, app: ASGIApp, trusted_proxy_cidrs: tuple[str, ...] = ()) -> None:
        self.app = app
        self.trusted_proxy_cidrs = trusted_proxy_cidrs

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
        status = 500

        async def send_with_context(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != b"x-request-id"
                ]
                message["headers"] = [*headers, (b"x-request-id", request_id.encode("ascii"))]
            await send(message)

        try:
            await self.app(scope, receive, send_with_context)
        finally:
            # Log the registered route template only: raw paths may contain sensitive values.
            route = scope.get("route")
            structlog.get_logger().info(
                "http_request",
                method=scope["method"],
                route=getattr(route, "path", "unmatched"),
                status=status,
                duration_ms=round((perf_counter() - start) * 1000, 3),
            )
            structlog.contextvars.reset_contextvars(**tokens)
