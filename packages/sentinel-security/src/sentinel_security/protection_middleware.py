"""Enforcement runs inside request monitoring, so rejected responses are monitored too."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel_security.events import client_identifier
from sentinel_security.protection import Decision, SecurityEngine


class ProtectionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        engine: SecurityEngine,
        identity_key: bytes,
        excluded_paths: tuple[str, ...],
    ) -> None:
        self.app, self.engine, self.identity_key = app, engine, identity_key
        self.excluded_paths = excluded_paths

    @staticmethod
    def remember(scope: Scope, decision: Decision) -> None:
        if decision.action != "allow":
            scope["state"].setdefault("sentinel_decisions", []).append(decision)
        if decision.response_status is not None and decision.policy is not None:
            scope["state"]["sentinel_endpoint"] = decision.policy.path_prefix

    async def restrict(self, decision: Decision, scope, receive, send) -> None:
        detail = (
            "Service temporarily unavailable"
            if decision.response_status == 503
            else "Request temporarily restricted"
        )
        response = JSONResponse(
            {"detail": detail},
            status_code=decision.response_status,
            headers={"Retry-After": str(decision.retry_after_seconds or 1)},
        )
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/")
            for prefix in self.excluded_paths
        ):
            await self.app(scope, receive, send)
            return
        identity = client_identifier(scope["state"]["client_ip"], self.identity_key)
        decision = await self.engine.before_request(scope, identity)
        self.remember(scope, decision)
        if decision.response_status is not None:
            await self.restrict(decision, scope, receive, send)
            return
        checked = replaced = False

        async def guarded_send(message: Message) -> None:
            nonlocal checked, replaced
            if replaced:
                # A failed state write must never forward the successful login response.
                return
            if message["type"] == "http.response.start" and not checked:
                checked = True
                result = await self.engine.after_authentication(scope, identity)
                self.remember(scope, result)
                if result.response_status is not None:
                    replaced = True
                    await self.restrict(result, scope, receive, send)
                    return
            await send(message)

        await self.app(scope, receive, guarded_send)
