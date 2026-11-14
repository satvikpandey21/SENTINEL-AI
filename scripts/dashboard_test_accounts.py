"""Ephemeral browser-test accounts. Run only via the dashboard Playwright fixture.

Credentials go directly to the parent test process memory, never a file or report.
Cleanup removes only exact names from this run and restores the original policies.
"""

import asyncio
import json
import re
import secrets
import sys
import urllib.request
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import delete, select

from sentinel_api.auth import HASHER
from sentinel_api.models import AdminAccount, AdminSession, RefreshToken
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.management import PolicyCoordinator, audit
from sentinel_security.policies import EndpointPolicy

ORIGINAL_POLICIES = None


def demo_request_id():
    with urllib.request.urlopen("http://demo-api:8000/api/demo/ping", timeout=10) as response:
        return response.headers["X-Request-ID"]


async def main():
    async with Resources(Settings()) as resources:
        coordinator = PolicyCoordinator(resources, Settings().effective_policies)
        if len(sys.argv) == 3 and sys.argv[1] == "--cleanup":
            prefix = sys.argv[2]
            if not re.fullmatch(r"phase6-[0-9a-f]{16}", prefix):
                raise ValueError("invalid browser-test account prefix")
            async with resources.session_factory() as session:
                current = await coordinator.latest(session)
            if ORIGINAL_POLICIES is not None and current.policies != ORIGINAL_POLICIES:
                await coordinator.write(
                    policies=[EndpointPolicy.model_validate(row) for row in ORIGINAL_POLICIES],
                    expected=current.version,
                )
            async with resources.session_factory() as session, session.begin():
                names = [prefix, prefix + "-analyst", prefix + "-created"]
                ids = select(AdminAccount.id).where(AdminAccount.username.in_(names))
                families = select(AdminSession.id).where(AdminSession.account_id.in_(ids))
                await session.execute(
                    delete(RefreshToken).where(RefreshToken.session_id.in_(families))
                )
                await session.execute(delete(AdminSession).where(AdminSession.account_id.in_(ids)))
                await session.execute(delete(AdminAccount).where(AdminAccount.id.in_(ids)))
            return
        if len(sys.argv) != 1:
            raise ValueError("unsupported browser-test operation")
        # Emit owned demo traffic before creating temporary accounts.
        request_id = await asyncio.to_thread(demo_request_id)
        prefix, password = "phase6-" + secrets.token_hex(8), secrets.token_urlsafe(24)
        async with resources.session_factory() as session, session.begin():
            current = await coordinator.latest(session)
            policies = current.policies
            for name, role in ((prefix, "ADMIN"), (prefix + "-analyst", "ANALYST")):
                identifier = uuid4()
                session.add(
                    AdminAccount(
                        id=identifier,
                        username=name,
                        password_hash=HASHER.hash(password),
                        role=role,
                        active=True,
                        created_at=datetime.now(UTC),
                    )
                )
                audit(
                    session,
                    identifier,
                    "account.verification",
                    str(identifier),
                    summary={"role": role},
                )
        print(
            json.dumps(
                {
                    "prefix": prefix,
                    "username": prefix,
                    "analyst": prefix + "-analyst",
                    "password": password,
                    "request_id": request_id,
                    "policies": policies,
                }
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
