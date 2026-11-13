"""Interactive, first-account-only bootstrap; passwords never enter argv or stdout."""

import argparse
import asyncio
import getpass
import re
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text

from sentinel_api.auth import HASHER
from sentinel_api.models import AdminAccount
from sentinel_security.config import Settings
from sentinel_security.infrastructure import Resources
from sentinel_security.management import audit


async def bootstrap(resources, username, password):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", username) or not 15 <= len(password) <= 128:
        raise ValueError(
            "Username must be 3..64 lowercase safe characters; password 15..128 characters"
        )
    encoded = await asyncio.to_thread(HASHER.hash, password)
    async with resources.session_factory() as session, session.begin():
        await session.execute(text("SELECT pg_advisory_xact_lock(517291406)"))
        if await session.scalar(select(AdminAccount.id).limit(1)) is not None:
            raise ValueError("Bootstrap unavailable: use authenticated account management")
        account = AdminAccount(
            id=uuid4(),
            username=username,
            password_hash=encoded,
            role="ADMIN",
            active=True,
            created_at=datetime.now(UTC),
        )
        session.add(account)
        audit(session, account.id, "account.bootstrap", str(account.id), summary={"role": "ADMIN"})
    return account.id


async def run(username, password):
    async with Resources(Settings()) as resources:
        await bootstrap(resources, username, password)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    password = getpass.getpass("Administrator password (15..128 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    try:
        asyncio.run(run(args.username, password))
    except ValueError as error:
        raise SystemExit(str(error)) from None
    print("Administrator provisioned. No credentials were printed.")


if __name__ == "__main__":
    main()
