"""Shared SQLAlchemy metadata and async session boundary. Schema changes use Alembic only."""

from collections.abc import AsyncIterator

from sqlalchemy.orm import DeclarativeBase
from starlette.requests import Request


class Base(DeclarativeBase):
    pass


async def get_session(request: Request) -> AsyncIterator:
    async with request.app.state.resources.session_factory() as session:
        yield session
