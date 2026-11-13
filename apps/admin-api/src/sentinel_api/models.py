"""Private administrator credentials, session families and token digests."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from sentinel_security.database import Base


class AdminAccount(Base):
    __tablename__ = "admin_accounts"
    __table_args__ = (
        CheckConstraint("role IN ('ADMIN','ANALYST')", name="ck_admin_role"),
        CheckConstraint("username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'", name="ck_admin_username"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(10))
    active: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    __table_args__ = (
        Index("ix_admin_sessions_account", "account_id", "expires_at"),
        CheckConstraint("expires_at > created_at", name="ck_admin_session_expiry"),
    )
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    account_id: Mapped[UUID] = mapped_column(ForeignKey("admin_accounts.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RefreshToken(Base):
    __tablename__ = "admin_refresh_tokens"
    __table_args__ = (
        Index("ix_admin_refresh_session", "session_id"),
        CheckConstraint(
            "digest ~ '^[0-9a-f]{64}$' AND csrf_digest ~ '^[0-9a-f]{64}$'",
            name="ck_admin_token_digests",
        ),
    )
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[UUID] = mapped_column(ForeignKey("admin_sessions.id"))
    csrf_digest: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
