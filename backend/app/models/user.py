"""Identity, session and API key models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.group import Group, user_groups


class Role(StrEnum):
    """Coarse role; permissions are derived from it, never checked directly."""

    ANALYST = "analyst"
    ADMIN = "admin"


class AuthSource(StrEnum):
    LOCAL = "local"
    OIDC = "oidc"
    PROXY = "proxy"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str | None] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(256))
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"), default=Role.ANALYST)
    auth_source: Mapped[AuthSource] = mapped_column(
        Enum(AuthSource, name="auth_source"), default=AuthSource.LOCAL
    )
    password_hash: Mapped[str | None] = mapped_column(String(256))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Time-based one-time password. The secret is sealed with the master key,
    # exactly like an analyzer credential, so a database dump does not expose it.
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_ciphertext: Mapped[str | None] = mapped_column(String(512))
    mfa_secret_wrapped_key: Mapped[str | None] = mapped_column(String(512))
    mfa_secret_key_version: Mapped[int] = mapped_column(Integer, default=1)
    mfa_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The last accepted time step, so the same code cannot be replayed.
    mfa_last_counter: Mapped[int | None] = mapped_column(BigInteger)
    # The playbook the scan page preselects for this analyst. A name rather
    # than a foreign key, so deleting a playbook degrades to no preference
    # instead of blocking the delete.
    default_playbook: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list[Session]] = relationship(back_populates="user", cascade="all, delete")
    api_keys: Mapped[list[ApiKey]] = relationship(back_populates="user", cascade="all, delete")
    groups: Mapped[list[Group]] = relationship(
        secondary=user_groups, back_populates="members", lazy="selectin"
    )
    recovery_codes: Mapped[list[MfaRecoveryCode]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN

    @property
    def group_ids(self) -> list[uuid.UUID]:
        return [group.id for group in self.groups]


class MfaRecoveryCode(Base):
    """A single-use code that replaces the authenticator when it is lost."""

    __tablename__ = "mfa_recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="recovery_codes")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="sessions")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="api_keys")


Index("ix_sessions_user_id", Session.user_id)
Index("ix_api_keys_user_id", ApiKey.user_id)
Index("ix_mfa_recovery_user_id", MfaRecoveryCode.user_id)
