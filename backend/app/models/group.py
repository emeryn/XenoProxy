"""Groups: the unit of membership and of restricted job visibility.

A group is XenoProxy's equivalent of an IntelOwl organisation. Every user belongs to
at least one; jobs submitted at TLP AMBER or RED are visible only to members of
the submitter's groups, while CLEAR and GREEN jobs stay visible to everyone.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Table, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base

user_groups = Table(
    "user_groups",
    Base.metadata,
    Column(
        "user_id",
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "group_id",
        UUID(as_uuid=True),
        ForeignKey("groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(512), default="")
    # New users join every default group, which is how the shared team history
    # keeps working without anyone assigning memberships by hand.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    require_mfa: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Names this group answers to in the identity provider or the directory. A
    # user signing in through either lands in every XenoProxy group whose list
    # holds one of the groups the provider reported, which is how a directory
    # stays the single place memberships are managed.
    external_names: Mapped[list[str]] = mapped_column(ARRAY(String(256)), default=list)
    # Membership grants the administrator role. Expressed on the group rather
    # than as one configured group name per provider, so a deployment can map
    # several directory groups onto administration without a second setting.
    grants_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Which provider last signed somebody in through this group, and when.
    # A group with neither is local: nothing outside has ever claimed it.
    # Recorded on the sign-in rather than configured, so the tag reflects
    # what actually happens instead of what someone intended.
    matched_source: Mapped[str | None] = mapped_column(String(16))
    matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    members: Mapped[list[User]] = relationship(  # noqa: F821
        secondary=user_groups, back_populates="groups", lazy="selectin"
    )
