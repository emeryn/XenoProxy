"""Playbook model: a named plugin pipeline scoped to observable types.

A playbook names the plugins of each type to run, in the order the lifecycle
imposes: analyzers first, then connectors on the aggregated result, then pivots
on the finished job. Keeping one list per type is what lets the orchestrator
schedule each phase without re-deriving a plugin's kind from the registry.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(512), default="")
    observable_types: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list)
    analyzers: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    connectors: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    pivots: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
