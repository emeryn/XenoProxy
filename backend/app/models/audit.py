"""Append-only, hash-chained audit trail."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AuditEvent(Base):
    """One audit row. Each row carries the hash of the previous row, so removing or
    rewriting a row breaks the chain and is detectable by `verify_chain`."""

    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4, unique=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    actor: Mapped[str] = mapped_column(String(128), default="system")
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    target: Mapped[str | None] = mapped_column(String(256))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


Index("ix_audit_occurred_at", AuditEvent.occurred_at.desc())
Index("ix_audit_action", AuditEvent.action)
