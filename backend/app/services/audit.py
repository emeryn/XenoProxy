"""Tamper-evident audit trail.

Every row carries the hash of the previous row. Deleting or rewriting a row
breaks the chain, which `verify_chain` detects and reports with the offending
sequence number.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger, request_id_var
from app.models.audit import AuditEvent

logger = get_logger(__name__)


def _entry_hash(payload: dict[str, Any], previous_hash: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{previous_hash}|{canonical}".encode()).hexdigest()


async def record(
    session: AsyncSession,
    *,
    action: str,
    actor: str = "system",
    actor_id: uuid.UUID | None = None,
    outcome: str = "success",
    target: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append one audit event, chained to the previous one."""
    previous = (
        await session.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1))
    ).scalar_one_or_none()
    previous_hash = previous.entry_hash if previous else ""

    event_id = uuid.uuid4()
    payload = {
        "id": str(event_id),
        "action": action,
        "actor": actor,
        "actor_id": str(actor_id) if actor_id else None,
        "outcome": outcome,
        "target": target,
        "ip_address": ip_address,
        "details": details or {},
    }
    event = AuditEvent(
        id=event_id,
        action=action,
        actor=actor[:128],
        actor_id=actor_id,
        outcome=outcome,
        target=target[:256] if target else None,
        ip_address=ip_address,
        user_agent=user_agent[:512] if user_agent else None,
        request_id=request_id_var.get(),
        details=details or {},
        previous_hash=previous_hash,
        entry_hash=_entry_hash(payload, previous_hash),
    )
    session.add(event)
    await session.flush()
    logger.info("audit", action=action, actor=actor, outcome=outcome, target=target)
    return event


async def verify_chain(session: AsyncSession, limit: int = 5000) -> dict[str, Any]:
    """Recompute the chain and report the first broken link, if any."""
    rows = list(
        (
            await session.execute(select(AuditEvent).order_by(AuditEvent.seq.asc()).limit(limit))
        ).scalars()
    )
    previous_hash = ""
    for row in rows:
        payload = {
            "id": str(row.id),
            "action": row.action,
            "actor": row.actor,
            "actor_id": str(row.actor_id) if row.actor_id else None,
            "outcome": row.outcome,
            "target": row.target,
            "ip_address": row.ip_address,
            "details": row.details or {},
        }
        expected = _entry_hash(payload, previous_hash)
        if row.previous_hash != previous_hash or row.entry_hash != expected:
            return {"valid": False, "checked": len(rows), "broken_at_seq": row.seq}
        previous_hash = row.entry_hash
    return {"valid": True, "checked": len(rows), "broken_at_seq": None}
