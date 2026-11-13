"""What a conversation has actually looked at.

A chat about an investigation loses its thread quickly: twenty exchanges later,
nobody remembers which addresses were checked or which of them came back bad.
The tools already answer with the observable, its type and its verdict, so the
conversation knows — it just never said so.

This reads it back out of the recorded tool steps rather than storing a second
copy. The steps are the evidence an analyst is shown anyway, so deriving from
them means the panel can never disagree with the trace above it, and a
conversation from before this existed gets its panel for free.

The one thing not taken from the transcript is the state of a job: a scan
the chat submitted is `PENDING` in the transcript forever, so `refresh()`
reads the referenced jobs back before the panel is shown.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.job import Job

# Keys a tool result uses for the same thing, in the order they are preferred.
_VALUE_KEYS = ("observable", "value")


def _as_entry(payload: Any) -> dict[str, str] | None:
    """One observable out of one tool result, or None if it holds no observable."""
    if not isinstance(payload, dict):
        return None
    value = ""
    for key in _VALUE_KEYS:
        candidate = payload.get(key)
        if isinstance(candidate, str) and candidate.strip():
            value = candidate.strip()
            break
    if not value:
        return None

    entry = {"value": value[:512]}
    for key in ("type", "verdict", "status", "job_id"):
        candidate = payload.get(key)
        if isinstance(candidate, str) and candidate:
            entry[key] = candidate[:64]
    return entry


def _walk(payload: Any, found: dict[str, dict[str, str]]) -> None:
    """Collect every observable in a result, however deeply it is nested.

    A tool answers with one object, a list of them, or an object holding a list;
    walking covers all three without the caller knowing which it got.
    """
    if isinstance(payload, list):
        for item in payload:
            _walk(item, found)
        return
    if not isinstance(payload, dict):
        return

    entry = _as_entry(payload)
    if entry is not None:
        # Later mentions win: a verdict settles as the job progresses, and the
        # most recent step holds the state the analyst should be shown.
        found[entry["value"]] = {**found.get(entry["value"], {}), **entry}

    for item in payload.values():
        if isinstance(item, (dict, list)):
            _walk(item, found)


def from_steps(steps: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Every observable the recorded tool steps touched, in order of first sight."""
    found: dict[str, dict[str, str]] = {}
    for step in steps or []:
        if not isinstance(step, dict):
            continue
        # Only what a tool answered counts. Arguments are what the model asked
        # for, which may be a value that does not exist.
        if step.get("ok"):
            _walk(step.get("result"), found)
    return list(found.values())


def from_messages(messages: list[Any]) -> list[dict[str, str]]:
    """The same, across a whole conversation."""
    found: dict[str, dict[str, str]] = {}
    for message in messages:
        for entry in from_steps(getattr(message, "steps", None)):
            found[entry["value"]] = {**found.get(entry["value"], {}), **entry}
    return list(found.values())


async def refresh(session: AsyncSession, entries: list[dict[str, str]]) -> list[dict[str, str]]:
    """Replace the recorded job state with the state those jobs are in now.

    The steps are a transcript: they hold what a tool answered at the moment it
    ran. A scan the assistant submitted is `PENDING` in that transcript and
    stays `PENDING` in it forever, even once the worker has finished and the
    verdict is in. Reading the referenced jobs back is what makes the panel
    show the investigation rather than its history.

    Only the job's own fields are refreshed. The observable and its type come
    from the transcript and cannot change.
    """
    wanted: dict[uuid.UUID, dict[str, str]] = {}
    for entry in entries:
        raw = entry.get("job_id")
        if not raw:
            continue
        try:
            wanted[uuid.UUID(raw)] = entry
        except (TypeError, ValueError):
            continue
    if not wanted:
        return entries

    rows = (await session.execute(select(Job).where(Job.id.in_(wanted)))).scalars()
    for job in rows:
        entry = wanted.get(job.id)
        if entry is None:
            continue
        entry["status"] = job.status.value
        entry["verdict"] = job.verdict.value
    return entries
