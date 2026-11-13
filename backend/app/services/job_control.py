"""Cooperative job cancellation.

An analyst can stop a running job, which IntelOwl exposes as the plugin `kill`
action. The request arrives in the API process while the job runs in a worker
process, so the two communicate through a short-lived key in the queue.

The cancellation is cooperative, and deliberately so: the orchestrator checks
the flag before it starts each plugin and between phases. A provider call that
is already in flight is left to finish — aborting it mid-request would leak a
half-written report and, for a submission-style provider like URLScan, would
lose the scan identifier we would need to collect the result later. What a kill
guarantees is that nothing further starts and that the job stops at KILLED.
"""

from __future__ import annotations

import uuid
from typing import Any, Protocol

from app.core.logging import get_logger

logger = get_logger(__name__)

KEY_PREFIX = "xenoproxy:job:kill:"
# Long enough to outlive any job (the worker's job_timeout is 900s), short
# enough that a stale flag cannot kill a later job that reuses the identifier.
TTL_SECONDS = 3600


class KeyValueStore(Protocol):
    """The slice of the Redis client this module needs."""

    async def set(self, name: str, value: Any, ex: int | None = ...) -> Any: ...
    async def exists(self, name: str) -> Any: ...
    async def delete(self, name: str) -> Any: ...


def _key(job_id: uuid.UUID) -> str:
    return f"{KEY_PREFIX}{job_id}"


async def request_kill(store: KeyValueStore, job_id: uuid.UUID) -> None:
    """Ask the worker to stop this job at its next checkpoint."""
    await store.set(_key(job_id), "1", ex=TTL_SECONDS)
    logger.info("job_kill_requested", job_id=str(job_id))


async def is_kill_requested(store: KeyValueStore | None, job_id: uuid.UUID) -> bool:
    """Whether a stop was asked for. A missing store means "not killed"."""
    if store is None:
        return False
    try:
        return bool(await store.exists(_key(job_id)))
    except Exception as exc:
        # The queue being briefly unreachable must not abort the analysis.
        logger.warning("job_kill_check_failed", job_id=str(job_id), error=str(exc))
        return False


async def clear_kill(store: KeyValueStore | None, job_id: uuid.UUID) -> None:
    """Drop the flag once the job has stopped, so a re-run is not killed too."""
    if store is None:
        return
    try:
        await store.delete(_key(job_id))
    except Exception as exc:
        logger.warning("job_kill_clear_failed", job_id=str(job_id), error=str(exc))
