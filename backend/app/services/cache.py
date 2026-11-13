"""Quota-saving report cache.

Before an analyzer is dispatched, the orchestrator looks for a successful report
for the same (observable, analyzer) pair inside the analyzer's TTL window. When
one exists it is copied into the new job and marked `from_cache`, so the external
API is never called twice for the same question within the window.

Only analyzer reports are cacheable, and the lookup enforces it. A connector
report records that an export happened; serving it from cache would mean
claiming an export took place when it did not. A pivot report is a decision
about one specific parent job, so it is not transferable either.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.job import ObservableType, PluginKind, PluginReport, ReportStatus


async def find_fresh_report(
    session: AsyncSession,
    *,
    plugin_name: str,
    observable_value: str,
    observable_type: ObservableType,
    ttl_seconds: int,
) -> PluginReport | None:
    """Return the most recent successful analyzer report still inside the TTL window."""
    if ttl_seconds <= 0:
        return None
    cutoff = datetime.now(UTC) - timedelta(seconds=ttl_seconds)
    statement = (
        select(PluginReport)
        .where(
            PluginReport.plugin_name == plugin_name,
            PluginReport.plugin_type == PluginKind.ANALYZER,
            PluginReport.observable_value == observable_value,
            PluginReport.observable_type == observable_type,
            PluginReport.status == ReportStatus.SUCCESS,
            PluginReport.created_at >= cutoff,
        )
        .order_by(PluginReport.created_at.desc())
        .limit(1)
    )
    return (await session.execute(statement)).scalar_one_or_none()


def clone_into_report(source: PluginReport, target: PluginReport) -> None:
    """Copy a cached result onto a pending report of the current job."""
    target.status = ReportStatus.SUCCESS
    target.raw_output = source.raw_output
    target.summary_data = source.summary_data
    target.errors = None
    target.execution_time_ms = 0
    target.from_cache = True
    target.cached_from_id = source.id
    target.finished_at = datetime.now(UTC)
