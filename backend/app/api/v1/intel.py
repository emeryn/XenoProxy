"""Querying what the providers returned, across jobs, and the service statistics.

Two read-only surfaces that both look inside the history rather than at one job:
a search over the provider payloads, and the counters a dashboard shows.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Date, and_, cast, func, select

from app.api.deps import DbSession, require
from app.api.v1.jobs import _visible_jobs
from app.models.job import ObservableType, PluginKind, PluginReport, Verdict
from app.models.user import User
from app.schemas.common import StrictModel
from app.services import reports

router = APIRouter(tags=["intel"])

AnalystUser = Annotated[User, Depends(require("jobs:read"))]


class PayloadQuery(StrictModel):
    """A question about the inside of the provider payloads."""

    plugin_name: str | None = Query(default=None, max_length=64)
    plugin_type: PluginKind | None = None
    observable_type: ObservableType | None = None
    verdict: Verdict | None = None
    # A Postgres JSON path, tested with `@?` against the payload. This is the
    # indexed way to ask, and it is a query language with nothing to execute.
    json_path: str | None = None
    # A plain substring over the serialised payload: unindexed, but it answers
    # "this string is in there somewhere" without knowing the provider's shape.
    contains: str | None = None
    # A path whose value is returned beside each hit, so the answer carries the
    # field that was being looked for rather than only the report that holds it.
    extract: str | None = None
    limit: int = 25
    offset: int = 0


@router.post(
    "/reports/search",
    response_model=dict,
    summary="Search the provider payloads across every job you may see",
)
async def search_payloads(
    payload: PayloadQuery, session: DbSession, user: AnalystUser
) -> dict[str, Any]:
    """Ask a question of what the providers actually returned.

    Examples, as `json_path`:

    - `$.data.attributes.last_analysis_stats.malicious ? (@ > 5)` — VirusTotal
      reports where more than five engines flagged the sample;
    - `$.results[*].alternativetaxonomy.cve[*] ? (@ == "CVE-2021-44228")` —
      Onyphe results mentioning one CVE;
    - `$.**.sha256` — any payload carrying a SHA-256 anywhere.
    """
    return await reports.search(
        session,
        _visible_jobs(user),
        plugin_name=payload.plugin_name,
        plugin_type=payload.plugin_type,
        observable_type=payload.observable_type,
        verdict=payload.verdict,
        json_path=payload.json_path,
        contains=payload.contains,
        extract=payload.extract,
        limit=payload.limit,
        offset=payload.offset,
    )


@router.get("/stats/service", response_model=dict, summary="Service statistics")
async def service_statistics(
    session: DbSession,
    user: AnalystUser,
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict[str, Any]:
    """What the team did over a window, and what it found.

    Every count is restricted to the jobs the caller may see, so the figures an
    analyst reads are the figures they could reach one by one. An administrator
    sees the whole instance.
    """
    since = datetime.now(UTC) - timedelta(days=days)
    visible = _visible_jobs(user).subquery()

    totals = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(visible.c.created_at >= since),
                func.count().filter(visible.c.verdict == Verdict.MALICIOUS),
                func.count().filter(visible.c.verdict == Verdict.SUSPICIOUS),
                func.count().filter(visible.c.parent_job_id.isnot(None)),
                func.count(func.distinct(visible.c.requested_by_name)),
            ).select_from(visible)
        )
    ).one()

    # Who runs analyses, and how much of what they run turns out bad. The ratio
    # is what makes the column useful: volume alone says nothing about hit rate.
    analysts = (
        await session.execute(
            select(
                visible.c.requested_by_name,
                func.count().label("jobs"),
                func.count().filter(visible.c.verdict == Verdict.MALICIOUS).label("malicious"),
                func.count().filter(visible.c.verdict == Verdict.SUSPICIOUS).label("suspicious"),
                func.max(visible.c.created_at).label("last_seen"),
            )
            .select_from(visible)
            .where(visible.c.created_at >= since)
            .group_by(visible.c.requested_by_name)
            .order_by(func.count().desc())
            .limit(50)
        )
    ).all()

    # The day is a cast rather than `date_trunc('day', …)`: the unit would be a
    # bound parameter, and Postgres will not treat two differently-numbered
    # parameters as the same expression, so it rejects the GROUP BY.
    day = cast(visible.c.created_at, Date)
    by_day = (
        await session.execute(
            select(
                day.label("day"),
                func.count().label("jobs"),
                func.count().filter(visible.c.verdict == Verdict.MALICIOUS).label("malicious"),
            )
            .select_from(visible)
            .where(visible.c.created_at >= since)
            .group_by(day)
            .order_by(day)
        )
    ).all()

    by_type = (
        await session.execute(
            select(visible.c.observable_type, func.count())
            .select_from(visible)
            .where(visible.c.created_at >= since)
            .group_by(visible.c.observable_type)
        )
    ).all()

    # Which sources earn their quota: how often each produced a verdict worse
    # than unknown, and how often it failed.
    by_plugin = (
        await session.execute(
            select(
                PluginReport.plugin_name,
                func.count().label("runs"),
                func.count().filter(PluginReport.from_cache.is_(True)).label("from_cache"),
                func.count().filter(PluginReport.status == "FAILED").label("failed"),
                func.count()
                .filter(
                    PluginReport.summary_data["verdict"].astext.in_(
                        [Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value]
                    )
                )
                .label("flagged"),
            )
            .where(
                and_(
                    PluginReport.job_id.in_(select(visible.c.id)),
                    PluginReport.plugin_type == PluginKind.ANALYZER,
                    PluginReport.created_at >= since,
                )
            )
            .group_by(PluginReport.plugin_name)
            .order_by(func.count().desc())
        )
    ).all()

    # The tags are unnested in a subquery first: Postgres will not group by the
    # output alias of a set-returning function.
    unnested = (
        select(func.unnest(visible.c.tags).label("tag"))
        .select_from(visible)
        .where(visible.c.created_at >= since)
        .subquery()
    )
    tags = (
        await session.execute(
            select(unnested.c.tag, func.count().label("jobs"))
            .group_by(unnested.c.tag)
            .order_by(func.count().desc())
            .limit(20)
        )
    ).all()

    statuses = (
        await session.execute(
            select(visible.c.status, func.count()).select_from(visible).group_by(visible.c.status)
        )
    ).all()

    return {
        "window_days": days,
        "totals": {
            "jobs": int(totals[0]),
            "jobs_in_window": int(totals[1]),
            "malicious": int(totals[2]),
            "suspicious": int(totals[3]),
            "from_pivots": int(totals[4]),
            "analysts": int(totals[5]),
        },
        "analysts": [
            {
                "name": row.requested_by_name,
                "jobs": int(row.jobs),
                "malicious": int(row.malicious),
                "suspicious": int(row.suspicious),
                "hit_ratio": round((int(row.malicious) + int(row.suspicious)) / int(row.jobs), 3)
                if row.jobs
                else 0.0,
                "last_seen": row.last_seen,
            }
            for row in analysts
        ],
        "by_day": [
            {"day": row.day, "jobs": int(row.jobs), "malicious": int(row.malicious)}
            for row in by_day
        ],
        "by_observable_type": {row[0].value: int(row[1]) for row in by_type},
        "by_status": {row[0].value: int(row[1]) for row in statuses},
        "by_plugin": [
            {
                "plugin_name": row.plugin_name,
                "runs": int(row.runs),
                "from_cache": int(row.from_cache),
                "failed": int(row.failed),
                "flagged": int(row.flagged),
            }
            for row in by_plugin
        ],
        "top_tags": [{"tag": row.tag, "jobs": int(row.jobs)} for row in tags],
    }
