"""Reading and querying what the providers actually returned.

A report keeps the provider's answer whole, in `raw_output`. That is the point:
an analyst who wants to know what Onyphe saw, or which of VirusTotal's eighty
engines disagreed, needs the payload and not a summary of it. Two problems
follow, and this module is both answers.

**Reading it.** A single VirusTotal file report runs to hundreds of kilobytes.
Sending that to a browser to look at one field is waste, so a path selects a
subtree and the caller gets only that.

**Finding it.** "Which jobs ever saw this certificate fingerprint" is a question
about the inside of the payloads, not about the summaries. Postgres answers it
with a JSON path over a GIN index, and the path is a query language with no way
to execute anything — unlike handing a text filter to `LIKE`, it stays indexed
and it stays bounded.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, Text, cast, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.models.job import Job, ObservableType, PluginKind, PluginReport, ReportStatus, Verdict

logger = get_logger(__name__)

MAX_PATH_LENGTH = 512
MAX_JSON_PATH_LENGTH = 1024
MAX_ROWS = 100
# A path segment is a key, or an index in brackets. Anything else is refused
# rather than guessed, so a typo is a clear error and not a silent empty result.
_SEGMENT = re.compile(r"^[A-Za-z0-9_.\-]+$")


@dataclass(frozen=True)
class RawSelection:
    """A subtree of one report's payload, and where it came from."""

    plugin_name: str
    path: str
    found: bool
    value: Any
    size_bytes: int


def parse_path(raw: str) -> list[str | int]:
    """Turn `data.attributes.last_analysis_results[0]` into a list of steps.

    Dots separate keys and brackets index arrays. A segment that is neither is
    refused: the alternative is to treat it as a key that will never match, and
    an empty answer that is really a typo is the worst outcome.
    """
    if len(raw) > MAX_PATH_LENGTH:
        raise ValidationFailedError(f"The path exceeds {MAX_PATH_LENGTH} characters.")

    steps: list[str | int] = []
    for part in raw.split("."):
        if not part:
            continue
        head, *indexes = part.split("[")
        if head:
            if not _SEGMENT.match(head):
                raise ValidationFailedError(f"'{head}' is not a usable path segment.")
            steps.append(head)
        for index in indexes:
            digits = index.rstrip("]")
            if not digits.isdigit():
                raise ValidationFailedError(f"'[{index}' is not an array index.")
            steps.append(int(digits))
    return steps


def select_path(payload: Any, raw_path: str) -> RawSelection:
    """Walk a payload down a path, reporting plainly when it does not exist."""
    steps = parse_path(raw_path)
    current = payload
    for step in steps:
        if isinstance(step, int):
            if not isinstance(current, list) or step >= len(current):
                return RawSelection("", raw_path, False, None, 0)
            current = current[step]
        else:
            if not isinstance(current, dict) or step not in current:
                return RawSelection("", raw_path, False, None, 0)
            current = current[step]
    return RawSelection("", raw_path, True, current, _size(current))


def _size(value: Any) -> int:
    import json

    try:
        return len(json.dumps(value, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def describe_payload(payload: Any, *, depth: int = 2) -> Any:
    """A shallow map of a payload, so a caller can see what to ask for.

    A provider answer is often a deep object an analyst has never seen. Showing
    the shape — keys, types, list lengths — is what lets them build a path
    without downloading the whole thing first.
    """
    if depth <= 0:
        return _kind(payload)
    if isinstance(payload, dict):
        return {key: describe_payload(value, depth=depth - 1) for key, value in payload.items()}
    if isinstance(payload, list):
        shape = describe_payload(payload[0], depth=depth - 1) if payload else None
        return {"type": "array", "length": len(payload), "items": shape}
    return _kind(payload)


def _kind(value: Any) -> Any:
    if isinstance(value, dict):
        return {"type": "object", "keys": sorted(value)[:50]}
    if isinstance(value, list):
        return {"type": "array", "length": len(value)}
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if value is None:
        return "null"
    rendered = str(value)
    return {"type": "string", "length": len(rendered), "sample": rendered[:120]}


# --------------------------------------------------------------------------
# Reading one report
# --------------------------------------------------------------------------


async def load_report(
    session: AsyncSession, visible: Select[tuple[Job]], job_id: uuid.UUID, plugin_name: str
) -> PluginReport:
    """One report of a job the caller may see."""
    job = (await session.execute(visible.where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        raise NotFoundError("The job does not exist.")
    report = next((entry for entry in job.reports if entry.plugin_name == plugin_name[:64]), None)
    if report is None:
        raise NotFoundError("The report does not exist.")
    return report


def raw_view(report: PluginReport, *, path: str | None, shape: bool) -> dict[str, Any]:
    """What the raw endpoint answers: the payload, a subtree, or its shape."""
    payload = report.raw_output
    base: dict[str, Any] = {
        "plugin_name": report.plugin_name,
        "plugin_type": report.plugin_type.value,
        "status": report.status.value,
        "observable_value": report.observable_value,
        "size_bytes": _size(payload),
        "from_cache": report.from_cache,
        "finished_at": report.finished_at,
    }
    if payload is None:
        return {**base, "found": False, "value": None, "note": "this plugin returned no payload"}
    if shape:
        return {**base, "shape": describe_payload(payload)}
    if path:
        selection = select_path(payload, path)
        return {
            **base,
            "path": selection.path,
            "found": selection.found,
            "value": selection.value,
            "selected_bytes": selection.size_bytes,
        }
    return {**base, "found": True, "value": payload}


# --------------------------------------------------------------------------
# Querying across reports
# --------------------------------------------------------------------------


def _validate_json_path(expression: str) -> str:
    """Bound the expression. Postgres validates the syntax itself.

    A JSON path cannot call a function or reach another table, so the risk is
    not injection but cost: an unbounded one over every payload. The length cap
    and the row limit are what keep the query answerable.
    """
    expression = expression.strip()
    if not expression:
        raise ValidationFailedError("A JSON path is required.")
    if len(expression) > MAX_JSON_PATH_LENGTH:
        raise ValidationFailedError(f"The JSON path exceeds {MAX_JSON_PATH_LENGTH} characters.")
    return expression


async def search(
    session: AsyncSession,
    visible: Select[tuple[Job]],
    *,
    plugin_name: str | None = None,
    plugin_type: PluginKind | None = None,
    observable_type: ObservableType | None = None,
    verdict: Verdict | None = None,
    json_path: str | None = None,
    contains: str | None = None,
    extract: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    """Find reports by what their payload contains.

    `json_path` is a Postgres JSON path tested against the payload, which is the
    indexed way to ask the question. `contains` is a plain substring over the
    serialised payload: slower and unindexed, but it answers "this string is in
    there somewhere" without knowing the provider's shape.
    """
    if not (json_path or contains or plugin_name or plugin_type or observable_type or verdict):
        raise ValidationFailedError(
            "Give at least one filter: a plugin, an observable type, a verdict, "
            "a JSON path or a substring."
        )

    visible_ids = visible.with_only_columns(Job.id).subquery()
    statement = (
        select(PluginReport, Job)
        .join(Job, Job.id == PluginReport.job_id)
        .where(PluginReport.job_id.in_(select(visible_ids.c.id)))
        .where(PluginReport.raw_output.isnot(None))
    )

    if plugin_name:
        statement = statement.where(PluginReport.plugin_name == plugin_name[:64])
    if plugin_type:
        statement = statement.where(PluginReport.plugin_type == plugin_type)
    if observable_type:
        statement = statement.where(PluginReport.observable_type == observable_type)
    if verdict:
        statement = statement.where(Job.verdict == verdict)

    if json_path:
        expression = _validate_json_path(json_path)
        # `@?` is the indexed existence test; the path is bound as a parameter.
        statement = statement.where(
            text("plugin_reports.raw_output @? CAST(:json_path AS jsonpath)").bindparams(
                json_path=expression
            )
        )
    if contains:
        needle = contains.strip()[:256]
        if needle:
            # Unindexed by nature: the payload is serialised to compare it. It
            # is offered anyway because it answers "this string is in there
            # somewhere" without knowing the provider's shape.
            statement = statement.where(cast(PluginReport.raw_output, Text).ilike(f"%{needle}%"))

    bounded = max(1, min(limit, MAX_ROWS))
    try:
        total = (
            await session.execute(select(func.count()).select_from(statement.subquery()))
        ).scalar_one()
        rows = (
            await session.execute(
                statement.order_by(PluginReport.created_at.desc())
                .offset(max(0, offset))
                .limit(bounded)
            )
        ).all()
    except DBAPIError as exc:
        # A malformed JSON path is a user error, not a server fault, and both
        # statements carry the same predicate so either can be the one refused.
        await session.rollback()
        raise ValidationFailedError(
            f"The query was refused by the database: {_db_reason(exc)}"
        ) from exc

    items: list[dict[str, Any]] = []
    for report, job in rows:
        item: dict[str, Any] = {
            "report_id": str(report.id),
            "job_id": str(job.id),
            "plugin_name": report.plugin_name,
            "plugin_type": report.plugin_type.value,
            "status": report.status.value,
            "observable_value": report.observable_value,
            "observable_type": report.observable_type.value,
            "job_verdict": job.verdict.value,
            "size_bytes": _size(report.raw_output),
            "created_at": report.created_at,
        }
        if extract:
            selection = select_path(report.raw_output, extract)
            item["extract"] = {
                "path": selection.path,
                "found": selection.found,
                "value": selection.value,
            }
        items.append(item)

    return {"items": items, "total": int(total), "limit": bounded, "offset": max(0, offset)}


def _db_reason(exc: DBAPIError) -> str:
    """The database's own message, without the statement it came from."""
    original = getattr(exc, "orig", None)
    return str(original or exc).splitlines()[0][:300]


async def inventory(
    session: AsyncSession, visible: Select[tuple[Job]], job_id: uuid.UUID
) -> list[dict[str, Any]]:
    """What a job has to read, and how large each piece is.

    Shown before anything is downloaded, so an analyst picks the report worth
    opening instead of loading every payload to find out.
    """
    job = (await session.execute(visible.where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        raise NotFoundError("The job does not exist.")
    return [
        {
            "plugin_name": report.plugin_name,
            "plugin_type": report.plugin_type.value,
            "status": report.status.value,
            "has_payload": report.raw_output is not None,
            "size_bytes": _size(report.raw_output),
            "top_level_keys": sorted(report.raw_output)[:50]
            if isinstance(report.raw_output, dict)
            else [],
            "from_cache": report.from_cache,
        }
        for report in sorted(
            job.reports, key=lambda entry: (entry.plugin_type.value, entry.plugin_name)
        )
        if report.status is not ReportStatus.PENDING
    ]
