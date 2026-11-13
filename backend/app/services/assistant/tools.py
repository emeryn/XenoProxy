"""The tools the agent may call, and the rules that bound them.

Three properties hold for every tool here, and they are what make agent mode
something other than a remote shell:

- **Never more than the analyst.** A tool runs against the same query filters
  and the same permission checks the interface uses. A reader asking the model
  to read somebody else's job gets the same nothing they would get by typing
  the URL.
- **Reads by default.** A tool that changes something is marked `writes`, and
  it only exists in the catalogue when the administrator turned writes on. The
  model cannot call a tool it was never offered.
- **Bounded results.** Every result is capped, because an unbounded tool output
  is how a prompt stops fitting and how an injected page gets a megabyte of
  room to work in.

What a tool returns is **data**. It is rendered into the conversation as a tool
result, never merged into the system prompt, so a provider report that contains
instructions is material under analysis rather than a new instruction.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import PERMISSIONS
from app.core.logging import get_logger
from app.models.job import Job, PluginKind
from app.models.user import User
from app.plugins import load_all
from app.plugins.base.registry import describe, iter_plugins
from app.services.observables import classify

logger = get_logger(__name__)

MAX_RESULT_CHARS = 8000
MAX_ROWS = 20


class ToolError(RuntimeError):
    """The tool refused. The message is shown to the model and to the analyst."""


@dataclass(frozen=True)
class ToolContext:
    """Everything a tool is allowed to act on behalf of."""

    session: AsyncSession
    user: User
    # The queue, so a tool that submits work can actually schedule it. Without
    # it a submitted job is written and never run, which looks to the analyst
    # exactly like the scan hanging.
    queue: Any | None = None

    def require(self, permission: str) -> None:
        """Refuse exactly as the API would, with the same words."""
        if permission not in PERMISSIONS.get(self.user.role, frozenset()):
            raise ToolError(
                f"you do not have the '{permission}' permission, so this cannot be done for you"
            )


@dataclass(frozen=True)
class Tool:
    """One callable the model may ask for."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[[ToolContext, dict[str, Any]], Awaitable[Any]]
    writes: bool = False

    def schema(self) -> dict[str, Any]:
        """The declaration both provider APIs accept."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


def _visible_jobs(user: User) -> Any:
    """The same visibility rule the jobs API applies, imported from it."""
    from app.api.v1.jobs import _visible_jobs as visible

    return visible(user)


def _trim(value: Any) -> Any:
    """Cap what goes back into the prompt."""
    rendered = json.dumps(value, default=str)
    if len(rendered) <= MAX_RESULT_CHARS:
        return value
    return {
        "truncated": True,
        "note": f"the result was larger than {MAX_RESULT_CHARS} characters and was cut",
        "preview": rendered[:MAX_RESULT_CHARS],
    }


# --------------------------------------------------------------------------
# Read tools
# --------------------------------------------------------------------------


async def _classify_observable(_context: ToolContext, args: dict[str, Any]) -> Any:
    value = str(args.get("value") or "").strip()
    if not value:
        raise ToolError("a value is required")
    observable = classify(value)
    return {
        "value": observable.value,
        "type": observable.type.value,
        "is_private": observable.is_private,
        "hash_algorithm": observable.hash_algorithm,
    }


async def _search_jobs(context: ToolContext, args: dict[str, Any]) -> Any:
    context.require("jobs:read")
    statement = _visible_jobs(context.user)

    search = str(args.get("observable") or "").strip()
    if search:
        statement = statement.where(Job.observable_value.ilike(f"%{search[:256]}%"))
    verdict = str(args.get("verdict") or "").strip().lower()
    if verdict:
        statement = statement.where(Job.verdict == verdict)

    limit = max(1, min(int(args.get("limit") or 10), MAX_ROWS))
    rows = (
        await context.session.execute(statement.order_by(Job.created_at.desc()).limit(limit))
    ).scalars()
    return _trim(
        [
            {
                "job_id": str(job.id),
                "observable": job.observable_value,
                "type": job.observable_type.value,
                "status": job.status.value,
                "verdict": job.verdict.value,
                "tags": list(job.tags or []),
                "created_at": job.created_at.isoformat() if job.created_at else None,
            }
            for job in rows
        ]
    )


async def _get_job(context: ToolContext, args: dict[str, Any]) -> Any:
    context.require("jobs:read")
    job = await load_visible_job(context, args.get("job_id"))
    return _trim(
        {
            "job_id": str(job.id),
            "observable": job.observable_value,
            "type": job.observable_type.value,
            "status": job.status.value,
            "verdict": job.verdict.value,
            "tlp": job.tlp.value,
            "tags": list(job.tags or []),
            "summary": job.summary or {},
            "reports": [
                {
                    "plugin": report.plugin_name,
                    "type": report.plugin_type.value,
                    "status": report.status.value,
                    "verdict": (report.summary_data or {}).get("verdict"),
                    "headline": (report.summary_data or {}).get("headline"),
                    "error": report.errors,
                }
                for report in job.reports
            ],
        }
    )


async def _get_report(context: ToolContext, args: dict[str, Any]) -> Any:
    """The raw provider payload of one plugin, for a detail the summary lost."""
    context.require("jobs:read")
    job = await load_visible_job(context, args.get("job_id"))
    plugin = str(args.get("plugin") or "").strip()[:64]
    report = next((entry for entry in job.reports if entry.plugin_name == plugin), None)
    if report is None:
        raise ToolError(f"this job has no report from '{plugin}'")
    return _trim(
        {
            "plugin": report.plugin_name,
            "status": report.status.value,
            "summary": report.summary_data or {},
            "raw_output": report.raw_output,
        }
    )


async def _list_plugins(_context: ToolContext, args: dict[str, Any]) -> Any:
    load_all()
    wanted = str(args.get("plugin_type") or "").strip().lower()
    kind = PluginKind(wanted) if wanted in {k.value for k in PluginKind} else None
    return _trim(
        [
            {
                "name": entry["name"],
                "type": entry["plugin_type"],
                "label": entry["label"],
                "supports": entry["supported_types"],
                "description": entry["description"],
            }
            for entry in (describe(cls) for cls in iter_plugins(kind))
        ]
    )


# --------------------------------------------------------------------------
# Write tools
# --------------------------------------------------------------------------


async def _tag_job(context: ToolContext, args: dict[str, Any]) -> Any:
    context.require("jobs:tag")
    job = await load_visible_job(context, args.get("job_id"))
    tags = [str(tag).strip().lower()[:64] for tag in (args.get("tags") or []) if str(tag).strip()]
    if not tags:
        raise ToolError("at least one tag is required")
    job.tags = sorted(set(list(job.tags or []) + tags))[:20]
    await context.session.flush()
    return {"job_id": str(job.id), "tags": job.tags}


async def _submit_scan(context: ToolContext, args: dict[str, Any]) -> Any:
    context.require("jobs:write")
    from app.services import orchestrator

    observable = str(args.get("observable") or "").strip()
    if not observable:
        raise ToolError("an observable is required")

    try:
        request = await orchestrator.resolve_selection(
            context.session,
            raw_observable=observable,
            playbook_name=str(args.get("playbook") or "") or None,
            tags=["assistant"],
        )
    except Exception as exc:
        raise ToolError(str(exc)) from exc

    job = await orchestrator.create_job(
        context.session,
        request,
        requested_by=context.user,
        requested_by_name=context.user.username,
    )
    # Committed before it is queued: the worker reads the row in its own
    # session, so queueing an uncommitted job races it to a job that is not
    # there yet.
    await context.session.commit()

    if context.queue is None:
        # Say so rather than reporting success. A job nothing will run is the
        # one failure the analyst cannot see from the answer.
        return {
            "job_id": str(job.id),
            "observable": job.observable_value,
            "error": "the job was created but could not be queued, so it will not run",
        }

    await context.queue.enqueue_job("run_job", str(job.id))
    return {
        "job_id": str(job.id),
        "observable": job.observable_value,
        "analyzers": list(job.requested_analyzers or []),
        "note": "the job is queued; its result is not available yet",
    }


async def load_visible_job(context: ToolContext, raw_id: Any) -> Job:
    try:
        job_id = uuid.UUID(str(raw_id))
    except (TypeError, ValueError) as exc:
        raise ToolError("a job identifier is required") from exc

    job = (
        await context.session.execute(_visible_jobs(context.user).where(Job.id == job_id))
    ).scalar_one_or_none()
    if job is None:
        # Exactly what the API answers: a job the analyst may not see does not
        # exist, and the model learns nothing from the difference.
        raise ToolError("no such job")
    return job


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------

_STRING = {"type": "string"}

ALL_TOOLS: tuple[Tool, ...] = (
    Tool(
        name="classify_observable",
        description=(
            "Detect the type of an observable (ip, domain, url, hash, generic) and refang it. "
            "Use it before talking about what XenoProxy would run on a value."
        ),
        parameters={
            "type": "object",
            "properties": {"value": _STRING},
            "required": ["value"],
        },
        handler=_classify_observable,
    ),
    Tool(
        name="search_jobs",
        description=(
            "Find recent jobs the analyst may see. Filter by a fragment of the observable "
            "and by verdict (clean, unknown, suspicious, malicious)."
        ),
        parameters={
            "type": "object",
            "properties": {
                "observable": _STRING,
                "verdict": _STRING,
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_ROWS},
            },
        },
        handler=_search_jobs,
    ),
    Tool(
        name="get_job",
        description="Read one job: its verdict, its aggregated summary and every plugin report.",
        parameters={
            "type": "object",
            "properties": {"job_id": _STRING},
            "required": ["job_id"],
        },
        handler=_get_job,
    ),
    Tool(
        name="get_report",
        description=(
            "Read the raw provider payload of one plugin of a job, when the summary is not "
            "enough to answer."
        ),
        parameters={
            "type": "object",
            "properties": {"job_id": _STRING, "plugin": _STRING},
            "required": ["job_id", "plugin"],
        },
        handler=_get_report,
    ),
    Tool(
        name="list_plugins",
        description=(
            "List the analyzers, connectors and pivots this instance has, and what they support."
        ),
        parameters={
            "type": "object",
            "properties": {"plugin_type": _STRING},
        },
        handler=_list_plugins,
    ),
    Tool(
        name="tag_job",
        description="Add tags to a job, so it can be found later.",
        parameters={
            "type": "object",
            "properties": {
                "job_id": _STRING,
                "tags": {"type": "array", "items": _STRING},
            },
            "required": ["job_id", "tags"],
        },
        handler=_tag_job,
        writes=True,
    ),
    Tool(
        name="submit_scan",
        description=(
            "Submit a new scan. The observable is classified automatically; a playbook name "
            "may be given. Spends provider quota."
        ),
        parameters={
            "type": "object",
            "properties": {"observable": _STRING, "playbook": _STRING},
            "required": ["observable"],
        },
        handler=_submit_scan,
        writes=True,
    ),
)

BY_NAME = {tool.name: tool for tool in ALL_TOOLS}


def catalogue(*, allow_writes: bool) -> list[Tool]:
    """The tools offered this turn. A write tool absent here cannot be called."""
    return [tool for tool in ALL_TOOLS if allow_writes or not tool.writes]


async def run(
    context: ToolContext, name: str, arguments: dict[str, Any], *, allow_writes: bool
) -> Any:
    """Run one tool, after checking it was actually on offer."""
    tool = BY_NAME.get(name)
    if tool is None:
        raise ToolError(f"there is no tool named '{name}'")
    if tool.writes and not allow_writes:
        # The model asked for something it was not offered. Refusing on the
        # catalogue alone would be trusting the prompt to be the boundary.
        raise ToolError(f"'{name}' changes data and write actions are disabled")

    logger.info(
        "assistant_tool_call",
        tool=name,
        actor=context.user.username,
        writes=tool.writes,
        arguments=sorted(arguments),
    )
    return await tool.handler(context, arguments)
