"""Job orchestration.

A submission is resolved into a concrete plugin selection, persisted with one
PENDING report per plugin, then handed to the worker. The worker runs the job in
three phases, which is the IntelOwl lifecycle:

1. **Analysis** — every selected analyzer runs concurrently, each in its own
   session, consulting the cache first. A failing analyzer degrades the job to
   PARTIAL_FAILURE; it never aborts the others.
2. **Connectors** — once a verdict has been aggregated, every selected connector
   publishes the finished result. This phase exists separately because a
   connector run during phase 1 would only ever see an empty verdict.
3. **Pivots** — every selected pivot inspects the finished job and names the
   observables worth analysing next. Each becomes a child job at depth + 1,
   bounded by the configured depth and fan-out.

Selection follows three rules, in order:

1. An explicit list of plugins, or a playbook, is honoured.
2. With neither, every *analyzer* that can run is selected, which is what makes
   the default scan automatic. Connectors and pivots are never auto-selected:
   one publishes to a third party and the other creates work, so both require
   an explicit choice.
3. Whatever the source of the list, a plugin is dropped when it is disabled,
   does not support the observable type, lacks a required credential, or is not
   allowed at the job's TLP. The reason is reported back to the caller.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.models.job import (
    Job,
    JobOrigin,
    JobStatus,
    ObservableType,
    PluginKind,
    PluginReport,
    ReportStatus,
    ScanMode,
    Tlp,
)
from app.models.playbook import Playbook
from app.models.user import User
from app.plugins import load_all
from app.plugins.base.connector import BaseConnector
from app.plugins.base.pivot import BasePivot
from app.plugins.base.plugin import JobContext, PluginResult, ReportView, SampleAccess
from app.plugins.base.registry import get_plugin, iter_plugins
from app.repositories import plugin_configs
from app.services import (
    cache,
    job_control,
    plugin_runtime,
    secrets_vault,
    settings_store,
    uploads,
    verdict,
)
from app.services import tlp as tlp_policy
from app.services.observables import Observable, classify, ensure_scannable

logger = get_logger(__name__)

SessionFactory = async_sessionmaker[AsyncSession]
Enqueue = Callable[[uuid.UUID], Awaitable[None]]


@dataclass(frozen=True)
class SkippedPlugin:
    """A plugin that was asked for, or auto-selected, but cannot run."""

    name: str
    plugin_type: PluginKind
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "type": self.plugin_type.value, "reason": self.reason}


@dataclass(frozen=True)
class PluginSelection:
    """The plugins of each type a job will run, in lifecycle order."""

    analyzers: list[str] = field(default_factory=list)
    connectors: list[str] = field(default_factory=list)
    pivots: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.analyzers or self.connectors or self.pivots)

    def count(self) -> int:
        return len(self.analyzers) + len(self.connectors) + len(self.pivots)

    def named(self, plugin_type: PluginKind) -> list[str]:
        return {
            PluginKind.ANALYZER: self.analyzers,
            PluginKind.CONNECTOR: self.connectors,
            PluginKind.PIVOT: self.pivots,
        }[plugin_type]


@dataclass(frozen=True)
class JobRequest:
    """A validated submission ready to be persisted."""

    observable: Observable
    selection: PluginSelection
    playbook_name: str | None
    tags: list[str]
    tlp: Tlp
    scan_mode: ScanMode
    scan_check_minutes: int | None
    runtime_configuration: dict[str, Any]
    skipped: list[SkippedPlugin] = field(default_factory=list)
    auto_selected: bool = False
    # Pivot lineage, set only when this job was derived from another.
    parent_job_id: uuid.UUID | None = None
    pivot_name: str | None = None
    depth: int = 0

    @property
    def force_rescan(self) -> bool:
        return self.scan_mode is ScanMode.FORCE_NEW


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------


async def candidate_plugins(
    session: AsyncSession,
    *,
    plugin_type: PluginKind,
    observable_type: ObservableType,
    job_tlp: Tlp,
) -> tuple[list[str], list[SkippedPlugin]]:
    """Split every plugin of one type into runnable and skipped.

    This is the single place that decides whether a plugin can run, so the scan
    page, the API preview and job creation never disagree.
    """
    load_all()
    configs = await plugin_configs.list_all(session)
    stored = await secrets_vault.configured_plugins(session)

    runnable: list[str] = []
    skipped: list[SkippedPlugin] = []

    for cls in iter_plugins(plugin_type):
        if not cls.supports(observable_type):
            skipped.append(
                SkippedPlugin(
                    cls.name,
                    plugin_type,
                    f"does not support a {observable_type.value} observable",
                )
            )
            continue

        config = configs.get(cls.name)
        if config is None or not config.enabled:
            skipped.append(SkippedPlugin(cls.name, plugin_type, "disabled"))
            continue

        max_tlp = config.max_tlp
        if not tlp_policy.allows(job_tlp, max_tlp):
            skipped.append(
                SkippedPlugin(cls.name, plugin_type, tlp_policy.refusal_reason(job_tlp, max_tlp))
            )
            continue

        missing = sorted(set(cls.required_secret_names()) - stored.get(cls.name, set()))
        if missing:
            skipped.append(
                SkippedPlugin(cls.name, plugin_type, f"missing credential: {', '.join(missing)}")
            )
            continue

        runnable.append(cls.name)

    return runnable, skipped


async def candidate_analyzers(
    session: AsyncSession,
    *,
    observable_type: ObservableType,
    job_tlp: Tlp,
) -> tuple[list[str], list[SkippedPlugin]]:
    """Analyzer-only view of `candidate_plugins`, used by the scan preview."""
    return await candidate_plugins(
        session,
        plugin_type=PluginKind.ANALYZER,
        observable_type=observable_type,
        job_tlp=job_tlp,
    )


async def _load_playbook(session: AsyncSession, name: str, observable: Observable) -> Playbook:
    playbook = (
        await session.execute(select(Playbook).where(Playbook.name == name))
    ).scalar_one_or_none()
    if playbook is None or not playbook.enabled:
        raise NotFoundError(f"Unknown playbook '{name}'.", code="PLAYBOOK_NOT_FOUND")
    if playbook.observable_types and observable.type.value not in playbook.observable_types:
        raise ValidationFailedError(
            f"Playbook '{name}' does not apply to a {observable.type.value} observable."
        )
    return playbook


def _partition_requested(
    requested: list[str],
) -> tuple[dict[PluginKind, list[str]], list[SkippedPlugin]]:
    """Group explicitly requested plugin names by their declared type.

    Accepting one flat list from the caller and sorting it here is what lets an
    API client name `opencti_export` alongside `shodan` without having to know
    which phase each belongs to.
    """
    grouped: dict[PluginKind, list[str]] = {kind: [] for kind in PluginKind}
    unknown: list[SkippedPlugin] = []
    for name in requested:
        try:
            cls = get_plugin(name)
        except NotFoundError:
            unknown.append(SkippedPlugin(name, PluginKind.ANALYZER, "unknown plugin"))
            continue
        grouped[cls.plugin_type].append(name)
    return grouped, unknown


async def resolve_selection(
    session: AsyncSession,
    *,
    raw_observable: str,
    analyzers: list[str] | None = None,
    connectors: list[str] | None = None,
    pivots: list[str] | None = None,
    plugins: list[str] | None = None,
    playbook_name: str | None = None,
    tags: list[str] | None = None,
    tlp: Tlp | None = None,
    scan_mode: ScanMode | None = None,
    scan_check_minutes: int | None = None,
    runtime_configuration: dict[str, Any] | None = None,
    parent_job_id: uuid.UUID | None = None,
    pivot_name: str | None = None,
    depth: int = 0,
) -> JobRequest:
    """Classify the observable and resolve which plugins will actually run.

    `plugins` is a type-agnostic list sorted by declared type; `analyzers`,
    `connectors` and `pivots` are the explicit per-type lists. Both forms may be
    used together, which is what keeps the scan form and scripted clients on the
    same endpoint.
    """
    load_all()
    settings = get_settings()
    stored_settings = await settings_store.load_all(session)

    effective_tlp = tlp or Tlp(stored_settings["default_tlp"])
    effective_mode = scan_mode or ScanMode(stored_settings["default_scan_mode"])
    if scan_check_minutes is None:
        configured = int(stored_settings["default_scan_check_minutes"])
        scan_check_minutes = configured or None

    allow_private = bool(stored_settings["allow_private_targets"]) or settings.allow_private_targets
    observable = classify(raw_observable)
    ensure_scannable(observable, allow_private=allow_private)

    # What the caller asked for, grouped by type.
    grouped, rejected = _partition_requested(list(plugins or []))
    grouped[PluginKind.ANALYZER].extend(analyzers or [])
    grouped[PluginKind.CONNECTOR].extend(connectors or [])
    grouped[PluginKind.PIVOT].extend(pivots or [])

    if playbook_name:
        playbook = await _load_playbook(session, playbook_name, observable)
        # A playbook supplies the default list of each phase, and an explicit
        # list for a phase replaces it rather than adding to it. Unioning them
        # would make a playbook's plugins impossible to remove: the interface
        # pre-selects what the playbook contains, and unticking one has to
        # mean it does not run.
        if not grouped[PluginKind.ANALYZER]:
            grouped[PluginKind.ANALYZER].extend(playbook.analyzers or [])
        if not grouped[PluginKind.CONNECTOR]:
            grouped[PluginKind.CONNECTOR].extend(playbook.connectors or [])
        if not grouped[PluginKind.PIVOT]:
            grouped[PluginKind.PIVOT].extend(playbook.pivots or [])

    auto_selected = False
    selected: dict[PluginKind, list[str]] = {kind: [] for kind in PluginKind}

    for kind in PluginKind:
        runnable, skipped = await candidate_plugins(
            session, plugin_type=kind, observable_type=observable.type, job_tlp=effective_tlp
        )
        runnable_set = set(runnable)
        skipped_by_name = {entry.name: entry for entry in skipped}

        wanted = list(dict.fromkeys(name for name in grouped[kind] if name))

        # Auto-selection covers analyzers only: a connector publishes outside
        # the instance and a pivot creates work, so neither may be implied.
        if (
            kind is PluginKind.ANALYZER
            and not wanted
            and not grouped[PluginKind.CONNECTOR]
            and not grouped[PluginKind.PIVOT]
            and not playbook_name
        ):
            if not bool(stored_settings["auto_select_analyzers"]):
                raise ValidationFailedError("Select at least one analyzer or a playbook.")
            wanted = list(runnable)
            auto_selected = True

        for name in wanted:
            if name in runnable_set:
                selected[kind].append(name)
            elif name in skipped_by_name:
                rejected.append(skipped_by_name[name])
            else:
                rejected.append(SkippedPlugin(name, kind, "not available"))

    selection = PluginSelection(
        analyzers=selected[PluginKind.ANALYZER],
        connectors=selected[PluginKind.CONNECTOR],
        pivots=selected[PluginKind.PIVOT],
    )

    if selection.is_empty():
        detail = "; ".join(f"{entry.name}: {entry.reason}" for entry in rejected) or "no candidate"
        raise ValidationFailedError(f"None of the selected plugins can run. {detail}")
    if not selection.analyzers:
        raise ValidationFailedError(
            "A job needs at least one analyzer: connectors and pivots act on an analysis."
        )

    maximum = int(stored_settings["max_analyzers_per_job"])
    if len(selection.analyzers) > maximum:
        raise ValidationFailedError(f"A job cannot run more than {maximum} analyzers.")

    overrides = _validate_runtime_configuration(runtime_configuration, selection)
    normalised_tags = sorted({tag.strip().lower()[:64] for tag in tags or [] if tag.strip()})

    return JobRequest(
        observable=observable,
        selection=selection,
        playbook_name=playbook_name,
        tags=normalised_tags,
        tlp=effective_tlp,
        scan_mode=effective_mode,
        scan_check_minutes=scan_check_minutes,
        runtime_configuration=overrides,
        skipped=rejected,
        auto_selected=auto_selected,
        parent_job_id=parent_job_id,
        pivot_name=pivot_name,
        depth=depth,
    )


def _validate_runtime_configuration(
    runtime_configuration: dict[str, Any] | None, selection: PluginSelection
) -> dict[str, Any]:
    """Keep only options the targeted plugins actually declare."""
    if not runtime_configuration:
        return {}

    in_job = set(selection.analyzers) | set(selection.connectors) | set(selection.pivots)
    overrides: dict[str, Any] = {}
    for plugin_name, options in runtime_configuration.items():
        if plugin_name not in in_job:
            raise ValidationFailedError(
                f"Runtime configuration targets '{plugin_name}', which is not in this job."
            )
        if not isinstance(options, dict):
            raise ValidationFailedError(
                f"Runtime configuration for '{plugin_name}' must be an object."
            )
        declared = set(get_plugin(plugin_name).options_schema or {})
        unknown = set(options) - declared
        if unknown:
            raise ValidationFailedError(
                f"Unknown option(s) for '{plugin_name}': {', '.join(sorted(unknown))}."
            )
        overrides[plugin_name] = options
    return overrides


async def create_job(
    session: AsyncSession,
    request: JobRequest,
    *,
    requested_by: User | None,
    requested_by_name: str,
    origin: JobOrigin = JobOrigin.UI,
) -> Job:
    """Persist the job and one PENDING report per selected plugin."""
    visible_to = (
        list(requested_by.group_ids)
        if requested_by is not None and tlp_policy.restricts_visibility(request.tlp)
        else []
    )

    job = Job(
        observable_value=request.observable.value,
        observable_type=request.observable.type,
        status=JobStatus.PENDING,
        tags=request.tags,
        playbook_name=request.playbook_name,
        requested_analyzers=request.selection.analyzers,
        requested_connectors=request.selection.connectors,
        requested_pivots=request.selection.pivots,
        force_rescan=request.scan_mode is ScanMode.FORCE_NEW,
        tlp=request.tlp,
        scan_mode=request.scan_mode,
        scan_check_minutes=request.scan_check_minutes,
        runtime_configuration=request.runtime_configuration,
        visible_to_group_ids=visible_to,
        parent_job_id=request.parent_job_id,
        pivot_name=request.pivot_name,
        depth=request.depth,
        origin=origin,
        requested_by_id=requested_by.id if requested_by else None,
        requested_by_name=requested_by_name,
        summary={"skipped_plugins": [entry.as_dict() for entry in request.skipped]},
    )
    session.add(job)
    await session.flush()

    for kind in PluginKind:
        for name in request.selection.named(kind):
            session.add(
                PluginReport(
                    job_id=job.id,
                    plugin_name=name,
                    plugin_type=kind,
                    status=ReportStatus.PENDING,
                    observable_value=request.observable.value,
                    observable_type=request.observable.type,
                    summary_data={},
                )
            )
    await session.flush()
    return job


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


async def run_job(
    session_factory: SessionFactory,
    job_id: uuid.UUID,
    *,
    store: job_control.KeyValueStore | None = None,
    enqueue: Enqueue | None = None,
) -> None:
    """Execute a job's three phases in order.

    `store` is the queue client used to poll for a cancellation request;
    `enqueue` schedules the child jobs the pivot phase creates. Both are
    optional so the orchestrator stays callable from a test without a worker.
    """
    load_all()

    async with session_factory() as session:
        job = (await session.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
        if job is None:
            logger.warning("run_job_missing", job_id=str(job_id))
            return

        job.status = JobStatus.RUNNING
        job.started_at = datetime.now(UTC)
        plan = _JobPlan.from_job(job)
        await session.commit()

    if await job_control.is_kill_requested(store, job_id):
        await _kill_pending(session_factory, job_id)
        await _finalise(session_factory, job_id, store=store)
        return

    await _run_analysis_phase(session_factory, plan, store=store)

    # The verdict has to exist before the connectors and pivots see the job.
    await _aggregate(session_factory, job_id, finished=False)

    if not await job_control.is_kill_requested(store, job_id):
        snapshot = await _build_context(session_factory, job_id)
        if snapshot is not None:
            context, analysis_status = snapshot
            await _run_connector_phase(session_factory, plan, context, analysis_status, store=store)
            await _run_pivot_phase(session_factory, plan, context, store=store, enqueue=enqueue)

    if await job_control.is_kill_requested(store, job_id):
        await _kill_pending(session_factory, job_id)

    await _finalise(session_factory, job_id, store=store)


@dataclass(frozen=True)
class _JobPlan:
    """The immutable facts a phase needs, read once so sessions stay short."""

    job_id: uuid.UUID
    observable: Observable
    force_rescan: bool
    overrides: dict[str, Any]
    check_minutes: int | None
    tlp: Tlp
    depth: int
    requested_by_id: uuid.UUID | None
    requested_by_name: str
    # Where the submitted sample lives, when the job carries one.
    file_path: str | None = None
    file_name: str | None = None

    @classmethod
    def from_job(cls, job: Job) -> _JobPlan:
        return cls(
            job_id=job.id,
            observable=Observable(
                value=job.observable_value,
                type=job.observable_type,
                hash_algorithm=_hash_algorithm(job),
            ),
            force_rescan=job.scan_mode is ScanMode.FORCE_NEW,
            overrides=dict(job.runtime_configuration or {}),
            check_minutes=job.scan_check_minutes,
            tlp=job.tlp,
            depth=job.depth,
            file_path=job.file_path,
            file_name=job.file_name,
            requested_by_id=job.requested_by_id,
            requested_by_name=job.requested_by_name,
        )


async def _pending_reports(
    session_factory: SessionFactory, job_id: uuid.UUID, plugin_type: PluginKind
) -> list[tuple[uuid.UUID, str]]:
    """Report ids still to run for one phase."""
    async with session_factory() as session:
        rows = (
            await session.execute(
                select(PluginReport.id, PluginReport.plugin_name).where(
                    PluginReport.job_id == job_id,
                    PluginReport.plugin_type == plugin_type,
                    PluginReport.status.in_([ReportStatus.PENDING, ReportStatus.RUNNING]),
                )
            )
        ).all()
    return [(row[0], row[1]) for row in rows]


async def _run_analysis_phase(
    session_factory: SessionFactory,
    plan: _JobPlan,
    *,
    store: job_control.KeyValueStore | None,
) -> None:
    """Run every pending analyzer concurrently.

    Each analyzer runs in its own session: an AsyncSession cannot be shared
    between concurrent tasks, and a shared one would make all but the first
    analyzer fail on a connection that is already in use.
    """
    pending = await _pending_reports(session_factory, plan.job_id, PluginKind.ANALYZER)
    if not pending:
        return

    settings = get_settings()
    semaphore = asyncio.Semaphore(max(1, settings.analyzer_max_concurrency))

    async def execute(report_id: uuid.UUID, plugin_name: str) -> None:
        async with semaphore, session_factory() as session:
            if await job_control.is_kill_requested(store, plan.job_id):
                await _mark(session, report_id, ReportStatus.KILLED, "Stopped before it started.")
                return
            try:
                await _run_analyzer(
                    session, plan=plan, report_id=report_id, plugin_name=plugin_name
                )
            except Exception as exc:
                logger.error("report_crashed", plugin=plugin_name, error=str(exc))
                await session.rollback()
                await _mark(
                    session, report_id, ReportStatus.FAILED, f"Internal error: {type(exc).__name__}"
                )

    await asyncio.gather(*(execute(report_id, name) for report_id, name in pending))



async def _sample_access(session: AsyncSession, plan: _JobPlan) -> SampleAccess | None:
    """How this job's plugins may reach the submitted file, if at all.

    The hashes always travel: they identify the sample without disclosing it.
    The bytes travel only where an administrator has allowed a file to be sent
    to a provider, which is off by default — a file under investigation may be
    confidential, and sending it out cannot be taken back.
    """
    if not plan.file_path:
        return None

    stored = await settings_store.load_all(session)
    allowed = bool(stored.get("send_files_to_providers"))

    def read() -> bytes | None:
        return uploads.read(plan.file_path or "")

    return SampleAccess(
        sha256=plan.observable.value,
        file_name=plan.file_name or "",
        read_bytes=read if allowed else None,
    )

async def _run_analyzer(
    session: AsyncSession,
    *,
    plan: _JobPlan,
    report_id: uuid.UUID,
    plugin_name: str,
) -> None:
    """Run a single analyzer, consulting the cache first unless a rescan is forced."""
    report = await _load_report(session, report_id)
    if report is None:
        return

    built = await plugin_runtime.build(
        session,
        plugin_name,
        expected_type=PluginKind.ANALYZER,
        user_id=plan.requested_by_id,
        runtime_options=plan.overrides.get(plugin_name),
        job_tlp=plan.tlp,
        sample=await _sample_access(session, plan),
    )
    if built is None:
        report.status = ReportStatus.SKIPPED
        report.errors = "The analyzer is disabled."
        report.finished_at = datetime.now(UTC)
        await session.commit()
        return

    cache_ttl = plan.check_minutes * 60 if plan.check_minutes else built.cache_ttl_seconds

    if not plan.force_rescan:
        cached = await cache.find_fresh_report(
            session,
            plugin_name=plugin_name,
            observable_value=plan.observable.value,
            observable_type=plan.observable.type,
            ttl_seconds=cache_ttl,
        )
        if cached is not None and cached.id != report.id:
            cache.clone_into_report(cached, report)
            await session.commit()
            logger.info("report_from_cache", plugin=plugin_name, job_id=str(plan.job_id))
            return

    report.status = ReportStatus.RUNNING
    await session.commit()

    result = await built.plugin.execute(plan.observable)
    await _store_result(session, report_id, result)


async def _build_context(
    session_factory: SessionFactory, job_id: uuid.UUID
) -> tuple[JobContext, JobStatus] | None:
    """Snapshot the finished analysis for the connector and pivot phases.

    The second element is the status of the analysis phase alone. The job's own
    status is still RUNNING at this point — the connector and pivot phases have
    not run yet — so a connector asking "did the analysis succeed?" has to be
    told by this snapshot rather than by reading the job row.
    """
    async with session_factory() as session:
        job = (
            await session.execute(
                select(Job).where(Job.id == job_id).options(selectinload(Job.reports))
            )
        ).scalar_one_or_none()
        if job is None:
            return None

        analyzer_reports = [
            report for report in job.reports if report.plugin_type is PluginKind.ANALYZER
        ]
        analysis_status = verdict.aggregate_status(analyzer_reports)

        context = JobContext(
            job_id=job.id,
            observable=Observable(
                value=job.observable_value,
                type=job.observable_type,
                hash_algorithm=_hash_algorithm(job),
            ),
            verdict=job.verdict,
            tlp=job.tlp,
            tags=list(job.tags or []),
            summary=dict(job.summary or {}),
            reports=[
                ReportView(
                    plugin_name=report.plugin_name,
                    plugin_type=report.plugin_type,
                    status=report.status,
                    summary=dict(report.summary_data or {}),
                    raw_output=report.raw_output,
                )
                for report in job.reports
                if report.plugin_type is PluginKind.ANALYZER
            ],
            requested_by=job.requested_by_name,
            depth=job.depth,
        )
        return context, analysis_status


async def _run_connector_phase(
    session_factory: SessionFactory,
    plan: _JobPlan,
    context: JobContext,
    analysis_status: JobStatus,
    *,
    store: job_control.KeyValueStore | None,
) -> None:
    """Publish the finished job through every pending connector."""
    pending = await _pending_reports(session_factory, plan.job_id, PluginKind.CONNECTOR)
    if not pending:
        return

    # Exports run with modest concurrency: the targets are internal platforms,
    # and hammering an OpenCTI instance with a burst is worse than finishing a
    # second later.
    semaphore = asyncio.Semaphore(2)

    async def execute(report_id: uuid.UUID, plugin_name: str) -> None:
        async with semaphore, session_factory() as session:
            if await job_control.is_kill_requested(store, plan.job_id):
                await _mark(session, report_id, ReportStatus.KILLED, "Stopped before it started.")
                return
            try:
                built = await plugin_runtime.build(
                    session,
                    plugin_name,
                    expected_type=PluginKind.CONNECTOR,
                    user_id=plan.requested_by_id,
                    runtime_options=plan.overrides.get(plugin_name),
                    job_tlp=plan.tlp,
                )
                if built is None:
                    await _mark(
                        session, report_id, ReportStatus.SKIPPED, "The connector is disabled."
                    )
                    return

                connector = built.plugin
                assert isinstance(connector, BaseConnector)
                refusal = connector.refusal_reason(context, analysis_status)
                if refusal is not None:
                    await _mark(session, report_id, ReportStatus.SKIPPED, refusal)
                    return

                await _mark(session, report_id, ReportStatus.RUNNING, None)
                result = await connector.execute(context)
                await _store_result(session, report_id, result)
            except Exception as exc:
                logger.error("connector_crashed", plugin=plugin_name, error=str(exc))
                await session.rollback()
                await _mark(
                    session, report_id, ReportStatus.FAILED, f"Internal error: {type(exc).__name__}"
                )

    await asyncio.gather(*(execute(report_id, name) for report_id, name in pending))


async def _run_pivot_phase(
    session_factory: SessionFactory,
    plan: _JobPlan,
    context: JobContext,
    *,
    store: job_control.KeyValueStore | None,
    enqueue: Enqueue | None,
) -> None:
    """Derive the next observables and create a child job for each."""
    pending = await _pending_reports(session_factory, plan.job_id, PluginKind.PIVOT)
    if not pending:
        return

    async with session_factory() as session:
        stored_settings = await settings_store.load_all(session)
    pivots_enabled = bool(stored_settings["pivots_enabled"])
    max_depth = int(stored_settings["max_pivot_depth"])
    budget = int(stored_settings["max_pivot_children_per_job"])

    spawned_total = 0

    # Pivots run one at a time on purpose: they share the per-job child budget,
    # and running them concurrently would make the budget racy.
    for report_id, plugin_name in pending:
        if await job_control.is_kill_requested(store, plan.job_id):
            async with session_factory() as session:
                await _mark(session, report_id, ReportStatus.KILLED, "Stopped before it started.")
            continue

        async with session_factory() as session:
            try:
                built = await plugin_runtime.build(
                    session,
                    plugin_name,
                    expected_type=PluginKind.PIVOT,
                    user_id=plan.requested_by_id,
                    runtime_options=plan.overrides.get(plugin_name),
                    job_tlp=plan.tlp,
                )
                if built is None:
                    await _mark(session, report_id, ReportStatus.SKIPPED, "The pivot is disabled.")
                    continue

                pivot = built.plugin
                assert isinstance(pivot, BasePivot)
                refusal = pivot.refusal_reason(context)
                if refusal is not None:
                    await _mark(session, report_id, ReportStatus.SKIPPED, refusal)
                    continue

                if plan.depth >= max_depth:
                    await _mark(
                        session,
                        report_id,
                        ReportStatus.SKIPPED,
                        f"the pivot depth limit of {max_depth} is already reached",
                    )
                    continue

                await _mark(session, report_id, ReportStatus.RUNNING, None)
                result = await pivot.execute(context)
            except Exception as exc:
                logger.error("pivot_crashed", plugin=plugin_name, error=str(exc))
                await session.rollback()
                await _mark(
                    session, report_id, ReportStatus.FAILED, f"Internal error: {type(exc).__name__}"
                )
                continue

        remaining = max(0, budget - spawned_total)
        created = await _spawn_children(
            session_factory,
            plan=plan,
            pivot_name=plugin_name,
            result=result,
            allowed=remaining if pivots_enabled else 0,
            enqueue=enqueue,
        )
        spawned_total += len(created)

        async with session_factory() as session:
            await _store_result(session, report_id, result, spawned_job_ids=created)
            if not pivots_enabled and result.derived:
                report = await _load_report(session, report_id)
                if report is not None:
                    report.errors = (
                        "Pivoting is turned off for this instance; no child job was created."
                    )
                    await session.commit()


async def _spawn_children(
    session_factory: SessionFactory,
    *,
    plan: _JobPlan,
    pivot_name: str,
    result: PluginResult,
    allowed: int,
    enqueue: Enqueue | None,
) -> list[uuid.UUID]:
    """Create and enqueue one child job per derived observable."""
    if allowed <= 0 or not result.derived:
        return []

    cls = get_plugin(pivot_name)
    child_playbook = getattr(cls, "child_playbook", "") or None
    created: list[uuid.UUID] = []

    for derived in result.derived[:allowed]:
        async with session_factory() as session:
            try:
                request = await resolve_selection(
                    session,
                    raw_observable=derived.value,
                    playbook_name=child_playbook,
                    tags=[f"pivot:{pivot_name}"],
                    tlp=plan.tlp,
                    parent_job_id=plan.job_id,
                    pivot_name=pivot_name,
                    depth=plan.depth + 1,
                )
            except (ValidationFailedError, NotFoundError) as exc:
                # A derived observable that cannot be analysed is a normal
                # outcome, not a pivot failure: it is recorded and skipped.
                logger.info(
                    "pivot_child_rejected",
                    pivot=pivot_name,
                    observable=derived.value,
                    reason=str(exc),
                )
                continue

            user = None
            if plan.requested_by_id is not None:
                user = (
                    await session.execute(select(User).where(User.id == plan.requested_by_id))
                ).scalar_one_or_none()

            child = await create_job(
                session,
                request,
                requested_by=user,
                requested_by_name=plan.requested_by_name,
                origin=JobOrigin.PIVOT,
            )
            await session.commit()
            created.append(child.id)

        if enqueue is not None:
            await enqueue(created[-1])

    if created:
        logger.info(
            "pivot_children_created",
            pivot=pivot_name,
            parent=str(plan.job_id),
            children=len(created),
        )
    return created


# --------------------------------------------------------------------------
# Report and job bookkeeping
# --------------------------------------------------------------------------


async def _load_report(session: AsyncSession, report_id: uuid.UUID) -> PluginReport | None:
    return (
        await session.execute(select(PluginReport).where(PluginReport.id == report_id))
    ).scalar_one_or_none()


async def _mark(
    session: AsyncSession, report_id: uuid.UUID, status: ReportStatus, message: str | None
) -> None:
    """Move a report to a status, stamping the end time for terminal ones."""
    report = await _load_report(session, report_id)
    if report is None:
        return
    report.status = status
    report.errors = message
    if status is not ReportStatus.RUNNING:
        report.finished_at = datetime.now(UTC)
    await session.commit()


async def _store_result(
    session: AsyncSession,
    report_id: uuid.UUID,
    result: PluginResult,
    *,
    spawned_job_ids: list[uuid.UUID] | None = None,
) -> None:
    """Write a plugin's outcome onto its report."""
    report = await _load_report(session, report_id)
    if report is None:
        return
    report.status = result.status
    report.raw_output = result.raw_output
    report.summary_data = result.summary.as_dict()
    report.errors = result.error
    report.execution_time_ms = result.execution_time_ms
    report.from_cache = False
    report.derived_observables = [entry.as_dict() for entry in result.derived]
    report.spawned_job_ids = spawned_job_ids or []
    report.finished_at = datetime.now(UTC)
    await session.commit()


async def _kill_pending(session_factory: SessionFactory, job_id: uuid.UUID) -> None:
    """Mark every report that had not finished as KILLED."""
    async with session_factory() as session:
        job = (
            await session.execute(
                select(Job).where(Job.id == job_id).options(selectinload(Job.reports))
            )
        ).scalar_one_or_none()
        if job is None:
            return
        now = datetime.now(UTC)
        for report in job.reports:
            if report.status in {ReportStatus.PENDING, ReportStatus.RUNNING}:
                report.status = ReportStatus.KILLED
                report.errors = "The job was stopped by an operator."
                report.finished_at = now
        await session.commit()


async def _aggregate(session_factory: SessionFactory, job_id: uuid.UUID, *, finished: bool) -> None:
    """Recompute the job's verdict, status and synthetic summary."""
    async with session_factory() as session:
        job = (
            await session.execute(
                select(Job).where(Job.id == job_id).options(selectinload(Job.reports))
            )
        ).scalar_one_or_none()
        if job is None:
            return

        reports = list(job.reports)
        job.verdict = verdict.aggregate_verdict(reports)
        previous = job.summary or {}
        job.summary = {
            **verdict.build_summary(reports),
            "skipped_plugins": previous.get("skipped_plugins", []),
        }
        if finished:
            job.status = verdict.aggregate_status(reports)
            job.finished_at = datetime.now(UTC)
        await session.commit()


async def _finalise(
    session_factory: SessionFactory,
    job_id: uuid.UUID,
    *,
    store: job_control.KeyValueStore | None,
) -> None:
    """Close the job out and drop its cancellation flag."""
    await _aggregate(session_factory, job_id, finished=True)
    await job_control.clear_kill(store, job_id)

    async with session_factory() as session:
        job = (
            await session.execute(
                select(Job).where(Job.id == job_id).options(selectinload(Job.reports))
            )
        ).scalar_one_or_none()
        if job is None:
            return
        logger.info(
            "job_finished",
            job_id=str(job_id),
            status=job.status.value,
            job_verdict=job.verdict.value,
            plugins=len(job.reports),
        )


async def retry_report(
    session: AsyncSession, *, job_id: uuid.UUID, report_id: uuid.UUID
) -> PluginReport:
    """Re-arm one failed or killed report so the job runs it again.

    This is IntelOwl's per-plugin `retry`. It is scoped to a report that has
    stopped: re-arming a running one would race the worker that owns it.
    """
    report = (
        await session.execute(
            select(PluginReport).where(PluginReport.id == report_id, PluginReport.job_id == job_id)
        )
    ).scalar_one_or_none()
    if report is None:
        raise NotFoundError("Unknown report for this job.", code="REPORT_NOT_FOUND")
    if report.status not in {ReportStatus.FAILED, ReportStatus.KILLED, ReportStatus.SKIPPED}:
        raise ValidationFailedError(
            f"Only a failed, killed or skipped report can be retried; this one is "
            f"{report.status.value}."
        )

    report.status = ReportStatus.PENDING
    report.errors = None
    report.raw_output = None
    report.summary_data = {}
    report.execution_time_ms = None
    report.from_cache = False
    report.cached_from_id = None
    report.derived_observables = []
    report.spawned_job_ids = []
    report.finished_at = None

    job = (await session.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is not None:
        job.status = JobStatus.PENDING
        job.finished_at = None
    await session.flush()
    return report


def _hash_algorithm(job: Job) -> str | None:
    if job.observable_type is not ObservableType.HASH:
        return None
    return {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(job.observable_value))
