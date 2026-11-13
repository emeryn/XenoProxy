"""Job submission, listing, detail, live status, plugin actions and export."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSession, client_ip, require
from app.core import http_client
from app.core.config import get_settings
from app.core.errors import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.models.job import (
    Job,
    JobStatus,
    ObservableType,
    PluginKind,
    PluginReport,
    ScanMode,
    Tlp,
    Verdict,
)
from app.models.playbook import Playbook
from app.models.user import User
from app.plugins import load_all
from app.schemas.common import MessageResponse, Page
from app.schemas.jobs import (
    JobCreate,
    JobDetailOut,
    JobSummaryOut,
    JobTagsUpdate,
    ObservablePreview,
    ObservablePreviewRequest,
    PluginReportDetail,
    PluginReportOut,
)
from app.services import (
    archives,
    audit,
    job_control,
    orchestrator,
    reports,
    settings_store,
    uploads,
)
from app.services.export import job_to_markdown
from app.services.observables import classify, refang

logger = get_logger(__name__)
router = APIRouter(prefix="/jobs", tags=["jobs"])

AnalystUser = Annotated[User, Depends(require("jobs:read"))]
WriterUser = Annotated[User, Depends(require("jobs:write"))]
TaggerUser = Annotated[User, Depends(require("jobs:tag"))]
ExporterUser = Annotated[User, Depends(require("jobs:export"))]

TERMINAL_STATUSES = {
    JobStatus.SUCCESS,
    JobStatus.PARTIAL_FAILURE,
    JobStatus.FAILED,
    JobStatus.KILLED,
}


@router.post(
    "/preview",
    response_model=ObservablePreview,
    summary="Classify an observable and list what can run on it",
)
async def preview(
    payload: ObservablePreviewRequest, session: DbSession, _user: AnalystUser
) -> ObservablePreview:
    """Drives the scan page: the detected type, and every plugin with its state."""
    load_all()
    stored = await settings_store.load_all(session)
    job_tlp = payload.tlp or Tlp(stored["default_tlp"])
    observable = classify(payload.value)

    runnable: dict[PluginKind, list[str]] = {}
    unavailable: list[dict[str, str]] = []
    for kind in PluginKind:
        available, skipped = await orchestrator.candidate_plugins(
            session, plugin_type=kind, observable_type=observable.type, job_tlp=job_tlp
        )
        runnable[kind] = available
        unavailable.extend(entry.as_dict() for entry in skipped)

    playbooks = (
        await session.execute(select(Playbook).where(Playbook.enabled.is_(True)))
    ).scalars()
    compatible_playbooks = sorted(
        playbook.name
        for playbook in playbooks
        if not playbook.observable_types or observable.type.value in playbook.observable_types
    )

    return ObservablePreview(
        value=observable.value,
        type=observable.type,
        hash_algorithm=observable.hash_algorithm,
        is_private=observable.is_private,
        refanged=refang(payload.value) != payload.value.strip(),
        tlp=job_tlp,
        compatible_analyzers=runnable[PluginKind.ANALYZER],
        compatible_connectors=runnable[PluginKind.CONNECTOR],
        compatible_pivots=runnable[PluginKind.PIVOT],
        compatible_playbooks=compatible_playbooks,
        # The analyzer-only list is kept so an existing client keeps working;
        # `unavailable_plugins` is the complete one.
        unavailable_analyzers=[
            entry for entry in unavailable if entry["type"] == PluginKind.ANALYZER.value
        ],
        unavailable_plugins=unavailable,
        auto_select=bool(stored["auto_select_analyzers"]),
        default_scan_mode=ScanMode(stored["default_scan_mode"]),
    )


@router.post(
    "",
    response_model=JobDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a new analysis job",
)
async def create_job(
    payload: JobCreate, request: Request, session: DbSession, user: WriterUser
) -> JobDetailOut:
    job_request = await orchestrator.resolve_selection(
        session,
        raw_observable=payload.observable,
        analyzers=payload.analyzers,
        connectors=payload.connectors,
        pivots=payload.pivots,
        plugins=payload.plugins,
        playbook_name=payload.playbook,
        tags=payload.tags,
        tlp=payload.tlp,
        scan_mode=payload.scan_mode or (ScanMode.FORCE_NEW if payload.force_rescan else None),
        scan_check_minutes=payload.scan_check_minutes,
        runtime_configuration=payload.runtime_configuration,
    )
    job = await orchestrator.create_job(
        session, job_request, requested_by=user, requested_by_name=user.username
    )
    await audit.record(
        session,
        action="job.create",
        actor=user.username,
        actor_id=user.id,
        target=str(job.id),
        ip_address=client_ip(request),
        details={
            "observable_type": job.observable_type.value,
            "analyzers": job_request.selection.analyzers,
            "connectors": job_request.selection.connectors,
            "pivots": job_request.selection.pivots,
            "playbook": job_request.playbook_name,
            "tlp": job_request.tlp.value,
            "scan_mode": job_request.scan_mode.value,
            "auto_selected": job_request.auto_selected,
            "skipped": [entry.as_dict() for entry in job_request.skipped],
        },
    )
    await session.commit()

    await request.app.state.queue.enqueue_job("run_job", str(job.id))
    await session.refresh(job, ["reports"])
    return _job_detail(job)


@router.post(
    "/file",
    response_model=JobDetailOut,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a file for analysis",
)
async def create_file_job(
    request: Request,
    session: DbSession,
    user: WriterUser,
    upload: Annotated[UploadFile, File(alias="file", description="The sample to analyse")],
    options: Annotated[str, Form(description="JSON object with the same fields as a scan")] = "{}",
    archive_password: Annotated[
        str, Form(description="Password of the archive, if it is not a conventional one")
    ] = "",
) -> JobDetailOut:
    """Analyse a sample the analyst already holds.

    The observable is the file's SHA-256, which is what every hash source looks
    up, so the usual catalogue applies with no special case.

    A sample normally arrives inside a password-protected archive, so that
    nothing opens it by accident on the way. When it does, the archive is
    opened here — only to hash what is inside, never extracted — and the job is
    about the **file inside**, which is what the analyst actually wants looked
    up. The archive itself is kept as context.

    Whether the bytes may then be sent to a provider is a separate decision,
    held in the scanning settings. By default they never leave.
    """
    settings = get_settings()
    payload = await upload.read(settings.max_upload_bytes + 1)
    sample = uploads.store(payload, filename=upload.filename)

    stored = await settings_store.load_all(session)
    extra = [
        entry.strip()
        for entry in str(stored.get("archive_passwords") or "").split(",")
        if entry.strip()
    ]
    if archive_password.strip():
        extra.insert(0, archive_password.strip())

    archive: dict[str, Any] | None = None
    observable_hash = sample.sha256
    if archives.looks_like_archive(payload):
        try:
            contents = archives.inspect(payload, passwords=extra)
        except archives.ArchiveError as exc:
            raise ValidationFailedError(str(exc)) from exc

        archive = {
            "name": sample.display_name,
            "sha256": sample.sha256,
            "encrypted": contents.encrypted,
            "entries": [
                {
                    "name": entry.name,
                    "size": entry.size,
                    "sha256": entry.sha256,
                    "md5": entry.md5,
                    "sha1": entry.sha1,
                }
                for entry in contents.entries
            ],
            "skipped": contents.skipped,
        }
        if len(contents.entries) == 1:
            # One file inside is the normal shape of a shipped sample, and it
            # is unambiguously what the analyst wants analysed.
            observable_hash = contents.entries[0].sha256
        elif not contents.entries:
            raise ValidationFailedError(
                "The archive holds nothing that could be hashed."
                + (f" Skipped: {', '.join(contents.skipped)}" if contents.skipped else "")
            )
        else:
            # Several files: the archive's own digest stays the observable, and
            # the inner hashes are recorded for the analyst to pick from.
            # Guessing which one matters would be worse than saying so.
            logger.info(
                "archive_holds_several_files",
                entries=len(contents.entries),
                sha256=sample.sha256,
            )

    try:
        parsed = json.loads(options or "{}")
    except ValueError as exc:
        raise ValidationFailedError("The options field is not valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise ValidationFailedError("The options field must be a JSON object.")
    # The digest is the observable, so a caller cannot name a different one.
    parsed.pop("observable", None)
    choices = JobCreate.model_validate({**parsed, "observable": observable_hash})

    job_request = await orchestrator.resolve_selection(
        session,
        raw_observable=observable_hash,
        analyzers=choices.analyzers,
        connectors=choices.connectors,
        pivots=choices.pivots,
        plugins=choices.plugins,
        playbook_name=choices.playbook,
        tags=choices.tags,
        tlp=choices.tlp,
        scan_mode=choices.scan_mode or (ScanMode.FORCE_NEW if choices.force_rescan else None),
        scan_check_minutes=choices.scan_check_minutes,
        runtime_configuration=choices.runtime_configuration,
    )
    job = await orchestrator.create_job(
        session, job_request, requested_by=user, requested_by_name=user.username
    )
    job.file_name = sample.display_name
    job.file_size = sample.size
    job.file_path = sample.path
    if archive is not None:
        job.runtime_configuration = {
            **(job.runtime_configuration or {}),
            "_archive": archive,
        }

    await audit.record(
        session,
        action="job.create_file",
        actor=user.username,
        actor_id=user.id,
        target=str(job.id),
        ip_address=client_ip(request),
        details={
            "sha256": sample.sha256,
            "analysed_sha256": observable_hash,
            "archive": bool(archive),
            "file_name": sample.display_name,
            "file_size": sample.size,
            "analyzers": job_request.selection.analyzers,
            "playbook": job_request.playbook_name,
        },
    )
    await session.commit()

    await request.app.state.queue.enqueue_job("run_job", str(job.id))
    await session.refresh(job, ["reports"])
    return _job_detail(job)


@router.get("", response_model=Page[JobSummaryOut], summary="List team jobs")
async def list_jobs(
    session: DbSession,
    user: AnalystUser,
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    search: Annotated[str | None, Query(max_length=256)] = None,
    job_status: Annotated[JobStatus | None, Query(alias="status")] = None,
    job_verdict: Annotated[Verdict | None, Query(alias="verdict")] = None,
    observable_type: Annotated[ObservableType | None, Query()] = None,
    tag: Annotated[str | None, Query(max_length=64)] = None,
    requested_by: Annotated[str | None, Query(max_length=128)] = None,
    job_tlp: Annotated[Tlp | None, Query(alias="tlp")] = None,
    derived: Annotated[bool | None, Query()] = None,
) -> Page[JobSummaryOut]:
    """Jobs are shared across the organisation so the team mutualises its history."""
    statement = _visible_jobs(user)
    if search:
        statement = statement.where(Job.observable_value.ilike(f"%{search.strip()}%"))
    if job_status:
        statement = statement.where(Job.status == job_status)
    if job_verdict:
        statement = statement.where(Job.verdict == job_verdict)
    if job_tlp:
        statement = statement.where(Job.tlp == job_tlp)
    if observable_type:
        statement = statement.where(Job.observable_type == observable_type)
    if tag:
        statement = statement.where(Job.tags.any(tag.strip().lower()))
    if requested_by:
        statement = statement.where(Job.requested_by_name == requested_by.strip().lower())
    if derived is not None:
        # Lets the history hide, or show only, the jobs a pivot created.
        statement = statement.where(
            Job.parent_job_id.isnot(None) if derived else Job.parent_job_id.is_(None)
        )

    total = (
        await session.execute(select(func.count()).select_from(statement.subquery()))
    ).scalar_one()
    rows = (
        await session.execute(
            statement.order_by(Job.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .options(selectinload(Job.reports))
        )
    ).scalars()

    return Page[JobSummaryOut](
        items=[_job_summary(job) for job in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/{job_id}", response_model=JobDetailOut, summary="Read one job with its reports")
async def get_job(job_id: uuid.UUID, session: DbSession, user: AnalystUser) -> JobDetailOut:
    return _job_detail(await _load_job(session, job_id, user))


@router.get(
    "/{job_id}/children",
    response_model=list[JobSummaryOut],
    summary="List the jobs a pivot derived from this one",
)
async def get_children(
    job_id: uuid.UUID, session: DbSession, user: AnalystUser
) -> list[JobSummaryOut]:
    """One level of the investigation tree below this job."""
    await _load_job(session, job_id, user)
    rows = (
        await session.execute(
            _visible_jobs(user)
            .where(Job.parent_job_id == job_id)
            .order_by(Job.created_at)
            .options(selectinload(Job.reports))
        )
    ).scalars()
    return [_job_summary(job) for job in rows]


@router.get(
    "/{job_id}/reports/{plugin_name}",
    response_model=PluginReportDetail,
    summary="Read the raw provider output of one plugin",
)
async def get_report(
    job_id: uuid.UUID,
    plugin_name: str,
    session: DbSession,
    user: AnalystUser,
) -> PluginReportDetail:
    await _load_job(session, job_id, user)
    report = (
        await session.execute(
            select(PluginReport).where(
                PluginReport.job_id == job_id,
                PluginReport.plugin_name == plugin_name[:64],
            )
        )
    ).scalar_one_or_none()
    if report is None:
        raise NotFoundError("The report does not exist.")
    return PluginReportDetail.model_validate(report, from_attributes=True)


@router.get(
    "/{job_id}/reports",
    response_model=list,
    summary="What this job has to read, and how large each payload is",
)
async def report_inventory(
    job_id: uuid.UUID, session: DbSession, user: AnalystUser
) -> list[dict[str, Any]]:
    """Shown before anything is downloaded, so nothing large is fetched blindly."""
    return await reports.inventory(session, _visible_jobs(user), job_id)


@router.get(
    "/{job_id}/reports/{plugin_name}/raw",
    response_model=dict,
    summary="The provider payload, a subtree of it, or its shape",
)
async def get_raw(
    job_id: uuid.UUID,
    plugin_name: str,
    session: DbSession,
    user: AnalystUser,
    path: Annotated[str | None, Query(max_length=reports.MAX_PATH_LENGTH)] = None,
    shape: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    """Everything the provider answered, kept whole and readable in parts.

    `shape` returns the structure rather than the content, which is how an
    analyst finds the path worth asking for without downloading a payload that
    runs to hundreds of kilobytes. `path` then returns just that subtree.
    """
    report = await reports.load_report(session, _visible_jobs(user), job_id, plugin_name)
    return reports.raw_view(report, path=path, shape=shape)


@router.post(
    "/{job_id}/kill",
    response_model=MessageResponse,
    summary="Stop a running job",
)
async def kill_job(
    job_id: uuid.UUID, request: Request, session: DbSession, user: WriterUser
) -> MessageResponse:
    """Ask the worker to stop at its next checkpoint.

    The cancellation is cooperative: nothing further starts, and a provider call
    already in flight is left to finish rather than abandoned half-written.
    """
    job = await _load_job(session, job_id, user)
    if job.status in TERMINAL_STATUSES:
        raise ValidationFailedError(f"The job already finished as {job.status.value}.")

    await job_control.request_kill(request.app.state.queue, job.id)
    await audit.record(
        session,
        action="job.kill",
        actor=user.username,
        actor_id=user.id,
        target=str(job.id),
        ip_address=client_ip(request),
        details={"status_when_requested": job.status.value},
    )
    await session.commit()
    return MessageResponse(
        message="The job will stop at its next checkpoint. Reports already finished are kept."
    )


@router.post(
    "/{job_id}/reports/{report_id}/retry",
    response_model=JobDetailOut,
    summary="Re-run one failed, killed or skipped plugin",
)
async def retry_report(
    job_id: uuid.UUID,
    report_id: uuid.UUID,
    request: Request,
    session: DbSession,
    user: WriterUser,
) -> JobDetailOut:
    """Re-arm a single plugin instead of re-running the whole job.

    This is what makes a transient provider failure cheap to recover from: the
    other reports, and the quota they cost, are untouched.
    """
    job = await _load_job(session, job_id, user)
    report = await orchestrator.retry_report(session, job_id=job.id, report_id=report_id)
    await audit.record(
        session,
        action="job.report_retry",
        actor=user.username,
        actor_id=user.id,
        target=str(job.id),
        ip_address=client_ip(request),
        details={"plugin": report.plugin_name, "plugin_type": report.plugin_type.value},
    )
    await session.commit()

    await job_control.clear_kill(request.app.state.queue, job.id)
    await request.app.state.queue.enqueue_job("run_job", str(job.id))
    await session.refresh(job, ["reports"])
    return _job_detail(job)


@router.get("/{job_id}/events", summary="Stream job progress as server-sent events")
async def job_events(job_id: uuid.UUID, request: Request, _user: AnalystUser) -> StreamingResponse:
    """Push the job state until it reaches a terminal status."""
    factory = request.app.state.session_factory

    async def stream() -> Any:
        last_payload: str | None = None
        for _ in range(600):
            if await request.is_disconnected():
                return
            async with factory() as session:
                job = (
                    await session.execute(
                        select(Job).where(Job.id == job_id).options(selectinload(Job.reports))
                    )
                ).scalar_one_or_none()
                if job is None:
                    yield "event: error\ndata: {}\n\n"
                    return
                payload = json.dumps(
                    _job_detail(job).model_dump(mode="json"), separators=(",", ":")
                )
                finished = job.status in TERMINAL_STATUSES
            if payload != last_payload:
                yield f"event: job\ndata: {payload}\n\n"
                last_payload = payload
            if finished:
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(1.5)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.patch("/{job_id}/tags", response_model=JobDetailOut, summary="Replace the tags of a job")
async def update_tags(
    job_id: uuid.UUID,
    payload: JobTagsUpdate,
    request: Request,
    session: DbSession,
    user: TaggerUser,
) -> JobDetailOut:
    job = await _load_job(session, job_id, user)
    job.tags = sorted({tag.strip().lower()[:64] for tag in payload.tags if tag.strip()})
    await audit.record(
        session,
        action="job.tag",
        actor=user.username,
        actor_id=user.id,
        target=str(job.id),
        ip_address=client_ip(request),
        details={"tags": job.tags},
    )
    return _job_detail(job)


@router.get("/{job_id}/export", summary="Export a job as JSON or Markdown")
async def export_job(
    job_id: uuid.UUID,
    session: DbSession,
    user: ExporterUser,
    export_format: Annotated[str, Query(alias="format", pattern="^(json|markdown)$")] = "json",
) -> Response:
    job = await _load_job(session, job_id, user)
    stem = f"xenoproxy-{job.observable_type.value}-{job.id}"

    if export_format == "markdown":
        return Response(
            content=job_to_markdown(job),
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{stem}.md"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    payload = {
        "job": _job_detail(job).model_dump(mode="json"),
        "reports": [
            PluginReportDetail.model_validate(report, from_attributes=True).model_dump(mode="json")
            for report in job.reports
        ],
        "exported_at": datetime.now().astimezone().isoformat(),
    }
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{stem}.json"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.post("/{job_id}/rerun", response_model=JobDetailOut, summary="Re-run a job, ignoring cache")
async def rerun_job(
    job_id: uuid.UUID, request: Request, session: DbSession, user: WriterUser
) -> JobDetailOut:
    source = await _load_job(session, job_id, user)
    job_request = await orchestrator.resolve_selection(
        session,
        raw_observable=source.observable_value,
        analyzers=list(source.requested_analyzers or []),
        connectors=list(source.requested_connectors or []),
        pivots=list(source.requested_pivots or []),
        playbook_name=None,
        tags=list(source.tags),
        tlp=source.tlp,
        scan_mode=ScanMode.FORCE_NEW,
        runtime_configuration=dict(source.runtime_configuration or {}),
    )
    job = await orchestrator.create_job(
        session, job_request, requested_by=user, requested_by_name=user.username
    )
    await audit.record(
        session,
        action="job.rerun",
        actor=user.username,
        actor_id=user.id,
        target=str(job.id),
        ip_address=client_ip(request),
        details={"source_job": str(source.id)},
    )
    await session.commit()
    await request.app.state.queue.enqueue_job("run_job", str(job.id))
    await session.refresh(job, ["reports"])
    return _job_detail(job)


@router.get("/stats/overview", response_model=dict, summary="Dashboard counters")
async def stats(session: DbSession, _user: AnalystUser) -> dict[str, Any]:
    by_verdict = (
        await session.execute(select(Job.verdict, func.count()).group_by(Job.verdict))
    ).all()
    by_status = (await session.execute(select(Job.status, func.count()).group_by(Job.status))).all()

    # The cache ratio is an analyzer statistic: connector and pivot reports are
    # never served from cache, so counting them would dilute it.
    analyzer_only = PluginReport.plugin_type == PluginKind.ANALYZER
    cached = (
        await session.execute(
            select(func.count())
            .select_from(PluginReport)
            .where(analyzer_only, PluginReport.from_cache.is_(True))
        )
    ).scalar_one()
    total_reports = (
        await session.execute(select(func.count()).select_from(PluginReport).where(analyzer_only))
    ).scalar_one()
    by_type = (
        await session.execute(
            select(PluginReport.plugin_type, func.count()).group_by(PluginReport.plugin_type)
        )
    ).all()
    derived_jobs = (
        await session.execute(
            select(func.count()).select_from(Job).where(Job.parent_job_id.isnot(None))
        )
    ).scalar_one()

    return {
        "jobs_by_verdict": {row[0].value: int(row[1]) for row in by_verdict},
        "jobs_by_status": {row[0].value: int(row[1]) for row in by_status},
        "reports_total": int(total_reports),
        "reports_from_cache": int(cached),
        "cache_hit_ratio": round(int(cached) / int(total_reports), 3) if total_reports else 0.0,
        "reports_by_plugin_type": {row[0].value: int(row[1]) for row in by_type},
        "jobs_from_pivots": int(derived_jobs),
    }


def _visible_jobs(user: User) -> Select[tuple[Job]]:
    """Restrict a query to the jobs this user may see.

    A job at CLEAR or GREEN is visible to the whole organisation. From AMBER up
    it is limited to the groups its submitter belonged to, which is how the TLP
    restricts sharing rather than only restricting which sources run.
    """
    if user.is_admin:
        return select(Job)
    open_levels = [Tlp.CLEAR, Tlp.GREEN]
    condition = Job.tlp.in_(open_levels)
    if user.group_ids:
        condition = or_(condition, Job.visible_to_group_ids.overlap(user.group_ids))
    if user.id is not None:
        condition = or_(condition, Job.requested_by_id == user.id)
    return select(Job).where(condition)


async def _load_job(session: DbSession, job_id: uuid.UUID, user: User) -> Job:
    job = (
        await session.execute(
            _visible_jobs(user).where(Job.id == job_id).options(selectinload(Job.reports))
        )
    ).scalar_one_or_none()
    if job is None:
        # A job the caller may not see is reported as missing, not as forbidden.
        raise NotFoundError("The job does not exist.")
    return job


def _job_summary(job: Job) -> JobSummaryOut:
    return JobSummaryOut(
        id=job.id,
        observable_value=job.observable_value,
        observable_type=job.observable_type,
        status=job.status,
        verdict=job.verdict,
        tags=list(job.tags or []),
        tlp=job.tlp,
        playbook_name=job.playbook_name,
        requested_by_name=job.requested_by_name,
        created_at=job.created_at,
        finished_at=job.finished_at,
        analyzer_count=sum(
            1 for report in job.reports if report.plugin_type is PluginKind.ANALYZER
        ),
        parent_job_id=job.parent_job_id,
        pivot_name=job.pivot_name,
        depth=job.depth,
    )


def _job_detail(job: Job) -> JobDetailOut:
    return JobDetailOut(
        **_job_summary(job).model_dump(),
        file_name=job.file_name,
        file_size=job.file_size,
        requested_analyzers=list(job.requested_analyzers or []),
        requested_connectors=list(job.requested_connectors or []),
        requested_pivots=list(job.requested_pivots or []),
        force_rescan=job.force_rescan,
        scan_mode=job.scan_mode,
        scan_check_minutes=job.scan_check_minutes,
        runtime_configuration=dict(job.runtime_configuration or {}),
        summary=job.summary or {},
        started_at=job.started_at,
        reports=[
            PluginReportOut.model_validate(report, from_attributes=True)
            # Ordered by phase, then by name, so the UI shows the lifecycle in
            # the order it actually ran.
            for report in sorted(
                job.reports,
                key=lambda item: (_PHASE_ORDER[item.plugin_type], item.plugin_name),
            )
        ],
    )


_PHASE_ORDER = {PluginKind.ANALYZER: 0, PluginKind.CONNECTOR: 1, PluginKind.PIVOT: 2}


# The formats a provider actually serves a page capture in. Anything else is
# refused rather than passed through: this route answers with an image, and a
# provider that returns something else is a reason to stop, not to guess.
_IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
_MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024


@router.get(
    "/{job_id}/reports/{report_id}/screenshot",
    summary="The page capture a source took, fetched through the backend",
)
async def report_screenshot(
    job_id: uuid.UUID,
    report_id: uuid.UUID,
    session: DbSession,
    user: AnalystUser,
) -> Response:
    """Serve a report's screenshot from here rather than from the provider.

    The browser must not fetch it directly. Doing so would tell the provider
    the analyst's address and what they are looking at, and the content policy
    refuses remote images anyway — so a direct load would simply show nothing.

    Fetching it here keeps both properties: the provider sees only the
    instance, and the page stays closed to third-party content.
    """
    # `_load_job` applies the visibility rule; the report must then belong
    # to that job, or a report id would be readable across jobs.
    job = await _load_job(session, job_id, user)
    report = (
        await session.execute(
            select(PluginReport).where(
                PluginReport.id == report_id, PluginReport.job_id == job.id
            )
        )
    ).scalar_one_or_none()
    if report is None:
        raise NotFoundError("Unknown report.", code="REPORT_NOT_FOUND")

    source = str((report.summary_data or {}).get("screenshot_url") or "")
    if not source:
        raise NotFoundError("This report carries no screenshot.", code="NO_SCREENSHOT")

    result = await http_client.get_bytes(source, timeout=30, max_bytes=_MAX_SCREENSHOT_BYTES)
    if result is None:
        raise NotFoundError("The provider did not return the screenshot.", code="NO_SCREENSHOT")

    content, content_type = result
    if content_type.split(";")[0].strip().lower() not in _IMAGE_TYPES:
        raise NotFoundError("The provider did not answer with an image.", code="NO_SCREENSHOT")

    return Response(
        content=content,
        media_type=content_type,
        headers={
            # It is a capture of someone else's page: never let it be framed,
            # sniffed into another type, or cached by a shared proxy.
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=3600",
        },
    )
