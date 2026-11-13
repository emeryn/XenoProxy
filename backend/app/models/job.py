"""Job and analyzer report models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class ObservableType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    FILE = "file"
    GENERIC = "generic"


class PluginKind(StrEnum):
    """Where a plugin sits in the job lifecycle.

    It lives in the model layer because the report table stores it, and the
    plugin package re-exports it as `PluginType`. Declaring it once is what
    guarantees the enum in the database and the enum the plugins declare can
    never drift apart.
    """

    ANALYZER = "analyzer"
    CONNECTOR = "connector"
    PIVOT = "pivot"


class JobStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"
    FAILED = "FAILED"
    # An operator stopped the job. Reports that had already finished keep their
    # result; the ones that had not are marked KILLED and never run.
    KILLED = "KILLED"


class ReportStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    KILLED = "KILLED"


class Tlp(StrEnum):
    """Traffic Light Protocol, following TLP v2.0.

    The level caps which analyzers may run: each analyzer declares the highest
    level it tolerates, so RED keeps an observable away from every external
    service, and GREEN keeps it away from the ones that publish or retain it.
    """

    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class ScanMode(StrEnum):
    """How the engine treats an existing recent report."""

    REUSE_RECENT = "reuse_recent"
    FORCE_NEW = "force_new"


class JobOrigin(StrEnum):
    """Where the request for this job came in through.

    The analyst needs this to read the history: a job nobody remembers running
    was very likely run for them by the assistant or by an agent over MCP, and
    "who" alone does not say that — the account is the same either way.
    """

    UI = "ui"
    API = "api"
    ASSISTANT = "assistant"
    MCP = "mcp"
    PIVOT = "pivot"


class Verdict(StrEnum):
    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    observable_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    observable_type: Mapped[ObservableType] = mapped_column(
        Enum(ObservableType, name="observable_type"), nullable=False
    )
    file_name: Mapped[str | None] = mapped_column(String(256))
    file_size: Mapped[int | None] = mapped_column(Integer)
    # Path inside the uploads volume. The bytes are kept so a sandbox
    # analyzer can submit the sample itself rather than only its hash.
    file_path: Mapped[str | None] = mapped_column(String(512))
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="job_status"), default=JobStatus.PENDING, nullable=False
    )
    verdict: Mapped[Verdict] = mapped_column(
        Enum(Verdict, name="verdict"), default=Verdict.UNKNOWN, nullable=False
    )
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    playbook_name: Mapped[str | None] = mapped_column(String(128))
    requested_analyzers: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    # Connectors run after the analysis phase; pivots run after the connectors.
    requested_connectors: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    requested_pivots: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    force_rescan: Mapped[bool] = mapped_column(Boolean, default=False)
    tlp: Mapped[Tlp] = mapped_column(Enum(Tlp, name="tlp"), default=Tlp.AMBER, nullable=False)
    scan_mode: Mapped[ScanMode] = mapped_column(
        Enum(ScanMode, name="scan_mode"), default=ScanMode.REUSE_RECENT, nullable=False
    )
    # Minutes a previous report stays reusable for this job; null falls back to
    # each analyzer's configured cache lifetime.
    scan_check_minutes: Mapped[int | None] = mapped_column(Integer)
    # Per-request analyzer options, keyed by analyzer name. They override the
    # stored configuration for this job only.
    runtime_configuration: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Groups that may see this job when the TLP restricts visibility.
    visible_to_group_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), default=list
    )
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Pivot lineage. A job created by a pivot points back at its parent and
    # records which pivot derived it, so the investigation tree is reconstructible
    # and the depth guard has something to count.
    parent_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL")
    )
    pivot_name: Mapped[str | None] = mapped_column(String(64))
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    origin: Mapped[JobOrigin] = mapped_column(
        Enum(JobOrigin, name="job_origin"), default=JobOrigin.UI, nullable=False
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    requested_by_name: Mapped[str] = mapped_column(String(128), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    reports: Mapped[list[PluginReport]] = relationship(
        back_populates="job", cascade="all, delete-orphan", lazy="selectin"
    )


class PluginReport(Base):
    """One plugin's contribution to a job, whatever its type.

    Analyzers, connectors and pivots all land here. `plugin_type` is what the
    UI groups on and what the orchestrator uses to know which phase a pending
    report belongs to, so a report is never run by the wrong phase.
    """

    __tablename__ = "plugin_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_type: Mapped[PluginKind] = mapped_column(
        Enum(PluginKind, name="plugin_kind"), default=PluginKind.ANALYZER, nullable=False
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status"), default=ReportStatus.PENDING, nullable=False
    )
    observable_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    observable_type: Mapped[ObservableType] = mapped_column(
        Enum(ObservableType, name="observable_type"), nullable=False
    )
    raw_output: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    summary_data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    errors: Mapped[str | None] = mapped_column(Text)
    execution_time_ms: Mapped[int | None] = mapped_column(Integer)
    from_cache: Mapped[bool] = mapped_column(Boolean, default=False)
    cached_from_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # Observables a pivot derived, and the child jobs they produced.
    derived_observables: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    spawned_job_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), default=list
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    job: Mapped[Job] = relationship(back_populates="reports")


Index("ix_jobs_created_at", Job.created_at.desc())
Index("ix_jobs_tlp", Job.tlp)
Index("ix_jobs_observable", Job.observable_value, Job.observable_type)
Index("ix_jobs_parent", Job.parent_job_id)
Index("ix_reports_job_id", PluginReport.job_id)
Index(
    "ix_reports_cache_lookup",
    PluginReport.plugin_name,
    PluginReport.observable_value,
    PluginReport.status,
    PluginReport.created_at.desc(),
)
