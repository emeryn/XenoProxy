"""Job submission and reporting schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.job import (
    JobOrigin,
    JobStatus,
    ObservableType,
    PluginKind,
    ReportStatus,
    ScanMode,
    Tlp,
    Verdict,
)
from app.schemas.common import StrictModel


class JobCreate(StrictModel):
    """A scan submission.

    Leaving every plugin list and `playbook` empty is the normal case: every
    analyzer that can run on the detected type, at the chosen TLP, is selected.
    Connectors and pivots are never implied — naming one is what turns it on for
    the job, because one publishes outside the instance and the other creates
    further jobs.

    `plugins` accepts names of any type and sorts them by declaration, so a
    scripted client need not know which phase each belongs to.
    """

    observable: str = Field(min_length=1, max_length=2048)
    analyzers: list[str] = Field(default_factory=list, max_length=40)
    connectors: list[str] = Field(default_factory=list, max_length=10)
    pivots: list[str] = Field(default_factory=list, max_length=10)
    plugins: list[str] = Field(default_factory=list, max_length=60)
    playbook: str | None = Field(default=None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=20)
    tlp: Tlp | None = None
    scan_mode: ScanMode | None = None
    scan_check_minutes: int | None = Field(default=None, ge=0, le=43200)
    # Per-plugin option overrides for this job only, keyed by plugin name.
    runtime_configuration: dict[str, dict[str, Any]] = Field(default_factory=dict)
    # Kept for existing callers: equivalent to scan_mode = force_new.
    force_rescan: bool = False

    @field_validator("analyzers", "connectors", "pivots", "plugins", "tags")
    @classmethod
    def _bounded_entries(cls, values: list[str]) -> list[str]:
        for value in values:
            if len(value) > 64:
                raise ValueError("entries are limited to 64 characters")
        return values


class ObservablePreviewRequest(StrictModel):
    value: str = Field(min_length=1, max_length=2048)
    tlp: Tlp | None = None


class PluginAvailability(BaseModel):
    """A plugin the detected type supports, and whether it can run."""

    name: str
    plugin_type: PluginKind
    available: bool
    reason: str | None = None


class ObservablePreview(BaseModel):
    value: str
    type: ObservableType
    hash_algorithm: str | None
    is_private: bool
    refanged: bool
    tlp: Tlp
    compatible_analyzers: list[str]
    compatible_connectors: list[str]
    compatible_pivots: list[str]
    compatible_playbooks: list[str]
    # Plugins that support this type but cannot run, each with the reason.
    unavailable_analyzers: list[dict[str, str]]
    unavailable_plugins: list[dict[str, str]]
    auto_select: bool
    default_scan_mode: ScanMode


class PluginReportOut(BaseModel):
    id: uuid.UUID
    plugin_name: str
    plugin_type: PluginKind
    status: ReportStatus
    summary_data: dict[str, Any]
    errors: str | None
    execution_time_ms: int | None
    from_cache: bool
    derived_observables: list[dict[str, Any]]
    spawned_job_ids: list[uuid.UUID]
    created_at: datetime
    finished_at: datetime | None


class PluginReportDetail(PluginReportOut):
    raw_output: dict[str, Any] | None


class JobSummaryOut(BaseModel):
    id: uuid.UUID
    observable_value: str
    observable_type: ObservableType
    status: JobStatus
    verdict: Verdict
    tags: list[str]
    tlp: Tlp
    playbook_name: str | None
    requested_by_name: str
    # Which entry point submitted it. The account alone cannot say whether the
    # analyst ran this themselves or the assistant ran it for them.
    origin: JobOrigin = JobOrigin.UI
    created_at: datetime
    finished_at: datetime | None
    analyzer_count: int
    # Pivot lineage, so a list can show that a job was derived rather than asked for.
    parent_job_id: uuid.UUID | None = None
    pivot_name: str | None = None
    depth: int = 0


class JobDetailOut(JobSummaryOut):
    # Present when the job was submitted as a file rather than as a value. The
    # stored path is deliberately absent: it is an internal location, and the
    # bytes are never served back.
    file_name: str | None = None
    file_size: int | None = None
    requested_analyzers: list[str]
    requested_connectors: list[str]
    requested_pivots: list[str]
    force_rescan: bool
    scan_mode: ScanMode
    scan_check_minutes: int | None
    runtime_configuration: dict[str, Any]
    summary: dict[str, Any]
    started_at: datetime | None
    reports: list[PluginReportOut]


class JobTagsUpdate(StrictModel):
    tags: list[str] = Field(default_factory=list, max_length=20)
