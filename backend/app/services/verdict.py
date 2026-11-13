"""Aggregation of per-plugin reports into a single job verdict.

Only analyzer reports carry intelligence about the observable, so only they
decide the verdict. A connector reporting "exported successfully" says nothing
about whether the address is malicious, and a pivot reporting "two observables
to analyse next" says nothing either. Letting them vote would make the verdict
depend on which exports an operator happens to have enabled.

The job status, by contrast, covers every phase: an export that failed is a
failure the analyst needs to see, which is why it degrades the job to
PARTIAL_FAILURE without touching the verdict.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.models.job import JobStatus, PluginKind, PluginReport, ReportStatus, Verdict

_SEVERITY = {
    Verdict.UNKNOWN: 0,
    Verdict.CLEAN: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}

_TERMINAL = {
    ReportStatus.SUCCESS,
    ReportStatus.FAILED,
    ReportStatus.SKIPPED,
    ReportStatus.KILLED,
}


def analyzer_reports(reports: Sequence[PluginReport]) -> list[PluginReport]:
    return [report for report in reports if report.plugin_type is PluginKind.ANALYZER]


def aggregate_verdict(reports: Sequence[PluginReport]) -> Verdict:
    """Take the worst verdict reported by any successful analyzer.

    OSINT sources disagree often; for triage the analyst needs the worst case
    surfaced, with the per-analyzer detail one click away.
    """
    worst = Verdict.UNKNOWN
    for report in analyzer_reports(reports):
        if report.status is not ReportStatus.SUCCESS:
            continue
        raw = (report.summary_data or {}).get("verdict")
        try:
            candidate = Verdict(raw)
        except ValueError:
            continue
        if _SEVERITY[candidate] > _SEVERITY[worst]:
            worst = candidate
    return worst


def aggregate_status(reports: Sequence[PluginReport]) -> JobStatus:
    """A single failing plugin never fails the job: it degrades it to partial."""
    if not reports:
        return JobStatus.FAILED
    if any(report.status not in _TERMINAL for report in reports):
        return JobStatus.RUNNING

    succeeded = sum(1 for report in reports if report.status is ReportStatus.SUCCESS)
    failed = sum(1 for report in reports if report.status is ReportStatus.FAILED)
    killed = sum(1 for report in reports if report.status is ReportStatus.KILLED)

    if killed and not succeeded:
        return JobStatus.KILLED
    if succeeded and (failed or killed):
        return JobStatus.PARTIAL_FAILURE
    if succeeded:
        return JobStatus.SUCCESS
    if failed:
        return JobStatus.FAILED
    # Everything was skipped: nothing ran, but nothing broke either.
    return JobStatus.SUCCESS


def build_summary(reports: Sequence[PluginReport]) -> dict[str, Any]:
    """Merge analyzer summaries into the synthetic view shown at the top of a job."""
    tags: set[str] = set()
    ports: set[int] = set()
    cves: set[str] = set()
    hostnames: set[str] = set()
    countries: set[str] = set()
    organisations: set[str] = set()
    asns: set[str] = set()
    detections: dict[str, str] = {}
    scores: dict[str, int] = {}

    analyzers = analyzer_reports(reports)
    for report in analyzers:
        if report.status is not ReportStatus.SUCCESS:
            continue
        summary = report.summary_data or {}
        tags.update(str(tag) for tag in summary.get("tags") or [])
        ports.update(int(port) for port in summary.get("open_ports") or [] if isinstance(port, int))
        cves.update(str(cve) for cve in summary.get("cves") or [])
        hostnames.update(str(name) for name in summary.get("hostnames") or [])
        if summary.get("country"):
            countries.add(str(summary["country"]))
        if summary.get("organisation"):
            organisations.add(str(summary["organisation"]))
        if summary.get("asn"):
            asns.add(str(summary["asn"]))
        if summary.get("detection_ratio"):
            detections[report.plugin_name] = str(summary["detection_ratio"])
        if isinstance(summary.get("score"), int):
            scores[report.plugin_name] = int(summary["score"])

    return {
        "tags": sorted(tags)[:60],
        "open_ports": sorted(ports)[:200],
        "cves": sorted(cves)[:200],
        "hostnames": sorted(hostnames)[:50],
        "countries": sorted(countries),
        "organisations": sorted(organisations)[:10],
        "asns": sorted(asns)[:10],
        "detection_ratios": detections,
        "scores": scores,
        "analyzers_succeeded": sum(1 for r in analyzers if r.status is ReportStatus.SUCCESS),
        "analyzers_failed": sum(1 for r in analyzers if r.status is ReportStatus.FAILED),
        "analyzers_skipped": sum(1 for r in analyzers if r.status is ReportStatus.SKIPPED),
        "analyzers_from_cache": sum(1 for r in analyzers if r.from_cache),
        **_phase_counts(reports),
    }


def _phase_counts(reports: Sequence[PluginReport]) -> dict[str, Any]:
    """Per-phase tallies, so the UI can show what each phase did."""
    counts: dict[str, Any] = {}
    for kind, label in (
        (PluginKind.CONNECTOR, "connectors"),
        (PluginKind.PIVOT, "pivots"),
    ):
        phase = [report for report in reports if report.plugin_type is kind]
        if not phase:
            continue
        counts[f"{label}_succeeded"] = sum(1 for r in phase if r.status is ReportStatus.SUCCESS)
        counts[f"{label}_failed"] = sum(1 for r in phase if r.status is ReportStatus.FAILED)
        counts[f"{label}_skipped"] = sum(1 for r in phase if r.status is ReportStatus.SKIPPED)

    spawned = [
        str(job_id)
        for report in reports
        if report.plugin_type is PluginKind.PIVOT
        for job_id in (report.spawned_job_ids or [])
    ]
    if spawned:
        counts["spawned_job_ids"] = spawned
    return counts
