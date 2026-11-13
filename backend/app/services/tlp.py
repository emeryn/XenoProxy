"""Traffic Light Protocol policy.

The level chosen for a job caps which analyzers may run on it. Each analyzer
declares the highest level it tolerates:

- `CLEAR`  the source publishes, indexes or shares the observable (URLScan
           submission, sandbox submission, anything that creates a public record).
- `AMBER`  the source receives the observable privately (most reputation APIs).
- `RED`    the analyzer never sends the observable anywhere outside the
           deployment (a local resolver, an internal reference set).

A job at RED therefore runs only RED-capable analyzers, GREEN runs GREEN and
below, and so on. This is the same ordering IntelOwl uses.
"""

from __future__ import annotations

from app.models.job import Tlp

# Ascending restriction: a job may use an analyzer whose maximum is at least as
# restrictive as the job's level.
_ORDER: dict[Tlp, int] = {
    Tlp.CLEAR: 0,
    Tlp.GREEN: 1,
    Tlp.AMBER: 2,
    Tlp.RED: 3,
}

DESCRIPTIONS: dict[Tlp, str] = {
    Tlp.CLEAR: "No restriction. Every source may run, including those that publish the observable.",
    Tlp.GREEN: "Sources that publish, index or retain the observable are excluded.",
    Tlp.AMBER: "Also limits who can see the job to the submitter's groups.",
    Tlp.RED: "Also excludes every external source; only local analyzers run.",
}


def rank(level: Tlp) -> int:
    return _ORDER[level]


def allows(job_tlp: Tlp, analyzer_max_tlp: Tlp) -> bool:
    """Report whether an analyzer may run on a job at this level."""
    return _ORDER[analyzer_max_tlp] >= _ORDER[job_tlp]


def restricts_visibility(level: Tlp) -> bool:
    """AMBER and above limit a job to the submitter's groups."""
    return _ORDER[level] >= _ORDER[Tlp.AMBER]


def describe(level: Tlp) -> str:
    return DESCRIPTIONS[level]


def refusal_reason(job_tlp: Tlp, analyzer_max_tlp: Tlp) -> str:
    return (
        f"not allowed at TLP:{job_tlp.value.upper()} "
        f"(the source is capped at TLP:{analyzer_max_tlp.value.upper()})"
    )
