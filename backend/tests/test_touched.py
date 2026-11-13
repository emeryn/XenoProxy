"""The observables a conversation looked at, read back from its tool steps.

The panel is derived rather than stored, so it is only as good as this
extraction. These pin the three shapes the tools actually answer with.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.services.assistant import touched


def test_a_single_object_yields_its_observable() -> None:
    steps = [
        {
            "tool": "get_job",
            "ok": True,
            "result": {
                "job_id": "f0b2",
                "observable": "1.1.1.1",
                "type": "ip",
                "verdict": "clean",
            },
        }
    ]
    assert touched.from_steps(steps) == [
        {"value": "1.1.1.1", "type": "ip", "verdict": "clean", "job_id": "f0b2"}
    ]


def test_a_list_result_yields_every_row() -> None:
    steps = [
        {
            "tool": "search_jobs",
            "ok": True,
            "result": [
                {"observable": "example.com", "type": "domain", "verdict": "unknown"},
                {"observable": "8.8.8.8", "type": "ip", "verdict": "malicious"},
            ],
        }
    ]
    values = [entry["value"] for entry in touched.from_steps(steps)]
    assert values == ["example.com", "8.8.8.8"]


def test_classify_uses_its_own_key_for_the_value() -> None:
    """`classify_observable` answers `value`, every other tool answers `observable`."""
    steps = [
        {
            "tool": "classify_observable",
            "ok": True,
            "result": {"value": "evil.test", "type": "domain"},
        }
    ]
    assert touched.from_steps(steps) == [{"value": "evil.test", "type": "domain"}]


def test_a_refused_step_contributes_nothing() -> None:
    """A tool that failed proves nothing was looked at."""
    steps = [{"tool": "get_job", "ok": False, "result": {"error": "not found"}}]
    assert touched.from_steps(steps) == []


def test_a_later_mention_updates_the_verdict() -> None:
    """A verdict settles as a job runs; the panel shows the latest state."""
    steps = [
        {"tool": "get_job", "ok": True, "result": {"observable": "1.1.1.1", "verdict": "unknown"}},
        {
            "tool": "get_job",
            "ok": True,
            "result": {"observable": "1.1.1.1", "verdict": "malicious"},
        },
    ]
    assert touched.from_steps(steps) == [{"value": "1.1.1.1", "verdict": "malicious"}]


def test_an_observable_nested_in_a_report_is_found() -> None:
    steps = [
        {
            "tool": "get_report",
            "ok": True,
            "result": {"job": {"observable": "deep.test", "type": "domain"}, "plugin": "dns"},
        }
    ]
    assert [entry["value"] for entry in touched.from_steps(steps)] == ["deep.test"]


def test_nothing_in_a_result_without_an_observable() -> None:
    steps = [
        {
            "tool": "list_plugins",
            "ok": True,
            "result": [{"name": "shodan", "type": "analyzer"}],
        }
    ]
    assert touched.from_steps(steps) == []


class _Job:
    """A job row, as `refresh` reads it back."""

    def __init__(self, job_id: uuid.UUID, status: str, verdict: str) -> None:
        self.id = job_id
        self.status = SimpleNamespace(value=status)
        self.verdict = SimpleNamespace(value=verdict)


class _Result:
    def __init__(self, rows: list[_Job]) -> None:
        self._rows = rows

    def scalars(self) -> list[_Job]:
        return self._rows


class _Session:
    def __init__(self, rows: list[_Job]) -> None:
        self._rows = rows

    async def execute(self, _statement: object) -> _Result:
        return _Result(self._rows)


@pytest.mark.asyncio
async def test_refresh_replaces_the_state_the_transcript_recorded() -> None:
    """A scan submitted from the chat is PENDING in the transcript forever."""
    job_id = uuid.uuid4()
    entries = [{"value": "9.9.9.9", "type": "ip", "status": "PENDING", "job_id": str(job_id)}]

    refreshed = await touched.refresh(
        _Session([_Job(job_id, "SUCCESS", "clean")]),  # type: ignore[arg-type]
        entries,
    )

    assert refreshed[0]["status"] == "SUCCESS"
    assert refreshed[0]["verdict"] == "clean"
    # What the transcript knows is left alone.
    assert refreshed[0]["value"] == "9.9.9.9"
    assert refreshed[0]["type"] == "ip"


@pytest.mark.asyncio
async def test_refresh_leaves_entries_without_a_job_alone() -> None:
    entries = [{"value": "example.com", "type": "domain"}]
    assert await touched.refresh(_Session([]), entries) == entries  # type: ignore[arg-type]
