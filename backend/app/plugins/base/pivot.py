"""Pivot contract: derive the next observable from a finished job.

A pivot is what turns a single enrichment into an investigation. It reads a
finished job, decides whether the result warrants going further, and names the
observables worth analysing next. The orchestrator then creates one child job
per derived observable, linked back to the parent.

The two guards that matter are here rather than in each pivot:

- `max_children` bounds the fan-out of one pivot, so a provider returning three
  hundred passive DNS records cannot create three hundred jobs.
- the orchestrator refuses to create a child beyond the configured depth, so a
  pivot chain that loops back on itself terminates.
"""

from __future__ import annotations

import abc
from typing import ClassVar

from app.models.job import ReportStatus, Verdict
from app.plugins.base.plugin import (
    BasePlugin,
    DerivedObservable,
    JobContext,
    PluginResult,
    PluginSummary,
    PluginType,
)


class BasePivot(BasePlugin):
    """A plugin that spawns child jobs from a finished job."""

    plugin_type = PluginType.PIVOT

    # Playbook the child jobs run. Empty falls back to the parent's own
    # selection, which is rarely what you want: a pivot usually moves to a
    # different observable type and therefore needs a different playbook.
    child_playbook: ClassVar[str] = ""
    # Pivot only on these verdicts. The default keeps a clean result from
    # generating work, which is what makes automatic pivoting affordable.
    run_on_verdicts: ClassVar[tuple[Verdict, ...]] = (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
    max_children: ClassVar[int] = 5
    # A pivot derives observables from reports already in hand, so by default it
    # makes no outbound call of its own.
    requires_network: ClassVar[bool] = False
    default_timeout: ClassVar[int] = 30

    @abc.abstractmethod
    async def run(self, context: JobContext) -> PluginResult:
        """Inspect the finished job and return the observables to analyse next."""

    async def _invoke(self, payload: JobContext) -> PluginResult:
        result = await self.run(payload)
        # The fan-out guard belongs here so no pivot can forget it.
        if len(result.derived) > self.max_children:
            result.derived = result.derived[: self.max_children]
        return result

    def refusal_reason(self, context: JobContext) -> str | None:
        """Return why this pivot declines the job, or None to run it."""
        if not self.supports(context.observable.type):
            return f"does not pivot from a {context.observable.type.value} observable"
        if self.run_on_verdicts and context.verdict not in self.run_on_verdicts:
            allowed = ", ".join(entry.value for entry in self.run_on_verdicts)
            return f"verdict is {context.verdict.value}; pivots only on {allowed}"
        return None

    def pivot_to(
        self, values: list[str], *, reason: str, raw: dict[str, object] | None = None
    ) -> PluginResult:
        """Build a successful result naming the observables to analyse next."""
        unique: list[DerivedObservable] = []
        seen: set[str] = set()
        for value in values:
            cleaned = (value or "").strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            unique.append(DerivedObservable(value=cleaned, reason=reason))

        headline = (
            f"{len(unique)} observable(s) to analyse next: {reason}"
            if unique
            else "nothing to pivot to"
        )
        return PluginResult(
            status=ReportStatus.SUCCESS,
            raw_output=raw if raw is not None else {"derived": [d.as_dict() for d in unique]},
            summary=PluginSummary(headline=headline, tags=[]),
            derived=unique,
        )

    def no_pivot(self, message: str = "nothing to pivot to") -> PluginResult:
        """Report that the job gave this pivot nothing to work with."""
        return PluginResult(
            status=ReportStatus.SUCCESS,
            raw_output={"derived": []},
            summary=PluginSummary(headline=message),
            derived=[],
        )
