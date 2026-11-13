"""Connector contract: publish a finished job somewhere else.

A connector is the mirror image of an analyzer. It does not read an observable
to learn about it; it takes the verdict the analysis produced and pushes it to a
platform the team already runs — a threat intelligence store, a ticketing
system, a chat channel, a workflow engine.

Two consequences follow, and they are the reason connectors are a separate type
rather than an analyzer with a flag:

- A connector runs in its own phase, after the analysis phase has aggregated a
  verdict. Running it alongside the analyzers would publish an empty verdict.
- A connector is selected by intent, never by observable type. It is not offered
  to the analyst because the observable happens to be an IP; it is offered
  because the operator wants results exported.
"""

from __future__ import annotations

import abc
from typing import ClassVar

from app.models.job import JobStatus, Verdict
from app.plugins.base.plugin import (
    BasePlugin,
    JobContext,
    PluginResult,
    PluginType,
)


class BaseConnector(BasePlugin):
    """A plugin that exports a finished job to an external platform."""

    plugin_type = PluginType.CONNECTOR

    # Export only when the aggregated verdict is one of these. Empty means
    # "whatever the verdict", which is right for an archival target and wrong
    # for a target that pages someone.
    run_on_verdicts: ClassVar[tuple[Verdict, ...]] = ()
    # Export even when some analyzers failed. A partial picture is usually still
    # worth archiving, so this defaults to True; a connector that must not
    # publish an incomplete record sets it to False.
    run_on_partial_failure: ClassVar[bool] = True

    @abc.abstractmethod
    async def run(self, context: JobContext) -> PluginResult:
        """Push the finished job to the target platform."""

    async def _invoke(self, payload: JobContext) -> PluginResult:
        return await self.run(payload)

    def refusal_reason(self, context: JobContext, job_status: JobStatus) -> str | None:
        """Return why this connector declines the job, or None to run it.

        The orchestrator calls this before building the connector, so a declined
        export is recorded as SKIPPED with an explicit reason rather than
        silently omitted.
        """
        if not self.supports(context.observable.type):
            return f"does not export a {context.observable.type.value} observable"
        if self.run_on_verdicts and context.verdict not in self.run_on_verdicts:
            allowed = ", ".join(entry.value for entry in self.run_on_verdicts)
            return f"verdict is {context.verdict.value}; exports only {allowed}"
        if not self.run_on_partial_failure and job_status is not JobStatus.SUCCESS:
            return f"the analysis ended in {job_status.value} and this export requires a full run"
        if job_status is JobStatus.FAILED:
            return "every analyzer failed, so there is nothing to export"
        return None
