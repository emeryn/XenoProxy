"""ANY.RUN: the public feed of interactive sandbox runs.

ANY.RUN's value to an analyst is the network trace of a sample executing — the
addresses it dialled, the requests it made. Those become the indicators to hunt
for in their own traffic.

This analyzer reads the **public** task feed only. It does not submit, and it
does not drive an interactive session. Two reasons: a submission on the free
plan is published, which turns a lookup into a disclosure; and detonation is a
decision an analyst takes deliberately, not a side effect of asking a question.

A run that an operator can see being started is also a warning to them, which
is the quiet reason passive reading matters more than it looks.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import (
    PluginQuotaError,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register
from app.services.observables import Observable

BASE = "https://api.any.run/v1"

_VERDICT = {
    "malicious": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    "no threats detected": Verdict.CLEAN,
}


@register
class AnyRunAnalyzer(BaseAnalyzer):
    """Public sandbox runs for a sample, and the traffic they produced."""

    name = "anyrun"
    label = "ANY.RUN"
    description = "Public interactive sandbox runs for a sample, with their network activity."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.HASH,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="From your ANY.RUN profile. The public feed needs a plan that exposes it.",
            placeholder="from app.any.run",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="ANY.RUN",
        url="https://any.run/",
        api_base_url="https://api.any.run/v1/analysis",
        credential_url="https://app.any.run/profile (API)",
        free_tier=(
            "The community plan publishes every submission and does not expose the API. "
            "Reading the feed through the API needs a paid plan."
        ),
        rate_limit="Per plan.",
        notes=(
            "Reads existing public runs only; it never submits. A submission on the free plan "
            "is published, and starting a run is visible to whoever is watching."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 45
    default_cache_ttl = 86400
    documentation_url = "https://any.run/api-documentation/"

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.get(
            f"{BASE}/analysis",
            params={"hash": observable.value, "limit": 10},
            headers={
                "Authorization": f"API-Key {self.secret('api_key')}",
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("ANY.RUN returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError(
                "ANY.RUN rejected the key, or the plan does not expose the API."
            )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        tasks = [
            entry
            for entry in (raw.get("data") or {}).get("tasks") or []
            if isinstance(entry, dict)
        ]
        if not tasks:
            return self.not_found("ANY.RUN has no public run for this sample.")

        worst = Verdict.UNKNOWN
        names: list[str] = []
        for task in tasks:
            verdict_text = str(
                task.get("verdict") or task.get("threatLevelText") or ""
            ).lower()
            mapped = _VERDICT.get(verdict_text, Verdict.UNKNOWN)
            if mapped is Verdict.MALICIOUS:
                worst = Verdict.MALICIOUS
            elif mapped is Verdict.SUSPICIOUS and worst is not Verdict.MALICIOUS:
                worst = Verdict.SUSPICIOUS
            name = str(task.get("name") or "")
            if name:
                names.append(name)

        newest = tasks[0]
        permanent = str(newest.get("permanentUrl") or "")

        return self.ok(
            raw,
            PluginSummary(
                verdict=worst,
                tags=names[:10],
                headline=(
                    f"{len(tasks)} public run(s); worst verdict {worst.value}. "
                    "Open a run for its network trace."
                ),
                links=[{"label": "Open the run", "url": permanent}] if permanent else [],
                extra={
                    "runs": len(tasks),
                    "names": names[:20],
                    "latest": {
                        "date": newest.get("date"),
                        "verdict": newest.get("verdict"),
                        "permanent_url": permanent,
                    },
                },
            ),
        )
