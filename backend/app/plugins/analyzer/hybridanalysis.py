"""Hybrid Analysis (Falcon Sandbox): what a sample did when it ran.

A hash lookup says whether a file is known. A sandbox report says what it
*does*: the addresses it called, the registry keys it wrote, the processes it
started. Those are the indicators an analyst takes back to their own logs to
find out who else was hit, which is the step that turns one sample into an
incident scope.

This analyzer only **reads** existing reports. It never submits: detonating a
sample is a decision with consequences — it can be published, it can tip off an
operator watching their own infrastructure — and it is not something a lookup
should do by itself.
"""

from __future__ import annotations

from typing import ClassVar

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

BASE = "https://www.hybrid-analysis.com/api/v2"

_VERDICT = {
    "malicious": Verdict.MALICIOUS,
    "suspicious": Verdict.SUSPICIOUS,
    "no specific threat": Verdict.CLEAN,
    "whitelisted": Verdict.CLEAN,
}


@register
class HybridAnalysisAnalyzer(BaseAnalyzer):
    """Behavioural indicators from an existing Falcon Sandbox report."""

    name = "hybridanalysis"
    label = "Hybrid Analysis"
    description = "What a sample did when it ran: contacted hosts, dropped files, registry keys."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.HASH,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="From your Hybrid Analysis profile, under API key.",
            placeholder="from hybrid-analysis.com",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Hybrid Analysis (Falcon Sandbox)",
        url="https://www.hybrid-analysis.com/",
        api_base_url="https://www.hybrid-analysis.com/api/v2/search/hash",
        credential_url="https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab",
        free_tier="Free account after validation; vetted researchers get a higher tier.",
        rate_limit="Per plan; the free account is a few hundred lookups a day.",
        notes=(
            "Reads existing reports only. It never submits a sample: detonation can publish "
            "the file and can tip off whoever is watching the infrastructure."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 45
    default_cache_ttl = 86400
    documentation_url = "https://www.hybrid-analysis.com/docs/api/v2"

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.post(
            f"{BASE}/search/hash",
            data={"hash": observable.value},
            headers={
                "api-key": self.secret("api_key"),
                "User-Agent": "Falcon Sandbox",
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Hybrid Analysis returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("Hybrid Analysis rejected the configured API key.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        reports = [entry for entry in response.json_body or [] if isinstance(entry, dict)]
        if not reports:
            return self.not_found("Hybrid Analysis has no report for this sample.")

        # The most informative report wins, not the newest: a run that saw
        # nothing is not evidence of a clean sample.
        report = max(reports, key=lambda entry: int(entry.get("threat_score") or 0))

        verdict_text = str(report.get("verdict") or "").lower()
        threat_score = report.get("threat_score")
        family = str(report.get("vx_family") or "")

        hosts = [str(entry) for entry in report.get("hosts") or [] if entry]
        domains = [str(entry) for entry in report.get("domains") or [] if entry]
        signatures = [
            str(entry.get("name") or "")
            for entry in report.get("signatures") or []
            if isinstance(entry, dict)
        ]

        headline = f"Verdict: {verdict_text or 'unknown'}"
        if family:
            headline += f" ({family})"
        if hosts or domains:
            headline += f" — contacted {len(hosts)} host(s), {len(domains)} domain(s)"

        return self.ok(
            {"reports": reports, "selected": report},
            PluginSummary(
                verdict=_VERDICT.get(verdict_text, Verdict.UNKNOWN),
                score=int(threat_score) if isinstance(threat_score, int) else None,
                tags=[tag for tag in (verdict_text, family, *signatures[:8]) if tag],
                hostnames=domains[:60],
                headline=headline,
                links=[
                    {
                        "label": "Open the report",
                        "url": f"https://www.hybrid-analysis.com/sample/{report.get('sha256', '')}",
                    }
                ],
                extra={
                    "family": family,
                    "threat_score": threat_score,
                    "av_detect": report.get("av_detect"),
                    "environment": report.get("environment_description"),
                    # The indicators an analyst takes back to their own logs.
                    "contacted_hosts": hosts[:100],
                    "contacted_domains": domains[:100],
                    "signatures": signatures[:40],
                    "processes": report.get("total_processes"),
                    "submit_name": report.get("submit_name"),
                },
            ),
        )
