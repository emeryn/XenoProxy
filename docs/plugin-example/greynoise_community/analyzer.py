"""GreyNoise Community lookup, shipped as a reference plugin.

A plugin is an ordinary plugin class: it inherits one of the three base classes
and so declares its type, says what it supports and what credentials it needs,
and performs its calls through the shared HTTP client, so the egress proxy, the
internal certificate authority, timeouts and the SSRF guard all apply.

This one is an analyzer. A connector would inherit `BaseConnector` from
`app.plugins.base.connector` and implement `run(context)` against the finished
job; a pivot would inherit `BasePivot` from `app.plugins.base.pivot`, declare
`child_playbook`, and return the observables to analyse next.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import (
    PluginQuotaError,
    PluginResult,
    PluginSummary,
    SecretSpec,
)
from app.core import http_client
from app.models.job import ObservableType, Verdict
from app.services.observables import Observable


class GreyNoiseCommunityAnalyzer(BaseAnalyzer):
    """Mass-scanner classification for an IP address."""

    # Must match the "name" field of plugin.json and the folder name.
    name = "greynoise_community"
    label = "GreyNoise Community"
    description = "Mass-scanner classification and actor attribution for an IP address."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            required=True,
            help_text="Free GreyNoise Community API key.",
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "benign_is_clean": {
            "type": "boolean",
            "default": True,
            "label": "Treat a benign classification as Clean rather than Unknown",
        }
    }
    documentation_url = "https://docs.greynoise.io/reference/get_v3-community-ip"
    free_tier = True
    default_timeout = 30
    default_cache_ttl = 43200

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.get(
            f"https://api.greynoise.io/v3/community/{observable.value}",
            headers={"key": self.secret("api_key"), "Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("GreyNoise has not observed this address.")
        if response.status_code == 429:
            raise PluginQuotaError("GreyNoise returned HTTP 429.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        classification = str(raw.get("classification") or "unknown").lower()
        benign_is_clean = bool(self.option("benign_is_clean", True))

        verdict = {
            "malicious": Verdict.MALICIOUS,
            "suspicious": Verdict.SUSPICIOUS,
            "benign": Verdict.CLEAN if benign_is_clean else Verdict.UNKNOWN,
        }.get(classification, Verdict.UNKNOWN)

        tags = [classification]
        if raw.get("noise"):
            tags.append("internet-scanner")
        if raw.get("riot"):
            tags.append("common-business-service")

        actor = str(raw["name"]) if raw.get("name") else None
        return self.ok(
            raw,
            PluginSummary(
                verdict=verdict,
                tags=tags,
                organisation=actor,
                headline=(
                    f"GreyNoise classifies this address as {classification}"
                    + (f" ({actor})." if actor else ".")
                ),
                links=[{"label": "Open in GreyNoise", "url": str(raw.get("link") or "")}],
                extra={
                    "noise": raw.get("noise"),
                    "riot": raw.get("riot"),
                    "last_seen": raw.get("last_seen"),
                    "message": raw.get("message"),
                },
            ),
        )
