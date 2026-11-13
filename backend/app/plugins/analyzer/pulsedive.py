"""Pulsedive: one lookup that already crossed the other feeds.

An aggregator earns its place when it saves an analyst from running six
sources by hand. Pulsedive answers for an address, a domain or a URL with a
risk level and, more usefully, the *feeds that contributed it* — so a verdict
arrives with its provenance rather than as a number to trust.
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

_RISK = {
    "critical": Verdict.MALICIOUS,
    "high": Verdict.MALICIOUS,
    "medium": Verdict.SUSPICIOUS,
    "low": Verdict.SUSPICIOUS,
    "none": Verdict.CLEAN,
    "unknown": Verdict.UNKNOWN,
    "retired": Verdict.UNKNOWN,
}


@register
class PulsediveAnalyzer(BaseAnalyzer):
    """A crossed risk level, with the feeds that produced it."""

    name = "pulsedive"
    label = "Pulsedive"
    description = "A risk level for an address, domain or URL, with its contributing feeds."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="A free account gives a key immediately.",
            placeholder="from your Pulsedive account",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Pulsedive",
        url="https://pulsedive.com/",
        api_base_url="https://pulsedive.com/api/v1/info.php?indicator={value}",
        credential_url="https://pulsedive.com/account (API key)",
        free_tier="Free account: around 50 lookups a day.",
        rate_limit="1 request per second on the free plan.",
        notes=(
            "Returns the feeds that contributed the risk level, so a verdict comes with its "
            "provenance rather than as a bare score."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 30
    default_cache_ttl = 43200
    documentation_url = "https://pulsedive.com/api/"

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.get(
            "https://pulsedive.com/api/v1/info.php",
            params={
                "indicator": observable.value,
                "pretty": "0",
                "key": self.secret("api_key"),
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Pulsedive returned HTTP 429.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        # The service answers 200 with an `error` key for an unknown indicator.
        if raw.get("error"):
            return self.not_found(str(raw["error"])[:200])

        risk = str(raw.get("risk") or "unknown").lower()
        threats = [
            str(entry.get("name") or "")
            for entry in raw.get("threats") or []
            if isinstance(entry, dict)
        ]
        feeds = [
            str(entry.get("name") or "")
            for entry in raw.get("feeds") or []
            if isinstance(entry, dict)
        ]

        headline = f"Risk: {risk}"
        if threats:
            headline += f" — {', '.join(threats[:4])}"
        if feeds:
            headline += f" (seen in {len(feeds)} feed(s))"

        return self.ok(
            raw,
            PluginSummary(
                verdict=_RISK.get(risk, Verdict.UNKNOWN),
                tags=[entry for entry in (*threats, *feeds) if entry][:20],
                headline=headline,
                links=[
                    {
                        "label": "Open in Pulsedive",
                        "url": f"https://pulsedive.com/indicator/?iid={raw.get('iid', '')}",
                    }
                ],
                extra={
                    "risk": risk,
                    "risk_recommended": raw.get("risk_recommended"),
                    "threats": threats,
                    "feeds": feeds,
                    "stamp_seen": raw.get("stamp_seen"),
                    "stamp_retired": raw.get("stamp_retired"),
                },
            ),
        )
