"""GreyNoise: whether an address is scanning everyone, or scanning you.

The internet is full of hosts that probe every address continuously —
researchers, census projects, worms, commodity botnets. They fill a firewall
log and look exactly like an attack until you know they hit everybody.

GreyNoise answers that one question, and it is the question that decides
whether an alert deserves an analyst. "Seen scanning the whole internet" turns
a page of log lines into noise to filter; absence from GreyNoise turns the same
line into something aimed at you.

That is why a `benign` classification here lowers nothing: a benign scanner is
still a scanner, and the finding is about the *targeting*, not the intent.
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

COMMUNITY = "https://api.greynoise.io/v3/community"


@register
class GreyNoiseAnalyzer(BaseAnalyzer):
    """Whether an address is indiscriminate background scanning."""

    name = "greynoise"
    label = "GreyNoise"
    description = "Whether an address scans the whole internet, or was aimed at you."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="A free community account is enough for this endpoint.",
            placeholder="from your GreyNoise account",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="GreyNoise",
        url="https://www.greynoise.io/",
        api_base_url="https://api.greynoise.io/v3/community/{ip}",
        credential_url="https://viz.greynoise.io/account/api-key",
        free_tier="The community endpoint is free, with a daily lookup allowance.",
        rate_limit="Community plan: a few thousand lookups a month.",
        notes=(
            "Answers whether an address is mass-scanning. A 'benign' classification means a "
            "known scanner, not a safe host, so it never improves a verdict."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 25
    default_cache_ttl = 43200
    documentation_url = "https://docs.greynoise.io/docs/using-the-greynoise-community-api"

    async def run(self, observable: Observable) -> PluginResult:
        address = await self.address_of(observable)
        if address is None:
            return self.not_found("The name does not resolve to a public address.")

        response = await http_client.get(
            f"{COMMUNITY}/{address}",
            headers={"key": self.secret("api_key"), "Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            # Not in the data set is itself the answer: this address is not
            # part of the internet-wide background noise.
            return self.ok(
                {"noise": False, "ip": address},
                PluginSummary(
                    verdict=Verdict.UNKNOWN,
                    tags=["not-background-noise"],
                    headline=(
                        "GreyNoise has not seen this address scanning. If it reached you, it "
                        "was not scanning everybody."
                    )
                    + self.resolved_note(observable, address),
                ),
            )
        if response.status_code == 429:
            raise PluginQuotaError("GreyNoise returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("GreyNoise rejected the configured API key.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        classification = str(raw.get("classification") or "unknown").lower()
        noise = bool(raw.get("noise"))
        name = str(raw.get("name") or "")

        # Only a malicious classification is a finding about the host. Benign
        # and unknown describe what it does to everyone, not what it did here.
        verdict = Verdict.MALICIOUS if classification == "malicious" else Verdict.UNKNOWN

        headline = (
            f"Mass-scanning, classified {classification}" if noise else "Not seen mass-scanning"
        )
        if name and name.lower() != "unknown":
            headline += f" ({name})"

        return self.ok(
            raw,
            PluginSummary(
                verdict=verdict,
                tags=[tag for tag in ("background-noise" if noise else "", classification) if tag],
                organisation=name or None,
                headline=headline + self.resolved_note(observable, address),
                links=[
                    {"label": "Open in GreyNoise", "url": f"https://viz.greynoise.io/ip/{address}"}
                ],
                extra={
                    "noise": noise,
                    "classification": classification,
                    "name": name,
                    "last_seen": raw.get("last_seen"),
                    "riot": raw.get("riot"),
                },
            ),
        )
