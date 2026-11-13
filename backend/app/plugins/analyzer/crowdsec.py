"""CrowdSec CTI: what a community of firewalls has seen an address do.

The signal comes from the blocklists of the people running CrowdSec, so it is
behavioural rather than reputational: an address appears because it was caught
doing something at somebody's edge, with the behaviour named — credential
stuffing, port scanning, exploiting a specific CVE.

That naming is the point. "Reported 40 times" tells an analyst to block;
"brute-forcing SSH, last seen two hours ago, from a residential range" tells
them what happened and whether it matches what they are looking at.
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

# How the service grades an address. Anything above `safe` is a finding.
_MALICIOUS = {"suspicious", "known", "aggressive"}


@register
class CrowdSecAnalyzer(BaseAnalyzer):
    """Community-reported behaviour for an address, with the behaviour named."""

    name = "crowdsec"
    label = "CrowdSec CTI"
    description = "What a community of firewalls caught an address doing, and when."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="From the CrowdSec console, under CTI.",
            placeholder="from app.crowdsec.net",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="CrowdSec CTI",
        url="https://www.crowdsec.net/cti-api",
        api_base_url="https://cti.api.crowdsec.net/v2/smoke/{ip}",
        credential_url="https://app.crowdsec.net/ (Settings, API keys)",
        free_tier="Free tier with a daily lookup allowance; a signal-sharing instance raises it.",
        rate_limit="Published per plan; the free one is a few dozen lookups a day.",
        notes=(
            "Behavioural rather than reputational: an address is listed because it was caught "
            "acting, and the behaviour is named."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 25
    default_cache_ttl = 21600
    documentation_url = "https://docs.crowdsec.net/docs/cti_api/getting_started"

    async def run(self, observable: Observable) -> PluginResult:
        address = await self.address_of(observable)
        if address is None:
            return self.not_found("The name does not resolve to a public address.")

        response = await http_client.get(
            f"https://cti.api.crowdsec.net/v2/smoke/{address}",
            headers={"x-api-key": self.secret("api_key"), "Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("CrowdSec has no report for this address.")
        if response.status_code == 429:
            raise PluginQuotaError("CrowdSec returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("CrowdSec rejected the configured API key.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        reputation = str(raw.get("reputation") or "unknown").lower()
        behaviours = [
            str(entry.get("label") or entry.get("name") or "")
            for entry in raw.get("behaviors") or []
            if isinstance(entry, dict)
        ]
        classifications = [
            str(entry.get("label") or entry.get("name") or "")
            for entry in (raw.get("classifications") or {}).get("classifications") or []
            if isinstance(entry, dict)
        ]
        scores = (raw.get("scores") or {}).get("overall") or {}
        total = scores.get("total")
        background_noise = raw.get("background_noise_score")

        verdict = (
            Verdict.MALICIOUS
            if reputation in _MALICIOUS
            else Verdict.CLEAN
            if reputation == "safe"
            else Verdict.UNKNOWN
        )

        named = ", ".join(entry for entry in behaviours if entry)[:160]
        headline = f"Reputation: {reputation}"
        if named:
            headline += f" — {named}"

        return self.ok(
            raw,
            PluginSummary(
                verdict=verdict,
                score=int(total) if isinstance(total, int) else None,
                tags=[entry for entry in (*behaviours, *classifications) if entry][:20],
                asn=str(raw.get("as_num") or "") or None,
                organisation=str(raw.get("as_name") or "") or None,
                country=str(raw.get("location", {}).get("country") or "") or None,
                headline=headline + self.resolved_note(observable, address),
                links=[
                    {
                        "label": "Open in CrowdSec",
                        "url": f"https://app.crowdsec.net/cti/{address}",
                    }
                ],
                extra={
                    "reputation": reputation,
                    "behaviors": behaviours,
                    "classifications": classifications,
                    "background_noise_score": background_noise,
                    "first_seen": (raw.get("history") or {}).get("first_seen"),
                    "last_seen": (raw.get("history") or {}).get("last_seen"),
                    "attack_details": [
                        str(entry.get("name") or "")
                        for entry in raw.get("attack_details") or []
                        if isinstance(entry, dict)
                    ][:30],
                },
            ),
        )
