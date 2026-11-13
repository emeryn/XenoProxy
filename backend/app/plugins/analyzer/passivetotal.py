"""PassiveTotal (RiskIQ): where a name used to point.

Passive DNS is a record of resolutions actually observed, so it answers the
question a live lookup cannot: *what did this resolve to last month?* That is
how an analyst follows infrastructure that moves — a domain rotated across a
dozen hosts, a C2 re-pointed after a takedown, a phishing kit that moved on.

Run the other way, it answers "what else lived on this address", which is how
one seized host turns into the rest of the campaign.
"""

from __future__ import annotations

import base64
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
from app.services.observables import Observable, hostname_of

ENDPOINT = "https://api.riskiq.net/pt/v2/dns/passive"


@register
class PassiveTotalAnalyzer(BaseAnalyzer):
    """Observed resolutions over time, in both directions."""

    name = "passivetotal"
    label = "PassiveTotal (RiskIQ)"
    description = "Passive DNS: what a name resolved to over time, or what lived on an address."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.IP,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "username",
            "Account e-mail",
            help_text="The e-mail of the RiskIQ account the key belongs to.",
            placeholder="you@example.org",
        ),
        SecretSpec(
            "api_key",
            "API key",
            help_text="The secret half of the key pair, from the account page.",
            placeholder="from community.riskiq.com",
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "max_records": {
            "type": "integer",
            "default": 200,
            "label": "Resolutions to keep in the report",
        },
    }
    provider = ProviderInfo(
        name="PassiveTotal (RiskIQ)",
        url="https://community.riskiq.com/",
        api_base_url="https://api.riskiq.net/pt/v2/dns/passive",
        credential_url="https://community.riskiq.com/settings (API keys)",
        free_tier="Community account: a small monthly quota, enough for targeted lookups.",
        rate_limit="Per plan; the community quota is spent quickly by bulk use.",
        notes=(
            "Authenticates with the account e-mail and the key as a HTTP Basic pair, which is "
            "why both fields are required."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 40
    # History does not change by the hour, and the quota is small.
    default_cache_ttl = 86400
    documentation_url = "https://api.riskiq.net/api/"

    async def run(self, observable: Observable) -> PluginResult:
        query = (
            observable.value
            if observable.type is ObservableType.IP
            else hostname_of(observable)
        )
        if not query:
            return self.skipped("This observable carries nothing to look up.")

        pair = f"{self.secret('username')}:{self.secret('api_key')}".encode()
        response = await http_client.get(
            ENDPOINT,
            params={"query": query},
            headers={
                "Authorization": f"Basic {base64.b64encode(pair).decode()}",
                "Accept": "application/json",
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("PassiveTotal returned HTTP 429: the quota is spent.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("PassiveTotal rejected the configured credentials.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        records = [entry for entry in raw.get("results") or [] if isinstance(entry, dict)]
        if not records:
            return self.not_found("PassiveTotal has no observed resolution for this value.")

        limit = max(1, int(self.option("max_records", 200)))
        kept = records[:limit]
        resolutions = sorted(
            {str(entry.get("resolve") or "") for entry in kept if entry.get("resolve")}
        )

        seen_first = [str(e.get("firstSeen") or "") for e in kept if e.get("firstSeen")]
        seen_last = [str(e.get("lastSeen") or "") for e in kept if e.get("lastSeen")]
        first_seen = min(seen_first, default="")
        last_seen = max(seen_last, default="")

        headline = f"{len(records)} observed resolution(s), {len(resolutions)} distinct value(s)"
        if first_seen:
            headline += f", first seen {first_seen[:10]}"

        return self.ok(
            {"query": query, "total": len(records), "results": kept},
            PluginSummary(
                # History is context, not a judgement: a name having moved is
                # not on its own a sign of anything.
                verdict=Verdict.UNKNOWN,
                hostnames=[entry for entry in resolutions if not entry[0].isdigit()][:100],
                headline=headline,
                links=[
                    {
                        "label": "Open in PassiveTotal",
                        "url": f"https://community.riskiq.com/search/{query}",
                    }
                ],
                extra={
                    "distinct_resolutions": resolutions[:200],
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "total": len(records),
                },
            ),
        )
