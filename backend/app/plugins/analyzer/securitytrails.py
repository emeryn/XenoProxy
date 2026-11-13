"""SecurityTrails: the history of a name, and everything under it.

Two questions this answers that a live lookup cannot.

*What did this used to point at?* Infrastructure moves — a domain seized, a
host re-pointed at a sinkhole, a phishing site parked after the campaign. The
current record describes today; the history describes the campaign.

*What else is under this name?* Enumerating subdomains is how typosquatting and
forgotten staging hosts are found, and it is the step an analyst would
otherwise do by hand against a certificate log.
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
from app.services.observables import Observable, hostname_of

BASE = "https://api.securitytrails.com/v1"


@register
class SecurityTrailsAnalyzer(BaseAnalyzer):
    """Current records, subdomains and the history of a name."""

    name = "securitytrails"
    label = "SecurityTrails"
    description = "Subdomains, current DNS and the history of a name's infrastructure."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="From your SecurityTrails account.",
            placeholder="from securitytrails.com",
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "max_subdomains": {
            "type": "integer",
            "default": 200,
            "label": "Subdomains to keep in the report",
        },
    }
    provider = ProviderInfo(
        name="SecurityTrails",
        url="https://securitytrails.com/",
        api_base_url="https://api.securitytrails.com/v1/domain/{domain}",
        credential_url="https://securitytrails.com/app/account/credentials",
        free_tier="Free tier: 50 queries a month. Each run here spends two.",
        rate_limit="Per plan; the free tier is small enough to exhaust in a session.",
        notes=(
            "Two calls per run: the current record, then the subdomain list. Worth setting a "
            "long cache window on the free tier."
        ),
    )
    max_tlp = Tlp.AMBER
    default_timeout = 40
    # Expensive on the free tier, and a name's history does not move hourly.
    default_cache_ttl = 604800
    documentation_url = "https://docs.securitytrails.com/reference"

    async def _call(self, path: str) -> Any:
        response = await http_client.get(
            f"{BASE}{path}",
            headers={"APIKEY": self.secret("api_key"), "Accept": "application/json"},
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("SecurityTrails returned HTTP 429: the quota is spent.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("SecurityTrails rejected the configured API key.")
        return response

    async def run(self, observable: Observable) -> PluginResult:
        host = hostname_of(observable)
        if not host:
            return self.skipped("This observable carries no hostname.")

        current = await self._call(f"/domain/{host}")
        if current.status_code == 404:
            return self.not_found("SecurityTrails has no record for this name.")
        if not current.ok:
            return self.provider_http_error(current.status_code)
        raw: dict[str, Any] = current.json_body or {}

        # The subdomain list is a second call, and a failure there must not
        # lose the record that already came back.
        subdomains: list[str] = []
        listing = await self._call(f"/domain/{host}/subdomains")
        if listing.ok:
            limit = max(1, int(self.option("max_subdomains", 200)))
            subdomains = [
                f"{entry}.{host}"
                for entry in (listing.json_body or {}).get("subdomains") or []
                if isinstance(entry, str)
            ][:limit]

        dns = raw.get("current_dns") or {}
        addresses = [
            str(value.get("ip") or "")
            for value in (dns.get("a") or {}).get("values") or []
            if isinstance(value, dict)
        ]
        mail = [
            str(value.get("hostname") or "")
            for value in (dns.get("mx") or {}).get("values") or []
            if isinstance(value, dict)
        ]

        headline = f"{len(subdomains)} subdomain(s)"
        if addresses:
            headline += f", resolving to {', '.join(addresses[:3])}"

        return self.ok(
            {"domain": raw, "subdomains": subdomains},
            PluginSummary(
                # Inventory is not a judgement: a name having many subdomains
                # says nothing about whether it is hostile.
                verdict=Verdict.UNKNOWN,
                hostnames=subdomains[:200],
                headline=headline,
                links=[
                    {
                        "label": "Open in SecurityTrails",
                        "url": f"https://securitytrails.com/domain/{host}/dns",
                    }
                ],
                extra={
                    "subdomain_count": len(subdomains),
                    "addresses": addresses,
                    "mail_servers": mail,
                    "alexa_rank": raw.get("alexa_rank"),
                    "apex_domain": raw.get("apex_domain"),
                    "hostname": raw.get("hostname"),
                },
            ),
        )
