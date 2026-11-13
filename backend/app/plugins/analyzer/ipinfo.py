"""IPinfo geolocation and network ownership."""

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


@register
class IpInfoAnalyzer(BaseAnalyzer):
    """Geolocation, ASN, carrier and privacy flags for an IP address."""

    name = "ipinfo"
    label = "IPinfo"
    description = "Geolocation, ASN ownership and VPN/proxy/Tor privacy flags."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "token",
            "Access token",
            required=False,
            help_text="Optional; the free endpoint works without a token at a lower rate.",
        ),
    )
    provider = ProviderInfo(
        name="IPinfo",
        url="https://ipinfo.io/",
        api_base_url="https://ipinfo.io/{ip}/json",
        credential_url="https://ipinfo.io/account/token",
        free_tier=(
            "50 000 requests per month with a token; geolocation works without one, with tighter "
            "limits."
        ),
        rate_limit="Monthly quota rather than per-second.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://ipinfo.io/developers"
    free_tier = True
    default_timeout = 20

    async def run(self, observable: Observable) -> PluginResult:
        address = await self.address_of(observable)
        if address is None:
            return self.not_found("The name does not resolve to a public address.")

        token = self.optional_secret("token")
        params = {"token": token} if token else {}
        response = await http_client.get(
            f"https://ipinfo.io/{address}/json", params=params, timeout=self.timeout
        )
        if response.status_code == 429:
            raise PluginQuotaError("IPinfo returned HTTP 429.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        privacy = raw.get("privacy") or {}
        tags = [flag for flag, value in privacy.items() if value is True]
        if raw.get("bogon"):
            tags.append("bogon")

        asn_field = raw.get("asn")
        if isinstance(asn_field, dict):
            asn, organisation = asn_field.get("asn"), asn_field.get("name")
        else:
            org = str(raw.get("org") or "")
            asn = org.split(" ", 1)[0] if org.startswith("AS") else None
            organisation = (
                org.split(" ", 1)[1] if org.startswith("AS") and " " in org else org or None
            )

        risky = {"vpn", "proxy", "tor", "relay", "hosting"} & set(tags)
        summary = PluginSummary(
            verdict=Verdict.SUSPICIOUS if risky else Verdict.UNKNOWN,
            tags=tags,
            country=raw.get("country"),
            asn=asn,
            organisation=organisation,
            hostnames=[str(raw["hostname"])] if raw.get("hostname") else [],
            headline=(
                ", ".join(
                    part
                    for part in (raw.get("city"), raw.get("region"), raw.get("country"))
                    if part
                )
                or "No geolocation available."
            )
            + self.resolved_note(observable, address),
            links=[{"label": "Open in IPinfo", "url": f"https://ipinfo.io/{address}"}],
            extra={
                "loc": raw.get("loc"),
                "timezone": raw.get("timezone"),
                "postal": raw.get("postal"),
                "privacy": privacy,
                "company": raw.get("company"),
                "abuse": raw.get("abuse"),
            },
        )
        return self.ok(raw, summary)
