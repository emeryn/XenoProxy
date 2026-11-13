"""Shodan host lookup."""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base import technologies
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import (
    PluginQuotaError,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register
from app.plugins.user_keys import USER_KEY_HELP
from app.services.observables import Observable

_RISK_TAGS = {"malware", "botnet", "c2", "compromised", "honeypot", "tor", "proxy", "scanner"}


@register
class ShodanAnalyzer(BaseAnalyzer):
    """Exposed services, banners and known vulnerabilities for an IP address."""

    name = "shodan"
    label = "Shodan"
    description = "Open ports, service banners, CVEs, ASN and geolocation for an IP address."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="Shodan account API key. " + USER_KEY_HELP,
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "minify": {"type": "boolean", "default": False, "label": "Request a minified record"}
    }
    provider = ProviderInfo(
        name="Shodan",
        url="https://www.shodan.io/",
        api_base_url="https://api.shodan.io/shodan/host/{ip}",
        credential_url="https://account.shodan.io/ (Account, API Key)",
        free_tier=(
            "No host lookups: the free plan cannot call this endpoint. A paid membership or an "
            "academic licence is required."
        ),
        rate_limit="1 request per second on every plan.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://developer.shodan.io/api"

    async def run(self, observable: Observable) -> PluginResult:
        address = await self.address_of(observable)
        if address is None:
            return self.not_found("The name does not resolve to a public address.")

        params = {"key": self.secret("api_key")}
        if self.option("minify", False):
            params["minify"] = "true"
        response = await http_client.get(
            f"https://api.shodan.io/shodan/host/{address}",
            params=params,
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("Shodan has no record for this address.")
        if response.status_code == 429:
            raise PluginQuotaError("Shodan returned HTTP 429.")
        if response.status_code == 401:
            raise PluginQuotaError("Shodan rejected the configured API key.")
        if response.status_code == 403:
            # Not a bad key: the free `oss` plan answers 403 "Requires
            # membership or higher" on this endpoint. Saying "rejected the
            # credential" sends the analyst to re-paste a key that is fine.
            # Shodan InternetDB covers the same ground without a key.
            raise PluginQuotaError(
                "Shodan refused the host lookup: this endpoint needs a paid membership "
                "(the free plan answers HTTP 403). Shodan InternetDB needs no key."
            )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        tags = [str(tag).lower() for tag in raw.get("tags") or []]
        stack = [
            technologies.clean(service.get("product"), service.get("version"))
            for service in raw.get("data") or []
            if isinstance(service, dict)
        ]
        stack.append(technologies.clean(raw.get("os")))
        cves = sorted({str(cve).upper() for cve in (raw.get("vulns") or [])})
        ports = [int(port) for port in raw.get("ports") or [] if isinstance(port, int)]

        if any(tag in _RISK_TAGS for tag in tags) or cves:
            verdict = (
                Verdict.MALICIOUS if any(t in _RISK_TAGS for t in tags) else Verdict.SUSPICIOUS
            )
        else:
            verdict = Verdict.CLEAN if ports else Verdict.UNKNOWN

        summary = PluginSummary(
            verdict=verdict,
            tags=tags,
            open_ports=ports,
            country=raw.get("country_name") or raw.get("country_code"),
            asn=raw.get("asn"),
            organisation=raw.get("org") or raw.get("isp"),
            hostnames=[str(host) for host in raw.get("hostnames") or []],
            technologies=[entry for entry in stack if entry],
            cves=cves,
            headline=(
                f"{len(ports)} open port(s), {len(cves)} known CVE(s)."
                + self.resolved_note(observable, address)
            ),
            links=[
                {"label": "Open in Shodan", "url": f"https://www.shodan.io/host/{address}"}
            ],
            extra={
                "last_update": raw.get("last_update"),
                "os": raw.get("os"),
                "services": [
                    {
                        "port": service.get("port"),
                        "transport": service.get("transport"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                    }
                    for service in (raw.get("data") or [])[:40]
                    if isinstance(service, dict)
                ],
            },
        )
        return self.ok(raw, summary)
