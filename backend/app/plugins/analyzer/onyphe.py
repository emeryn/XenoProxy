"""Onyphe summary lookup."""

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
from app.plugins.user_keys import USER_KEY_HELP
from app.services.observables import Observable, hostname_of

_BASE = "https://www.onyphe.io/api/v2"
_THREAT_CATEGORIES = {"threatlist", "vulnscan", "datascan"}


@register
class OnypheAnalyzer(BaseAnalyzer):
    """Aggregated Onyphe summary for an IP address or a domain."""

    name = "onyphe"
    label = "Onyphe"
    description = "Aggregated exposure, threat lists, open ports and geolocation."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="Onyphe API key. " + USER_KEY_HELP,
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="ONYPHE",
        url="https://www.onyphe.io/",
        api_base_url="https://www.onyphe.io/api/v2/summary/{ip|domain|hostname}/{value}",
        credential_url="https://www.onyphe.io/login/ (Account, API key)",
        free_tier="A free account allows a few hundred queries per month on the summary endpoints.",
        rate_limit="Published per plan.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://www.onyphe.io/docs/apis"

    async def run(self, observable: Observable) -> PluginResult:
        if observable.type is ObservableType.IP:
            endpoint = f"{_BASE}/summary/ip/{observable.value}"
        else:
            endpoint = f"{_BASE}/summary/domain/{hostname_of(observable)}"

        response = await http_client.get(
            endpoint,
            headers={"Authorization": f"apikey {self.secret('api_key')}"},
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Onyphe returned HTTP 429.")
        if response.status_code == 404:
            return self.not_found("Onyphe has no record for this observable.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        results = [item for item in raw.get("results") or [] if isinstance(item, dict)]
        if not results:
            return self.not_found("Onyphe has no record for this observable.")

        ports: list[int] = []
        tags: set[str] = set()
        cves: set[str] = set()
        hostnames: set[str] = set()
        country: str | None = None
        asn: str | None = None
        organisation: str | None = None
        on_threatlist = False

        for item in results:
            category = str(item.get("@category") or "")
            if category == "threatlist":
                on_threatlist = True
                if item.get("threatlist"):
                    tags.add(str(item["threatlist"]).lower())
            if isinstance(item.get("port"), int):
                ports.append(int(item["port"]))
            for cve in item.get("cve") or []:
                cves.add(str(cve).upper())
            for tag in item.get("tag") or []:
                tags.add(str(tag).lower())
            for hostname in item.get("hostname") or []:
                hostnames.add(str(hostname))
            country = country or item.get("country")
            asn = asn or item.get("asn")
            organisation = organisation or item.get("organization")

        if on_threatlist:
            verdict = Verdict.MALICIOUS
        elif cves:
            verdict = Verdict.SUSPICIOUS
        elif ports:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN

        summary = PluginSummary(
            verdict=verdict,
            tags=sorted(tags),
            open_ports=ports,
            country=country,
            asn=asn,
            organisation=organisation,
            hostnames=sorted(hostnames),
            cves=sorted(cves),
            headline=(
                "Present on at least one Onyphe threat list."
                if on_threatlist
                else f"{len(results)} Onyphe record(s) across {len(set(ports))} port(s)."
            ),
            extra={
                "categories": sorted(
                    {str(item.get("@category")) for item in results if item.get("@category")}
                ),
                "total": raw.get("total"),
            },
        )
        return self.ok(raw, summary)
