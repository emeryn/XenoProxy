"""Shodan InternetDB: the exposure of an address, without a Shodan licence.

Shodan's host endpoint needs a paid membership, which puts the most useful
exposure data behind a bill on a free deployment. InternetDB serves a reduced
view of the same crawl — open ports, hostnames, CPEs, known vulnerabilities —
free and unauthenticated. It is the one source that gives a fresh instance a
real answer about an address on day one.
"""

from __future__ import annotations

from typing import ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable


@register
class InternetDbAnalyzer(BaseAnalyzer):
    """Open ports, hostnames, software and CVEs Shodan saw on an address."""

    name = "shodan_internetdb"
    label = "Shodan InternetDB"
    description = "Open ports, hostnames, detected software and known CVEs, free and keyless."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    provider = ProviderInfo(
        name="Shodan InternetDB",
        url="https://internetdb.shodan.io/",
        api_base_url="https://internetdb.shodan.io/{ip}",
        free_tier="Free and unauthenticated. No account, no key.",
        rate_limit="Fair use; no published quota.",
        notes=(
            "A reduced view of the Shodan crawl. The full host record, with banners, needs the "
            "paid `shodan` analyzer."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 20
    documentation_url = "https://internetdb.shodan.io/"

    async def run(self, observable: Observable) -> PluginResult:
        from app.core import http_client

        address = await self.address_of(observable)
        if address is None:
            return self.not_found("The name does not resolve to a public address.")

        response = await http_client.get(
            f"https://internetdb.shodan.io/{address}", timeout=self.timeout
        )
        if response.status_code == 404:
            return self.not_found("Shodan has not seen this address.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw = response.json_body
        if not isinstance(raw, dict):
            return self.failed("InternetDB did not return a JSON object.")

        ports = [int(port) for port in raw.get("ports") or [] if isinstance(port, int)]
        cves = [str(entry) for entry in raw.get("vulns") or []]
        hostnames = [str(entry) for entry in raw.get("hostnames") or []]
        tags = [str(entry) for entry in raw.get("tags") or []]

        # Exposure is not a verdict. A host with open ports is a host, and
        # saying "suspicious" because it answers on 443 would make the
        # aggregated verdict useless. Known vulnerabilities are different: a
        # CVE on an exposed service is a finding an analyst has to see.
        verdict = Verdict.SUSPICIOUS if cves else Verdict.UNKNOWN
        headline = f"{len(ports)} open port(s)"
        if cves:
            headline += f", {len(cves)} known CVE(s)"

        return self.ok(
            raw,
            PluginSummary(
                verdict=verdict,
                tags=tags,
                open_ports=ports,
                cves=cves,
                hostnames=hostnames,
                headline=headline + self.resolved_note(observable, address),
                links=[
                    {
                        "label": "Open in Shodan",
                        "url": f"https://www.shodan.io/host/{address}",
                    }
                ],
                extra={"cpes": [str(entry) for entry in raw.get("cpes") or []]},
            ),
        )
