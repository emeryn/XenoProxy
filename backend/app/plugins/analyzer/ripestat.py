"""RIPEstat: whose network an address actually sits in.

Geolocation says where a database thinks an address is; the routing table says
who announces it. For attribution the second matters more — a hosting provider
known for abuse, a bulletproof AS and a residential ISP are different findings,
and only the prefix and the autonomous system tell them apart.

RIPEstat is run by the RIPE NCC from the routing data they already collect, so
it is free, keyless, and answers for the whole Internet rather than only for
the RIPE region.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

BASE = "https://stat.ripe.net/data"


@register
class RipeStatAnalyzer(BaseAnalyzer):
    """The announced prefix, the autonomous system and its abuse contact."""

    name = "ripestat"
    label = "RIPEstat routing"
    description = "The prefix announcing an address, its autonomous system and the abuse contact."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.GENERIC,
    )
    provider = ProviderInfo(
        name="RIPEstat (RIPE NCC)",
        url="https://stat.ripe.net/",
        api_base_url="https://stat.ripe.net/data/{prefix-overview|abuse-contact-finder}/data.json",
        free_tier="Free and unauthenticated, for the whole Internet and not only the RIPE region.",
        rate_limit=(
            "Fair use. A heavy automated volume is expected to identify itself with the "
            "`sourceapp` parameter, which this analyzer sends."
        ),
        notes=(
            "Routing is attribution, not reputation: this analyzer never votes on a verdict. "
            "Accepts an ASN as a generic observable, written either `AS1234` or `1234`."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 25
    default_cache_ttl = 86400
    documentation_url = "https://stat.ripe.net/docs/02.data-api/"

    async def _fetch(self, endpoint: str, resource: str) -> Any:
        """Call one RIPEstat endpoint, returning its `data` object."""
        response = await http_client.get(
            f"{BASE}/{endpoint}/data.json",
            # Identifying the caller is what RIPEstat asks of automated use.
            params={"resource": resource, "sourceapp": "xenoproxy-osint"},
            timeout=self.timeout,
        )
        if not response.ok:
            return None
        body = response.json_body
        if not isinstance(body, dict) or body.get("status") != "ok":
            return None
        return body.get("data")

    async def run(self, observable: Observable) -> PluginResult:
        resource = self._resource(observable)
        if resource is None:
            return self.skipped("This observable is neither an address nor an ASN.")

        # An address resolves to the prefix announcing it; an ASN is its own
        # resource and `prefix-overview` refuses it, so each has its endpoint.
        endpoint = "prefix-overview" if observable.type is ObservableType.IP else "as-overview"
        overview = await self._fetch(endpoint, resource)
        if overview is None:
            return self.failed(f"RIPEstat did not answer for {resource}.")

        # The abuse contact is a second call, and a missing one is normal: it
        # must not fail the report.
        contacts = await self._fetch("abuse-contact-finder", resource) or {}

        asns = overview.get("asns") or []
        first = asns[0] if asns and isinstance(asns[0], dict) else {}
        # `as-overview` names the holder at the top level; `prefix-overview`
        # nests it under the announcing autonomous systems.
        number = first.get("asn") or _asn_of(overview.get("resource"))
        holder = str(first.get("holder") or overview.get("holder") or "")
        prefix = str(overview.get("resource") or "")
        announced = bool(overview.get("announced"))
        emails = [str(entry) for entry in contacts.get("abuse_contacts") or []]

        headline = f"AS{number} {holder}".strip() if number else "No announcing prefix was found."
        if not announced:
            headline = f"{prefix} is allocated but not announced." if prefix else headline

        return self.ok(
            {"prefix_overview": overview, "abuse_contacts": contacts},
            PluginSummary(
                # Attribution never votes: an address belonging to a large
                # hosting provider is not a finding about the address.
                verdict=Verdict.UNKNOWN,
                asn=f"AS{number}" if number else None,
                organisation=holder or None,
                headline=headline,
                links=[
                    {
                        "label": "Open in RIPEstat",
                        "url": f"https://stat.ripe.net/app/launchpad/{resource}",
                    }
                ],
                extra={
                    "prefix": prefix,
                    "announced": announced,
                    "asns": [entry.get("asn") for entry in asns if isinstance(entry, dict)],
                    "abuse_contacts": emails,
                    "block": (overview.get("block") or {}).get("desc"),
                },
            ),
        )

    def _resource(self, observable: Observable) -> str | None:
        if observable.type is ObservableType.IP:
            return observable.value
        candidate = observable.value.strip().upper().removeprefix("AS")
        return f"AS{candidate}" if candidate.isdigit() else None


def _asn_of(resource: Any) -> int | None:
    """Read an ASN resource, however RIPEstat spelled it.

    `prefix-overview` echoes a prefix, which is not an ASN. `as-overview`
    echoes the autonomous system, and does so without the `AS` prefix, so
    requiring one would silently lose the number.
    """
    text = str(resource or "").strip().upper().removeprefix("AS")
    return int(text) if text.isdigit() else None
