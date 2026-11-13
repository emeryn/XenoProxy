"""Reputation lists queried over DNS, including the Tor exit list.

A DNS blocklist is answered by resolving a name, which has two consequences
worth stating. It is fast and free, with no key and no quota to spend. And the
query carries the address to the list operator's resolver, so it is a third
party like any other and the handling level is capped accordingly.

The Tor check is the same mechanism and is in the same module for that reason,
not because being a Tor exit is a reputation finding. It is not: it is a fact
about the address that changes how every other finding should be read.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

# Each list answers in 127.0.0.x, and the last octet says why. Only the ones
# whose meaning is documented and stable are interpreted; the rest are reported
# as a raw answer rather than guessed at.
LISTS: dict[str, dict[str, Any]] = {
    "zen.spamhaus.org": {
        "label": "Spamhaus ZEN",
        "codes": {
            "127.0.0.2": "SBL — direct spam source",
            "127.0.0.3": "CSS — snowshoe spam source",
            "127.0.0.4": "XBL — exploited machine or proxy",
            "127.0.0.9": "DROP — hijacked or leased for abuse",
            "127.0.0.10": "PBL — should not deliver mail directly",
            "127.0.0.11": "PBL — should not deliver mail directly",
        },
    },
    "bl.spamcop.net": {"label": "SpamCop", "codes": {"127.0.0.2": "reported spam source"}},
    "b.barracudacentral.org": {
        "label": "Barracuda",
        "codes": {"127.0.0.2": "poor reputation"},
    },
    "dnsbl.sorbs.net": {"label": "SORBS", "codes": {}},
}


async def _resolve(name: str, deadline: float) -> list[str]:
    """Resolve one A record set, treating "no answer" as the normal case.

    `deadline` is how long the resolver itself may take, which is a property of
    the lookup rather than a cancellation scope around it.
    """
    import dns.asyncresolver
    import dns.exception

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = deadline
    resolver.timeout = deadline
    try:
        answer = await resolver.resolve(name, "A")
    except dns.exception.DNSException:
        # NXDOMAIN is the overwhelmingly common answer and means "not listed".
        return []
    return sorted({rdata.to_text() for rdata in answer})


def _reversed(address: str) -> str | None:
    """`1.2.3.4` becomes `4.3.2.1`, which is how a DNSBL is addressed."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.version != 4:
        # The IPv4 form is what these lists publish; an IPv6 query would answer
        # nothing and look like a clean result.
        return None
    return ".".join(reversed(address.split(".")))


@register
class DnsBlocklistAnalyzer(BaseAnalyzer):
    """Checks an address against several DNS reputation lists at once."""

    name = "dnsbl"
    label = "DNS blocklists"
    description = "Spamhaus, SpamCop, Barracuda and SORBS, queried over DNS without a key."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)
    options_schema: ClassVar[dict[str, Any]] = {
        "lists": {
            "type": "string",
            "default": ",".join(LISTS),
            "label": "Comma-separated zones to query",
        },
    }
    provider = ProviderInfo(
        name="Spamhaus, SpamCop, Barracuda, SORBS",
        url="https://www.spamhaus.org/",
        api_base_url="{reversed-ip}.{zone} over DNS",
        free_tier=(
            "Free for a human-scale volume from your own resolver. Spamhaus refuses queries "
            "arriving through a large public resolver such as 8.8.8.8, and answers 127.255.255.x "
            "when it does."
        ),
        rate_limit="Spamhaus: free use up to 300 000 queries a day from your own resolver.",
        notes=(
            "A listing means the address sends mail it should not, or is a compromised host. "
            "It is not evidence about a web service on the same address."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    requires_network = True
    default_timeout = 20
    default_cache_ttl = 10800
    documentation_url = "https://www.spamhaus.org/faqs/dnsbl-usage/"

    async def run(self, observable: Observable) -> PluginResult:
        reversed_address = _reversed(observable.value)
        if reversed_address is None:
            return self.skipped("These lists only answer for IPv4 addresses.")

        zones = [
            zone.strip()
            for zone in str(self.option("lists", ",".join(LISTS))).split(",")
            if zone.strip()
        ]
        per_zone = max(2.0, self.timeout / max(1, len(zones)))

        answers = await asyncio.gather(
            *(_resolve(f"{reversed_address}.{zone}", per_zone) for zone in zones)
        )

        listings: list[dict[str, Any]] = []
        refused: list[str] = []
        for zone, addresses in zip(zones, answers, strict=True):
            if not addresses:
                continue
            # 127.255.255.x is not a listing: it is the operator refusing the
            # query, usually because it arrived through a public resolver.
            if any(entry.startswith("127.255.255.") for entry in addresses):
                refused.append(zone)
                continue
            known = LISTS.get(zone, {})
            reasons = [
                known.get("codes", {}).get(entry, f"listed ({entry})") for entry in addresses
            ]
            listings.append(
                {
                    "zone": zone,
                    "label": known.get("label", zone),
                    "answers": addresses,
                    "reasons": reasons,
                }
            )

        raw = {
            "queried": zones,
            "reversed": reversed_address,
            "listings": listings,
            "refused_queries": refused,
        }

        if refused and not listings:
            # Reporting "clean" here would be a lie: nothing was actually asked.
            return self.failed(
                "The lists refused the query, which usually means the container's resolver is "
                f"a large public one: {', '.join(refused)}. Point it at your own resolver."
            )

        if not listings:
            return self.ok(
                raw,
                PluginSummary(
                    verdict=Verdict.CLEAN,
                    headline=f"Not listed on any of {len(zones)} list(s).",
                ),
            )

        reasons = [reason for entry in listings for reason in entry["reasons"]]
        return self.ok(
            raw,
            PluginSummary(
                # Several independent lists agreeing is a real signal; one is a
                # reason to look, which is what suspicious means here.
                verdict=Verdict.MALICIOUS if len(listings) >= 2 else Verdict.SUSPICIOUS,
                tags=[str(entry["label"]).lower().replace(" ", "-") for entry in listings],
                headline=f"Listed on {len(listings)} of {len(zones)} list(s): {reasons[0]}",
                extra={"listings": listings, "refused_queries": refused},
            ),
        )


@register
class TorExitAnalyzer(BaseAnalyzer):
    """Whether an address is a Tor exit node, by the official DNS list."""

    name = "tor_exit"
    label = "Tor exit node"
    description = "Whether the address is a published Tor exit node, over the official DNS list."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)
    provider = ProviderInfo(
        name="Tor Project (DNSEL)",
        url="https://metrics.torproject.org/",
        api_base_url="{reversed-ip}.dnsel.torproject.org over DNS",
        free_tier="Free and keyless.",
        rate_limit="Fair use.",
        notes=(
            "Being an exit node is not a verdict. It means the traffic was relayed, so the "
            "address attributes nothing about who sent it — which is exactly what an analyst "
            "needs to know before drawing a conclusion from it."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 15
    default_cache_ttl = 10800
    documentation_url = "https://support.torproject.org/relay-operators/"

    async def run(self, observable: Observable) -> PluginResult:
        reversed_address = _reversed(observable.value)
        if reversed_address is None:
            return self.skipped("The exit list only answers for IPv4 addresses.")

        name = f"{reversed_address}.dnsel.torproject.org"
        answers = await _resolve(name, float(self.timeout))
        listed = "127.0.0.2" in answers

        return self.ok(
            {"queried": name, "answers": answers, "is_exit_node": listed},
            PluginSummary(
                # Neither clean nor malicious: it is a fact that changes how the
                # other findings read, and claiming either would be wrong.
                verdict=Verdict.UNKNOWN,
                tags=["tor-exit-node"] if listed else [],
                headline=(
                    "This is a published Tor exit node: the traffic was relayed, so the address "
                    "says nothing about its origin."
                    if listed
                    else "Not a published Tor exit node."
                ),
                extra={"is_exit_node": listed},
            ),
        )
