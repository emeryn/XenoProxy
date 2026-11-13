"""Direct DNS resolution and RDAP registration lookup, with no third-party API."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, ClassVar

import dns.asyncresolver
import dns.exception
import dns.reversename

from app.core import http_client
from app.core.http_client import HttpResult
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable, hostname_of

_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA")


@register
class DnsAnalyzer(BaseAnalyzer):
    """Resolves the standard record set for a domain, or the PTR record for an IP."""

    name = "dns"
    label = "DNS resolver"
    description = "A, AAAA, MX, TXT, NS, SOA, CNAME and CAA records, or reverse PTR for an IP."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.IP,
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "nameserver": {
            "type": "string",
            "default": "",
            "label": "Resolver IP to use (empty means the container resolver)",
        }
    }
    # Resolution happens from this deployment, so nothing leaves it.
    provider = ProviderInfo(
        name="DNS",
        url="",
        api_base_url="The resolver of the container, over DNS",
        free_tier="No credential and no quota: the lookup is made directly.",
        notes="Nothing leaves for a third party, so this is allowed up to TLP:RED.",
    )
    max_tlp = Tlp.RED
    free_tier = True
    default_timeout = 20
    default_cache_ttl = 3600

    def _resolver(self) -> dns.asyncresolver.Resolver:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = float(self.timeout)
        resolver.timeout = min(5.0, float(self.timeout))
        nameserver = str(self.option("nameserver", "") or "").strip()
        if nameserver:
            resolver.nameservers = [nameserver]
        return resolver

    async def run(self, observable: Observable) -> PluginResult:
        resolver = self._resolver()
        if observable.type is ObservableType.IP:
            return await self._reverse(resolver, observable)

        hostname = hostname_of(observable)
        records: dict[str, list[str]] = {}

        async def resolve(record_type: str) -> None:
            try:
                answer = await resolver.resolve(hostname, record_type)
            except (dns.exception.DNSException, ValueError):
                return
            records[record_type] = sorted({rdata.to_text()[:512] for rdata in answer})

        await asyncio.gather(*(resolve(record) for record in _RECORD_TYPES))

        if not records:
            return self.not_found(f"No DNS record resolved for {hostname}.")

        addresses = records.get("A", []) + records.get("AAAA", [])
        has_spf = any("v=spf1" in entry for entry in records.get("TXT", []))
        has_dmarc = False
        try:
            dmarc = await resolver.resolve(f"_dmarc.{hostname}", "TXT")
            has_dmarc = any("v=DMARC1" in rdata.to_text() for rdata in dmarc)
        except (dns.exception.DNSException, ValueError):
            has_dmarc = False

        total_records = sum(len(values) for values in records.values())
        tags = [f"{record.lower()}-record" for record in records]
        if not has_spf:
            tags.append("no-spf")
        if not has_dmarc:
            tags.append("no-dmarc")

        return self.ok(
            {"hostname": hostname, "records": records, "spf": has_spf, "dmarc": has_dmarc},
            PluginSummary(
                verdict=Verdict.UNKNOWN,
                tags=tags,
                hostnames=addresses,
                headline=f"{total_records} record(s) across {len(records)} type(s).",
                extra={"records": records, "spf": has_spf, "dmarc": has_dmarc},
            ),
        )

    async def _reverse(
        self, resolver: dns.asyncresolver.Resolver, observable: Observable
    ) -> PluginResult:
        try:
            pointer = dns.reversename.from_address(observable.value)
            answer = await resolver.resolve(pointer, "PTR")
            names = sorted({rdata.to_text().rstrip(".") for rdata in answer})
        except (dns.exception.DNSException, ValueError):
            return self.ok(
                {"ptr": []},
                PluginSummary(verdict=Verdict.UNKNOWN, headline="No PTR record for this address."),
            )
        return self.ok(
            {"ptr": names},
            PluginSummary(
                verdict=Verdict.UNKNOWN,
                hostnames=names,
                headline=f"PTR: {', '.join(names)}",
                extra={"ptr": names},
            ),
        )


@register
class RdapAnalyzer(BaseAnalyzer):
    """Registration data for a domain or an IP address over RDAP."""

    name = "rdap"
    label = "RDAP / Whois"
    description = "Registrar, registration and expiry dates, abuse contacts and network ownership."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.IP,
    )
    provider = ProviderInfo(
        name="RDAP",
        url="https://about.rdap.org/",
        api_base_url=(
            "https://rdap.org/{ip|domain}/{value} (bootstrapped to the authoritative registry)"
        ),
        free_tier="Free and unauthenticated; RDAP replaces WHOIS.",
        rate_limit="Set by each registry; a popular TLD's server can throttle.",
        notes=(
            "The bootstrap redirects to the registry that holds the record, and every hop is "
            "re-validated against the SSRF rules."
        ),
    )
    max_tlp = Tlp.AMBER
    free_tier = True
    default_timeout = 30
    default_cache_ttl = 86400

    async def _query(self, path: str) -> HttpResult:
        # rdap.org is a bootstrap service: it redirects to the authoritative registry.
        return await http_client.get(
            f"https://rdap.org/{path}",
            headers={"Accept": "application/rdap+json"},
            timeout=self.timeout,
            max_redirects=3,
        )

    async def run(self, observable: Observable) -> PluginResult:
        queried = observable.value

        if observable.type is ObservableType.IP:
            response = await self._query(f"ip/{observable.value}")
        else:
            # A registry holds a record for the registered domain, not for every
            # name under it: `vercel.app` answers, `app.vercel.app` is rejected
            # with 400 and `www.example.xyz` with 404. Walking the labels from
            # the most specific name down finds the record that does exist,
            # which is the difference between this analyzer working on a real
            # observable and never working at all.
            #
            # Dropping a label is also why no public suffix list is needed: the
            # first name that answers is the answer, whatever the suffix rules.
            labels = hostname_of(observable).strip(".").split(".")
            response = None
            for start in range(len(labels) - 1):
                candidate = ".".join(labels[start:])
                attempt = await self._query(f"domain/{candidate}")
                queried = candidate
                if attempt.status_code not in (400, 404):
                    response = attempt
                    break
                response = attempt
            if response is None:
                return self.not_found("No RDAP registration record found.")

        if response.status_code in (400, 404):
            return self.not_found("No RDAP registration record found.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        raw["_queried"] = queried
        events = {
            str(event.get("eventAction")): str(event.get("eventDate"))
            for event in raw.get("events") or []
            if isinstance(event, dict)
        }
        registrar = None
        abuse_email = None
        for entity in raw.get("entities") or []:
            if not isinstance(entity, dict):
                continue
            roles = [str(role) for role in entity.get("roles") or []]
            vcard = entity.get("vcardArray")
            name = _vcard_value(vcard, "fn")
            if "registrar" in roles and name:
                registrar = name
            if "abuse" in roles:
                abuse_email = _vcard_value(vcard, "email") or abuse_email

        registered = events.get("registration")
        age_days = _age_in_days(registered)
        tags = [str(status) for status in raw.get("status") or []]
        if age_days is not None and age_days < 30:
            tags.append("recently-registered")

        return self.ok(
            raw,
            PluginSummary(
                verdict=Verdict.SUSPICIOUS
                if age_days is not None and age_days < 30
                else Verdict.UNKNOWN,
                tags=tags,
                country=raw.get("country"),
                organisation=registrar or raw.get("name"),
                hostnames=[
                    str(ns.get("ldhName"))
                    for ns in raw.get("nameservers") or []
                    if isinstance(ns, dict) and ns.get("ldhName")
                ],
                headline=(
                    f"Registered {registered} ({age_days} day(s) ago)."
                    if registered and age_days is not None
                    else f"Handle {raw.get('handle') or 'unknown'}."
                ),
                extra={
                    "handle": raw.get("handle"),
                    "registrar": registrar,
                    "abuse_email": abuse_email,
                    "events": events,
                    "cidr": raw.get("cidr0_cidrs"),
                    "start_address": raw.get("startAddress"),
                    "end_address": raw.get("endAddress"),
                    "age_days": age_days,
                },
            ),
        )


def _vcard_value(vcard: Any, key: str) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for entry in vcard[1]:
        if isinstance(entry, list) and len(entry) >= 4 and entry[0] == key:
            value = entry[3]
            if isinstance(value, str):
                return value[:256]
    return None


def _age_in_days(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - parsed).days
