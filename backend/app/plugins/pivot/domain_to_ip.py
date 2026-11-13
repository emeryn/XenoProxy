"""Pivot from a flagged domain to the addresses it resolves to."""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp
from app.plugins.base.pivot import BasePivot
from app.plugins.base.plugin import JobContext, PluginResult, ProviderInfo
from app.plugins.base.registry import register


@register
class DomainToIpPivot(BasePivot):
    """Analyses the A and AAAA records the DNS analyzer already resolved.

    It deliberately reuses the parent job's DNS report rather than resolving
    again: the parent already paid for that lookup, and resolving a second time
    could pick a different answer from a round-robin record set, which would
    make the investigation tree inconsistent with the job it came from.
    """

    name = "domain_to_ip"
    label = "Domain to IP"
    description = "Triages the addresses a suspicious or malicious domain resolves to."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    child_playbook = "Fast IP triage"
    max_children = 4
    provider = ProviderInfo(
        name="XenoProxy",
        api_base_url="None: the addresses are read from the parent job's DNS report",
        free_tier="No credential and no outbound call.",
        notes=(
            "Reuses the parent's resolution rather than resolving again, so the tree stays "
            "consistent with the job it came from."
        ),
    )
    max_tlp = Tlp.RED
    options_schema: ClassVar[dict[str, Any]] = {
        "include_ipv6": {
            "type": "boolean",
            "default": True,
            "label": "Also pivot to AAAA records",
        },
    }

    def refusal_reason(self, context: JobContext) -> str | None:
        base = super().refusal_reason(context)
        if base is not None:
            return base
        report = context.report("dns")
        if report is None:
            return "the parent job did not run the DNS analyzer"
        if not report.succeeded:
            return "the parent job's DNS report did not succeed"
        return None

    async def run(self, context: JobContext) -> PluginResult:
        report = context.report("dns")
        if report is None or not report.succeeded:
            return self.no_pivot("no usable DNS report on the parent job")

        records = ((report.summary or {}).get("extra") or {}).get("records") or {}
        if not isinstance(records, dict):
            return self.no_pivot("the DNS report carries no record set")

        wanted = ["A", "AAAA"] if self.option("include_ipv6", True) else ["A"]
        addresses: list[str] = []
        for record_type in wanted:
            for entry in records.get(record_type) or []:
                candidate = str(entry).strip()
                try:
                    # A record's text form can carry a trailing dot or padding.
                    addresses.append(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    continue

        if not addresses:
            return self.no_pivot("the domain resolved to no address")

        return self.pivot_to(
            addresses,
            reason=f"resolved from the flagged domain {context.observable.value}",
            raw={"source_analyzer": "dns", "records": records, "selected": addresses},
        )
