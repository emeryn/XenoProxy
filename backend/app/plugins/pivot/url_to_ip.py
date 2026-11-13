"""Pivot from a flagged URL to the address that served the page."""

from __future__ import annotations

import ipaddress
from typing import ClassVar

from app.models.job import ObservableType, Tlp
from app.plugins.base.pivot import BasePivot
from app.plugins.base.plugin import JobContext, PluginResult, ProviderInfo
from app.plugins.base.registry import register


@register
class UrlToIpPivot(BasePivot):
    """Triages the hosting address URLScan observed for a flagged URL.

    This is the address that actually served the content, which is not always
    what DNS resolves to now — behind a CDN, or after the operator moved the
    page, the two differ. Pivoting on the observed address is what keeps the
    investigation anchored to what was really seen.
    """

    name = "url_to_ip"
    label = "URL to hosting IP"
    description = "Triages the address URLScan saw serving a suspicious or malicious URL."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.URL,)
    child_playbook = "Fast IP triage"
    max_children = 1
    provider = ProviderInfo(
        name="XenoProxy",
        api_base_url="None: the address is read from the parent job's URLScan report",
        free_tier="No credential and no outbound call.",
    )
    max_tlp = Tlp.RED

    def refusal_reason(self, context: JobContext) -> str | None:
        base = super().refusal_reason(context)
        if base is not None:
            return base
        report = context.report("urlscan")
        if report is None:
            return "the parent job did not run the URLScan analyzer"
        if not report.succeeded:
            return "the parent job's URLScan report did not succeed"
        return None

    async def run(self, context: JobContext) -> PluginResult:
        report = context.report("urlscan")
        if report is None or not report.succeeded:
            return self.no_pivot("no usable URLScan report on the parent job")

        raw_ip = str(((report.summary or {}).get("extra") or {}).get("ip") or "").strip()
        if not raw_ip:
            return self.no_pivot("URLScan reported no hosting address")
        try:
            address = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            return self.no_pivot(f"URLScan reported '{raw_ip}', which is not an address")

        return self.pivot_to(
            [address],
            reason=f"address observed serving the flagged URL {context.observable.value}",
            raw={"source_analyzer": "urlscan", "ip": address},
        )
