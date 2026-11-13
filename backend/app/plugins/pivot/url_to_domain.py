"""Pivot from a flagged URL to the domain that serves it."""

from __future__ import annotations

import ipaddress
from typing import ClassVar
from urllib.parse import urlsplit

from app.models.job import ObservableType, Tlp
from app.plugins.base.pivot import BasePivot
from app.plugins.base.plugin import JobContext, PluginResult, ProviderInfo
from app.plugins.base.registry import register


@register
class UrlToDomainPivot(BasePivot):
    """Extracts the host of a suspicious or malicious URL and analyses it.

    A flagged URL usually means the domain behind it deserves its own look:
    registration age, certificates, sibling URLs. That is a different playbook
    from URL triage, which is the whole point of pivoting rather than adding
    more analyzers to the parent job.
    """

    name = "url_to_domain"
    label = "URL to domain"
    description = "Analyses the domain of a suspicious or malicious URL."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.URL,)
    child_playbook = "Domain reconnaissance"
    max_children = 1
    # Reads the parent observable only, so it is safe at any handling level.
    provider = ProviderInfo(
        name="XenoProxy",
        api_base_url="None: the host is read from the parent job's own observable",
        free_tier="No credential and no outbound call.",
    )
    max_tlp = Tlp.RED

    async def run(self, context: JobContext) -> PluginResult:
        host = (urlsplit(context.observable.value).hostname or "").strip().lower()
        if not host:
            return self.no_pivot("the URL carries no host")

        # An IP-hosted URL has no domain to investigate; the url_to_ip pivot
        # covers that case, so this one declines instead of duplicating it.
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return self.no_pivot("the URL points at a literal IP address, not a domain")

        if "." not in host:
            return self.no_pivot(f"'{host}' is not a routable domain name")

        return self.pivot_to([host], reason=f"host of the flagged URL {context.observable.value}")
