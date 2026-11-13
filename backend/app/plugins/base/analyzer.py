"""Analyzer contract: read an observable, return intelligence about it."""

from __future__ import annotations

import abc
import ipaddress

import dns.asyncresolver
import dns.exception

from app.core.config import get_settings
from app.models.job import ObservableType
from app.plugins.base.plugin import (
    BasePlugin,
    PluginResult,
    PluginType,
)
from app.services.observables import Observable, hostname_of


class BaseAnalyzer(BasePlugin):
    """A plugin that enriches one observable during the analysis phase.

    Analyzers are the only plugin type selected by observable type, which is why
    `supported_types` is mandatory for them: the registry refuses an analyzer
    that does not declare what it can read.
    """

    plugin_type = PluginType.ANALYZER

    @abc.abstractmethod
    async def run(self, observable: Observable) -> PluginResult:
        """Query the provider and return a normalised result."""

    async def _invoke(self, payload: Observable) -> PluginResult:
        return await self.run(payload)

    async def address_of(self, observable: Observable) -> str | None:
        """The address to query for this observable, resolving a name if needed.

        A provider that indexes hosts — exposure, geolocation, abuse reports —
        answers for an address, not for a name. Asking the analyst to pivot to
        the address first is asking them to do the lookup by hand: scanning a
        URL should say where it is hosted and what is open there.

        The resolved address is re-checked against the same rule the submitted
        observable passed, so a name that resolves into a private range cannot
        be used to reach the internal network through an analyzer.

        Returns `None` when the name does not resolve or resolves somewhere the
        instance refuses to scan; the caller reports that rather than failing.
        """
        if observable.type is ObservableType.IP:
            return observable.value

        hostname = hostname_of(observable)
        if not hostname:
            return None

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = min(10.0, float(self.timeout))
        resolver.timeout = min(5.0, float(self.timeout))

        for record_type in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(hostname, record_type)
            except (dns.exception.DNSException, ValueError):
                continue
            for record in answer:
                candidate = str(record)
                try:
                    parsed = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if parsed.is_global or get_settings().allow_private_targets:
                    return candidate
        return None

    def resolved_note(self, observable: Observable, address: str) -> str:
        """A line saying which address an answer actually describes."""
        if observable.type is ObservableType.IP:
            return ""
        return f" (resolved {hostname_of(observable)} to {address})"
