"""CIRCL passive DNS and passive SSL.

CIRCL runs these as a public service for the CSIRT community. They answer the
same two questions as the commercial passive-DNS products, from a European
non-profit, on credentials granted per organisation rather than per credit
card.

**Passive DNS** records resolutions actually observed, so it shows where a name
used to point — the history a live lookup has already lost.

**Passive SSL** records certificates seen on addresses. Given an address it
answers what was served there, which ties a bare host to the names it presented
even after the DNS has moved on.

Access is granted on request, to known teams: see https://www.circl.lu/services/.
"""

from __future__ import annotations

import base64
import json
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
from app.services.observables import Observable, hostname_of

_CREDENTIALS: tuple[SecretSpec, ...] = (
    SecretSpec(
        "username",
        "Username",
        help_text="Granted by CIRCL on request; the same pair works for both services.",
        placeholder="issued by CIRCL",
    ),
    SecretSpec(
        "password",
        "Password",
        help_text="The other half of the pair CIRCL issued.",
        placeholder="issued by CIRCL",
    ),
)


class _CirclService(BaseAnalyzer):
    """Shared Basic-auth plumbing for the two CIRCL passive services."""

    secrets: ClassVar[tuple[SecretSpec, ...]] = _CREDENTIALS
    max_tlp = Tlp.AMBER
    default_timeout = 40
    default_cache_ttl = 86400

    def _auth(self) -> dict[str, str]:
        pair = f"{self.secret('username')}:{self.secret('password')}".encode()
        return {
            "Authorization": f"Basic {base64.b64encode(pair).decode()}",
            "Accept": "application/json",
        }

    @staticmethod
    def _lines(text: str) -> list[dict[str, Any]]:
        """Both services answer newline-delimited JSON, not a JSON array."""
        records: list[dict[str, Any]] = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
        return records


@register
class CirclPassiveDnsAnalyzer(_CirclService):
    """Resolutions CIRCL observed for a name or an address."""

    name = "circl_passivedns"
    label = "CIRCL passive DNS"
    description = "Resolutions CIRCL observed over time, with first and last sighting."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.IP,
    )
    provider = ProviderInfo(
        name="CIRCL passive DNS",
        url="https://www.circl.lu/services/passive-dns/",
        api_base_url="https://www.circl.lu/pdns/query/{value}",
        credential_url="https://www.circl.lu/services/passive-dns/ (access granted on request)",
        free_tier="Free for CSIRTs and vetted organisations; access is requested, not bought.",
        rate_limit="Fair use, as agreed with CIRCL.",
        notes=(
            "A European non-profit alternative to the commercial passive DNS products. The "
            "same credentials work for CIRCL passive SSL."
        ),
    )
    documentation_url = "https://www.circl.lu/services/passive-dns/"

    async def run(self, observable: Observable) -> PluginResult:
        query = (
            observable.value
            if observable.type is ObservableType.IP
            else hostname_of(observable)
        )
        if not query:
            return self.skipped("This observable carries nothing to look up.")

        response = await http_client.get(
            f"https://www.circl.lu/pdns/query/{query}",
            headers=self._auth(),
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("CIRCL has no observed resolution for this value.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("CIRCL rejected the configured credentials.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        records = self._lines(response.text)
        if not records:
            return self.not_found("CIRCL has no observed resolution for this value.")

        values = sorted(
            {str(entry.get("rdata") or "") for entry in records if entry.get("rdata")}
        )
        firsts = [str(e.get("time_first") or "") for e in records if e.get("time_first")]
        lasts = [str(e.get("time_last") or "") for e in records if e.get("time_last")]
        first = min(firsts, default="")
        last = max(lasts, default="")

        return self.ok(
            {"query": query, "records": records[:400]},
            PluginSummary(
                verdict=Verdict.UNKNOWN,
                hostnames=[entry for entry in values if entry and not entry[0].isdigit()][:100],
                headline=f"{len(records)} record(s), {len(values)} distinct value(s) observed.",
                extra={
                    "distinct_values": values[:200],
                    "record_types": sorted({str(entry.get("rrtype") or "") for entry in records}),
                    "time_first": first,
                    "time_last": last,
                },
            ),
        )


@register
class CirclPassiveSslAnalyzer(_CirclService):
    """Certificates CIRCL observed being served on an address."""

    name = "circl_passivessl"
    label = "CIRCL passive SSL"
    description = "Certificates seen on an address, tying a bare host to the names it served."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)
    provider = ProviderInfo(
        name="CIRCL passive SSL",
        url="https://www.circl.lu/services/passive-ssl/",
        api_base_url="https://www.circl.lu/v2pssl/query/{ip}",
        credential_url="https://www.circl.lu/services/passive-ssl/ (access granted on request)",
        free_tier="Free for CSIRTs and vetted organisations; access is requested, not bought.",
        rate_limit="Fair use, as agreed with CIRCL.",
        notes=(
            "Answers for an address only. Useful once DNS has moved on: the certificate says "
            "which names the host presented."
        ),
    )
    documentation_url = "https://www.circl.lu/services/passive-ssl/"

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.get(
            f"https://www.circl.lu/v2pssl/query/{observable.value}",
            headers=self._auth(),
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("CIRCL has seen no certificate on this address.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("CIRCL rejected the configured credentials.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        # The answer is keyed by address, each holding its certificate set.
        fingerprints: list[str] = []
        for entry in raw.values():
            if isinstance(entry, dict):
                fingerprints.extend(str(item) for item in (entry.get("certificates") or []))
        if not fingerprints:
            return self.not_found("CIRCL has seen no certificate on this address.")

        return self.ok(
            raw,
            PluginSummary(
                verdict=Verdict.UNKNOWN,
                headline=f"{len(fingerprints)} certificate(s) observed on this address.",
                extra={"fingerprints": fingerprints[:100], "certificate_count": len(fingerprints)},
            ),
        )
