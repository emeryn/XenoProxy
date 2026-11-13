"""NVD: the canonical record for a CVE, from NIST.

Every other source quotes CVE identifiers; this is where they are defined. An
analyst reading "CVE-2021-44228" in a Shodan banner needs the severity, the
vector and the affected products, and needs them from the authority rather
than from whichever blog the number was copied into.

It takes a CVE as a generic observable, so pasting an identifier straight from
an alert works.
"""

from __future__ import annotations

import re
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
from app.services.observables import Observable

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE = re.compile(r"^cve-\d{4}-\d{4,}$", re.IGNORECASE)

# A score becomes a verdict, because an exposed critical is a finding.
_SEVERITY = {
    "CRITICAL": Verdict.MALICIOUS,
    "HIGH": Verdict.MALICIOUS,
    "MEDIUM": Verdict.SUSPICIOUS,
    "LOW": Verdict.SUSPICIOUS,
    "NONE": Verdict.CLEAN,
}


@register
class NvdAnalyzer(BaseAnalyzer):
    """The authoritative description and severity of a CVE."""

    name = "nvd"
    label = "NVD (NIST)"
    description = "The canonical description, CVSS severity and affected products of a CVE."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.GENERIC,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            required=False,
            help_text="Optional. Without one the rate limit is 5 requests per 30 seconds.",
            placeholder="request one at nvd.nist.gov",
        ),
    )
    provider = ProviderInfo(
        name="NVD (NIST)",
        url="https://nvd.nist.gov/",
        api_base_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
        credential_url="https://nvd.nist.gov/developers/request-an-api-key",
        free_tier="Free, and usable with no key at all.",
        rate_limit=(
            "5 requests per 30 seconds without a key, 50 with one. A key is free and worth "
            "requesting on a busy instance."
        ),
        notes="Takes a CVE identifier pasted as a generic observable, such as CVE-2021-44228.",
    )
    # Asking NIST about a CVE reveals nothing about the investigation: the
    # identifier is public and the lookup says nothing about who is affected.
    max_tlp = Tlp.RED
    free_tier = True
    default_timeout = 30
    # The record changes when the analysis is revised, which is rare.
    default_cache_ttl = 604800
    documentation_url = "https://nvd.nist.gov/developers/vulnerabilities"

    async def run(self, observable: Observable) -> PluginResult:
        identifier = observable.value.strip().upper()
        if not _CVE.match(identifier):
            return self.skipped("This observable is not a CVE identifier.")

        key = self.optional_secret("api_key")
        response = await http_client.get(
            ENDPOINT,
            params={"cveId": identifier},
            headers={"apiKey": key} if key else None,
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError(
                "NVD returned HTTP 429. Without an API key the limit is 5 requests per 30 seconds."
            )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        entries = raw.get("vulnerabilities") or []
        if not entries:
            return self.not_found(f"NVD has no record for {identifier}.")

        cve = (entries[0] or {}).get("cve") or {}
        descriptions = [
            str(entry.get("value") or "")
            for entry in cve.get("descriptions") or []
            if isinstance(entry, dict) and entry.get("lang") == "en"
        ]
        metrics = cve.get("metrics") or {}
        # Newest scoring first: an older record may carry only v2.
        scored = (
            metrics.get("cvssMetricV31")
            or metrics.get("cvssMetricV30")
            or metrics.get("cvssMetricV2")
            or []
        )
        primary = (scored[0] if scored else {}).get("cvssData") or {}
        severity = str(
            primary.get("baseSeverity") or (scored[0] if scored else {}).get("baseSeverity") or ""
        ).upper()
        score = primary.get("baseScore")

        weaknesses = [
            str(item.get("value") or "")
            for entry in cve.get("weaknesses") or []
            for item in (entry or {}).get("description") or []
            if isinstance(item, dict) and str(item.get("value") or "").startswith("CWE")
        ]

        headline = identifier
        if severity:
            headline += f" — {severity}"
        if isinstance(score, (int, float)):
            headline += f" {score}"
        if descriptions:
            headline += f": {descriptions[0][:140]}"

        return self.ok(
            raw,
            PluginSummary(
                verdict=_SEVERITY.get(severity, Verdict.UNKNOWN),
                # CVSS runs 0 to 10 with one decimal; the summary's score is a
                # whole number, so 9.8 is carried as 98 rather than rounded
                # down to 9 and losing the distinction from 9.0.
                score=round(float(score) * 10) if isinstance(score, (int, float)) else None,
                tags=[tag for tag in (severity.lower(), *weaknesses) if tag][:10],
                cves=[identifier],
                headline=headline,
                links=[
                    {
                        "label": "Open in NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{identifier}",
                    }
                ],
                extra={
                    "severity": severity,
                    "base_score": score,
                    "vector": primary.get("vectorString"),
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "status": cve.get("vulnStatus"),
                    "weaknesses": weaknesses,
                    "description": descriptions[0] if descriptions else "",
                },
            ),
        )
