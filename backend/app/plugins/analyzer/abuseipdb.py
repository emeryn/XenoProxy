"""AbuseIPDB reputation check."""

from __future__ import annotations

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
from app.plugins.user_keys import USER_KEY_HELP
from app.services.observables import Observable

_CATEGORIES = {
    3: "Fraud orders",
    4: "DDoS attack",
    5: "FTP brute-force",
    6: "Ping of death",
    7: "Phishing",
    9: "Open proxy",
    10: "Web spam",
    11: "Email spam",
    14: "Port scan",
    15: "Hacking",
    16: "SQL injection",
    17: "Spoofing",
    18: "Brute-force",
    19: "Bad web bot",
    20: "Exploited host",
    21: "Web app attack",
    22: "SSH abuse",
    23: "IoT targeted",
}


@register
class AbuseIpdbAnalyzer(BaseAnalyzer):
    """Abuse confidence score and report history for an IP address."""

    name = "abuseipdb"
    label = "AbuseIPDB"
    description = "Abuse confidence score, report count and abuse categories."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="AbuseIPDB API v2 key. " + USER_KEY_HELP,
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "max_age_days": {"type": "integer", "default": 90, "label": "Report window in days"},
        "malicious_threshold": {
            "type": "integer",
            "default": 50,
            "label": "Confidence score above which the verdict is Malicious",
        },
    }
    provider = ProviderInfo(
        name="AbuseIPDB",
        url="https://www.abuseipdb.com/",
        api_base_url="https://api.abuseipdb.com/api/v2/check",
        credential_url="https://www.abuseipdb.com/account/api",
        free_tier="1 000 checks per day on a free account.",
        rate_limit="Per-day quota; a 429 means the day is spent.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://docs.abuseipdb.com/"

    async def run(self, observable: Observable) -> PluginResult:
        address = await self.address_of(observable)
        if address is None:
            return self.not_found("The name does not resolve to a public address.")

        response = await http_client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": self.secret("api_key"), "Accept": "application/json"},
            params={
                "ipAddress": address,
                "maxAgeInDays": int(self.option("max_age_days", 90)),
                "verbose": "true",
            },
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("AbuseIPDB returned HTTP 429 (daily quota reached).")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        data = raw.get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        reports = int(data.get("totalReports") or 0)
        threshold = int(self.option("malicious_threshold", 50))

        if score >= threshold:
            verdict = Verdict.MALICIOUS
        elif score > 0 or reports:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        category_ids: set[int] = set()
        for report in data.get("reports") or []:
            if isinstance(report, dict):
                for category in report.get("categories") or []:
                    if isinstance(category, int):
                        category_ids.add(category)
        tags = [_CATEGORIES.get(cid, f"category-{cid}") for cid in sorted(category_ids)]
        if data.get("isTor"):
            tags.append("tor")
        if data.get("usageType"):
            tags.append(str(data["usageType"]).lower())

        summary = PluginSummary(
            verdict=verdict,
            score=score,
            tags=tags,
            country=data.get("countryName") or data.get("countryCode"),
            organisation=data.get("isp"),
            hostnames=[str(host) for host in data.get("hostnames") or [] if host],
            headline=(
                f"Abuse confidence {score}% from {reports} report(s)."
                + self.resolved_note(observable, address)
            ),
            links=[
                {
                    "label": "Open in AbuseIPDB",
                    "url": f"https://www.abuseipdb.com/check/{address}",
                }
            ],
            extra={
                "total_reports": reports,
                "distinct_reporters": data.get("numDistinctUsers"),
                "last_reported_at": data.get("lastReportedAt"),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
                "is_whitelisted": data.get("isWhitelisted"),
            },
        )
        return self.ok(raw, summary)
