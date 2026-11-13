"""crt.sh: certificate transparency, which is how you find the subdomains.

Every publicly trusted certificate is logged, and the logs are searchable. For
a domain under investigation that answers two questions a DNS lookup cannot:
which names the owner has ever certified, and when they started. A certificate
issued yesterday for a domain registered yesterday is the shape of a phishing
campaign.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable, hostname_of


@register
class CrtShAnalyzer(BaseAnalyzer):
    """Certificates logged for a domain, and the names they cover."""

    name = "crtsh"
    label = "crt.sh certificate transparency"
    description = "Certificates issued for a domain, the names they cover and when they appeared."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "include_subdomains": {
            "type": "boolean",
            "default": True,
            "label": "Also match the subdomains of the name",
        },
        "max_certificates": {
            "type": "integer",
            "default": 200,
            "label": "Certificates to keep in the report",
        },
    }
    provider = ProviderInfo(
        name="crt.sh (Sectigo)",
        url="https://crt.sh/",
        api_base_url="https://crt.sh/?q={domain}&output=json",
        free_tier="Free and unauthenticated.",
        rate_limit=(
            "No published quota, but the service is slow under load and answers 502 when "
            "it is busy. A generous timeout is worth more than a retry."
        ),
        notes=(
            "The query itself is public in the sense that it reveals interest to Sectigo, so "
            "this is capped at TLP:GREEN."
        ),
    )
    # Querying a certificate log tells the log operator which domain is being
    # investigated, so it does not go above GREEN.
    max_tlp = Tlp.GREEN
    free_tier = True
    default_timeout = 60
    default_cache_ttl = 43200
    documentation_url = "https://crt.sh/"

    async def run(self, observable: Observable) -> PluginResult:
        from app.core import http_client

        host = hostname_of(observable)
        pattern = f"%.{host}" if self.option("include_subdomains", True) else host

        response = await http_client.get(
            "https://crt.sh/",
            params={"q": pattern, "output": "json"},
            timeout=self.timeout,
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        entries = response.json_body
        if entries is None:
            # crt.sh answers an empty body rather than an empty array when it
            # knows nothing, which is not a failure.
            return self.not_found("No certificate is logged for this name.")
        if not isinstance(entries, list):
            return self.failed("crt.sh did not return a list of certificates.")

        limit = max(1, int(self.option("max_certificates", 200)))
        kept = entries[:limit]

        names: set[str] = set()
        issuers: set[str] = set()
        earliest: str | None = None
        latest: str | None = None
        for entry in kept:
            if not isinstance(entry, dict):
                continue
            for name in str(entry.get("name_value") or "").split("\n"):
                cleaned = name.strip().lower().lstrip("*.")
                if cleaned:
                    names.add(cleaned)
            issuer = str(entry.get("issuer_name") or "")
            if issuer:
                issuers.add(_issuer_organisation(issuer))
            seen = str(entry.get("not_before") or "")
            if seen:
                earliest = seen if earliest is None or seen < earliest else earliest
                latest = seen if latest is None or seen > latest else latest

        age_days = _days_since(earliest)
        # A name first certified in the last few days is worth a second look. It
        # is not a verdict on its own — every legitimate new site starts here —
        # so it reports as suspicious rather than malicious, and says why.
        recent = age_days is not None and age_days <= 7
        headline = f"{len(entries)} certificate(s), {len(names)} distinct name(s)"
        if recent:
            headline += f"; first certified {age_days} day(s) ago"

        return self.ok(
            {
                "queried": pattern,
                "total": len(entries),
                "kept": len(kept),
                "certificates": kept,
                "names": sorted(names),
                "issuers": sorted(issuers),
                "first_seen": earliest,
                "last_seen": latest,
            },
            PluginSummary(
                verdict=Verdict.SUSPICIOUS if recent else Verdict.UNKNOWN,
                tags=["recently-certified"] if recent else [],
                hostnames=sorted(names),
                headline=headline,
                links=[{"label": "Open in crt.sh", "url": f"https://crt.sh/?q={pattern}"}],
                extra={
                    "issuers": sorted(issuers),
                    "first_seen": earliest,
                    "last_seen": latest,
                    "first_seen_days_ago": age_days,
                    "distinct_names": len(names),
                },
            ),
        )


def _issuer_organisation(issuer: str) -> str:
    """`C=US, O=Let's Encrypt, CN=R3` reads as `Let's Encrypt`."""
    for part in issuer.split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "O" and value:
            return value.strip()
    return issuer[:120]


def _days_since(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        seen = datetime.fromisoformat(timestamp.replace("Z", ""))
    except ValueError:
        return None
    # crt.sh writes the timestamp without a zone, and it is UTC. Attaching the
    # zone is what makes the subtraction below correct rather than off by the
    # container's offset.
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    return max(0, (datetime.now(UTC) - seen).days)
