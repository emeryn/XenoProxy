"""Abuse.ch feeds: ThreatFox, MalwareBazaar and Feodo Tracker."""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo, SecretSpec
from app.plugins.base.registry import register
from app.services.observables import Observable, hostname_of

_AUTH_HELP = "Abuse.ch Auth-Key from your abuse.ch account profile."


@register
class ThreatFoxAnalyzer(BaseAnalyzer):
    """Indicator-of-compromise lookup in the ThreatFox database."""

    name = "threatfox"
    label = "ThreatFox"
    description = "Known IOC matches with malware family and confidence level."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.HASH,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "auth_key", "Auth-Key", required=True, help_text=_AUTH_HELP, user_overridable=True
        ),
    )
    provider = ProviderInfo(
        name="abuse.ch",
        url="https://abuse.ch/",
        api_base_url=(
            "https://threatfox-api.abuse.ch/api/v1/ · https://mb-api.abuse.ch/api/v1/ · "
            "https://feodotracker.abuse.ch/downloads/"
        ),
        credential_url="https://auth.abuse.ch/ (Auth-Key)",
        free_tier=(
            "Free for everyone; an Auth-Key is now required on the ThreatFox, MalwareBazaar and "
            "URLhaus APIs."
        ),
        rate_limit="Fair use.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://threatfox.abuse.ch/api/"
    free_tier = True
    default_timeout = 30

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": self.secret("auth_key")},
            json={"query": "search_ioc", "search_term": observable.value},
            timeout=self.timeout,
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        if raw.get("query_status") == "no_result":
            return self.not_found("Not listed in ThreatFox.")
        if raw.get("query_status") != "ok":
            return self.failed(f"ThreatFox answered: {raw.get('query_status')}.")

        entries = [item for item in raw.get("data") or [] if isinstance(item, dict)]
        families = sorted(
            {
                str(item.get("malware_printable"))
                for item in entries
                if item.get("malware_printable")
            }
        )
        confidence = max(
            (int(item.get("confidence_level") or 0) for item in entries),
            default=0,
        )
        tags: set[str] = set(families)
        for item in entries:
            for tag in item.get("tags") or []:
                tags.add(str(tag).lower())

        summary = PluginSummary(
            verdict=Verdict.MALICIOUS if entries else Verdict.UNKNOWN,
            score=confidence,
            tags=sorted(tags),
            headline=f"Listed in ThreatFox as {', '.join(families) or 'a known IOC'}.",
            links=[{"label": "Open in ThreatFox", "url": "https://threatfox.abuse.ch/browse/"}],
            extra={
                "iocs": [
                    {
                        "id": item.get("id"),
                        "threat_type": item.get("threat_type"),
                        "malware": item.get("malware_printable"),
                        "first_seen": item.get("first_seen"),
                        "last_seen": item.get("last_seen"),
                        "reporter": item.get("reporter"),
                    }
                    for item in entries[:20]
                ]
            },
        )
        return self.ok(raw, summary)


@register
class MalwareBazaarAnalyzer(BaseAnalyzer):
    """Sample metadata for a file hash known to MalwareBazaar."""

    name = "malwarebazaar"
    label = "MalwareBazaar"
    description = "Malware sample metadata, family, signature and file type."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.HASH,)
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "auth_key", "Auth-Key", required=True, help_text=_AUTH_HELP, user_overridable=True
        ),
    )
    provider = ProviderInfo(
        name="abuse.ch — MalwareBazaar",
        url="https://bazaar.abuse.ch/",
        api_base_url="https://mb-api.abuse.ch/api/v1/ (query=get_info)",
        credential_url="https://auth.abuse.ch/ (Auth-Key)",
        free_tier="Free for everyone; an Auth-Key is now required on the abuse.ch APIs.",
        rate_limit="Fair use.",
        notes=(
            "Answers on a sample that was submitted to MalwareBazaar; silence is not a clean "
            "verdict."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://bazaar.abuse.ch/api/"
    free_tier = True
    default_timeout = 30

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": self.secret("auth_key")},
            data={"query": "get_info", "hash": observable.value},
            timeout=self.timeout,
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        if raw.get("query_status") in {"hash_not_found", "no_results"}:
            return self.not_found("Sample not present in MalwareBazaar.")
        if raw.get("query_status") != "ok":
            return self.failed(f"MalwareBazaar answered: {raw.get('query_status')}.")

        entries = [item for item in raw.get("data") or [] if isinstance(item, dict)]
        if not entries:
            return self.not_found("Sample not present in MalwareBazaar.")
        sample = entries[0]
        tags = [str(tag).lower() for tag in sample.get("tags") or []]
        if sample.get("signature"):
            tags.append(str(sample["signature"]).lower())

        summary = PluginSummary(
            verdict=Verdict.MALICIOUS,
            tags=tags,
            headline=f"Known malware sample: {sample.get('signature') or 'unclassified'}.",
            links=[
                {
                    "label": "Open in MalwareBazaar",
                    "url": f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash')}/",
                }
            ],
            extra={
                "file_name": sample.get("file_name"),
                "file_type": sample.get("file_type"),
                "file_size": sample.get("file_size"),
                "signature": sample.get("signature"),
                "first_seen": sample.get("first_seen"),
                "sha256": sample.get("sha256_hash"),
                "imphash": sample.get("imphash"),
                "delivery_method": sample.get("delivery_method"),
            },
        )
        return self.ok(raw, summary)


@register
class FeodoTrackerAnalyzer(BaseAnalyzer):
    """Botnet command-and-control check against the Feodo Tracker blocklist."""

    name = "feodotracker"
    label = "Feodo Tracker"
    description = "Botnet command-and-control server blocklist for IP addresses."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)
    provider = ProviderInfo(
        name="abuse.ch — Feodo Tracker",
        url="https://feodotracker.abuse.ch/",
        api_base_url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        credential_url="https://auth.abuse.ch/ (Auth-Key)",
        free_tier="Free for everyone; an Auth-Key is now required on the abuse.ch APIs.",
        rate_limit="Fair use.",
        notes=(
            "A published blocklist, downloaded whole: nothing about the observable is sent, so it "
            "is allowed up to TLP:RED."
        ),
    )
    max_tlp = Tlp.RED
    documentation_url = "https://feodotracker.abuse.ch/blocklist/"
    free_tier = True
    default_timeout = 30
    default_cache_ttl = 3600

    async def run(self, observable: Observable) -> PluginResult:
        response = await http_client.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=self.timeout
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        entries = response.json_body if isinstance(response.json_body, list) else []
        matches = [
            item
            for item in entries
            if isinstance(item, dict) and item.get("ip_address") == observable.value
        ]
        if not matches:
            return self.ok(
                {"listed": False, "blocklist_size": len(entries)},
                PluginSummary(
                    verdict=Verdict.CLEAN,
                    headline="Not present on the Feodo Tracker command-and-control blocklist.",
                ),
            )

        match = matches[0]
        return self.ok(
            {"listed": True, "entries": matches},
            PluginSummary(
                verdict=Verdict.MALICIOUS,
                tags=[str(match.get("malware") or "botnet").lower(), "c2"],
                open_ports=[int(match["port"])] if isinstance(match.get("port"), int) else [],
                country=match.get("country"),
                organisation=match.get("as_name"),
                asn=f"AS{match.get('as_number')}" if match.get("as_number") else None,
                headline=f"Active {match.get('malware') or 'botnet'} command-and-control server.",
                links=[
                    {
                        "label": "Feodo Tracker blocklist",
                        "url": "https://feodotracker.abuse.ch/browse/",
                    }
                ],
                extra={
                    "status": match.get("status"),
                    "first_seen": match.get("first_seen"),
                    "last_online": match.get("last_online"),
                },
            ),
        )


@register
class UrlHausAnalyzer(BaseAnalyzer):
    """Malware distribution URL lookup in URLhaus."""

    name = "urlhaus"
    label = "URLhaus"
    description = "Malware distribution URLs, payloads and threat status."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.URL,
        ObservableType.DOMAIN,
        ObservableType.IP,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "auth_key", "Auth-Key", required=True, help_text=_AUTH_HELP, user_overridable=True
        ),
    )
    provider = ProviderInfo(
        name="abuse.ch — URLhaus",
        url="https://urlhaus.abuse.ch/",
        api_base_url="https://urlhaus-api.abuse.ch/v1/{url|host}/",
        credential_url="https://auth.abuse.ch/ (Auth-Key)",
        free_tier="Free for everyone; an Auth-Key is now required on the abuse.ch APIs.",
        rate_limit="Fair use.",
        notes="Known malware distribution URLs and the hosts serving them.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://urlhaus-api.abuse.ch/"
    free_tier = True
    default_timeout = 30

    async def run(self, observable: Observable) -> PluginResult:
        headers = {"Auth-Key": self.secret("auth_key")}
        if observable.type is ObservableType.URL:
            endpoint, payload = "url", {"url": observable.value}
        else:
            endpoint, payload = "host", {"host": hostname_of(observable)}

        response = await http_client.post(
            f"https://urlhaus-api.abuse.ch/v1/{endpoint}/",
            headers=headers,
            data=payload,
            timeout=self.timeout,
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        status = raw.get("query_status")
        if status in {"no_results", "not_found"}:
            return self.not_found("Not listed in URLhaus.")
        if status != "ok":
            return self.failed(f"URLhaus answered: {status}.")

        urls = [item for item in raw.get("urls") or [] if isinstance(item, dict)]
        online = [item for item in urls if item.get("url_status") == "online"]
        tags: set[str] = {str(tag).lower() for tag in raw.get("tags") or [] if tag}
        for item in urls:
            for tag in item.get("tags") or []:
                tags.add(str(tag).lower())

        return self.ok(
            raw,
            PluginSummary(
                verdict=Verdict.MALICIOUS,
                tags=sorted(tags),
                headline=(
                    f"{len(urls)} malicious URL(s) recorded, {len(online)} currently online."
                    if urls
                    else f"Listed in URLhaus with threat {raw.get('threat')}."
                ),
                links=[
                    {
                        "label": "Open in URLhaus",
                        "url": str(raw.get("urlhaus_reference") or "https://urlhaus.abuse.ch/"),
                    }
                ],
                extra={
                    "threat": raw.get("threat"),
                    "url_status": raw.get("url_status"),
                    "date_added": raw.get("date_added"),
                    "payloads": [
                        {
                            "file_type": payload.get("file_type"),
                            "signature": payload.get("signature"),
                            "sha256": payload.get("response_sha256"),
                        }
                        for payload in raw.get("payloads") or []
                        if isinstance(payload, dict)
                    ][:20],
                },
            ),
        )
