"""Censys Search API v2 host and certificate lookup."""

from __future__ import annotations

import base64
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
from app.services.observables import Observable, hostname_of

_BASE = "https://search.censys.io/api/v2"


@register
class CensysAnalyzer(BaseAnalyzer):
    """Exposed services and TLS fingerprints from the Censys host and certificate index."""

    name = "censys"
    label = "Censys"
    description = "Exposed services, software and TLS certificate fingerprints."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_id",
            "API ID",
            help_text="Censys Search API ID. " + USER_KEY_HELP,
            user_overridable=True,
        ),
        SecretSpec(
            "api_secret",
            "API secret",
            help_text="Censys Search API secret.",
            user_overridable=True,
        ),
    )
    provider = ProviderInfo(
        name="Censys Platform",
        url="https://platform.censys.io/",
        api_base_url="https://api.platform.censys.io/v3/global/asset/host/{ip}",
        credential_url="https://platform.censys.io/ (Settings, API Keys)",
        free_tier="A community account allows a limited number of queries per month.",
        rate_limit="Published per plan; the community plan is the tightest.",
        notes="The organisation identifier goes with the key: both are required.",
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://search.censys.io/api"

    def _auth_header(self) -> dict[str, str]:
        token = base64.b64encode(
            f"{self.secret('api_id')}:{self.secret('api_secret')}".encode()
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    async def run(self, observable: Observable) -> PluginResult:
        if observable.type is ObservableType.IP:
            return await self._host_lookup(observable)
        return await self._certificate_search(hostname_of(observable))

    async def _host_lookup(self, observable: Observable) -> PluginResult:
        response = await http_client.get(
            f"{_BASE}/hosts/{observable.value}",
            headers=self._auth_header(),
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("Censys has no host record for this address.")
        if response.status_code == 429:
            raise PluginQuotaError("Censys returned HTTP 429.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        host = (raw.get("result") or {}) if isinstance(raw.get("result"), dict) else {}
        services = [s for s in host.get("services") or [] if isinstance(s, dict)]
        ports = [int(s["port"]) for s in services if isinstance(s.get("port"), int)]
        location = host.get("location") or {}
        autonomous_system = host.get("autonomous_system") or {}

        summary = PluginSummary(
            verdict=Verdict.CLEAN if ports else Verdict.UNKNOWN,
            open_ports=ports,
            country=location.get("country"),
            asn=f"AS{autonomous_system.get('asn')}" if autonomous_system.get("asn") else None,
            organisation=autonomous_system.get("name"),
            hostnames=sorted(
                {
                    str(name.get("name"))
                    for name in host.get("dns", {}).get("names", [])
                    if isinstance(name, dict) and name.get("name")
                }
            )
            if isinstance(host.get("dns"), dict)
            else [],
            headline=f"{len(ports)} exposed service(s) indexed by Censys.",
            links=[
                {
                    "label": "Open in Censys",
                    "url": f"https://search.censys.io/hosts/{observable.value}",
                }
            ],
            extra={
                "services": [
                    {
                        "port": service.get("port"),
                        "service_name": service.get("service_name"),
                        "transport": service.get("transport_protocol"),
                        "software": [
                            entry.get("product")
                            for entry in service.get("software") or []
                            if isinstance(entry, dict)
                        ],
                        "tls_fingerprint": (service.get("tls") or {})
                        .get("certificates", {})
                        .get("leaf_data", {})
                        .get("fingerprint")
                        if isinstance(service.get("tls"), dict)
                        else None,
                    }
                    for service in services[:40]
                ],
                "operating_system": host.get("operating_system"),
            },
        )
        return self.ok(raw, summary)

    async def _certificate_search(self, hostname: str) -> PluginResult:
        response = await http_client.get(
            f"{_BASE}/certificates/search",
            headers=self._auth_header(),
            params={"q": f"names: {hostname}", "per_page": 25},
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Censys returned HTTP 429.")
        if response.status_code == 404:
            return self.not_found("Censys has no certificate for this name.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        hits = [hit for hit in (raw.get("result") or {}).get("hits", []) if isinstance(hit, dict)]
        names: set[str] = set()
        for hit in hits:
            for name in hit.get("names") or []:
                names.add(str(name))
        summary = PluginSummary(
            verdict=Verdict.UNKNOWN,
            hostnames=sorted(names),
            headline=f"{len(hits)} certificate(s) referencing {hostname}.",
            links=[
                {
                    "label": "Open in Censys",
                    "url": f"https://search.censys.io/search?resource=certificates&q={hostname}",
                }
            ],
            extra={
                "certificates": [
                    {
                        "fingerprint": hit.get("fingerprint_sha256"),
                        "issuer": (hit.get("parsed") or {}).get("issuer_dn"),
                        "subject": (hit.get("parsed") or {}).get("subject_dn"),
                        "validity": (hit.get("parsed") or {}).get("validity_period"),
                    }
                    for hit in hits[:25]
                ]
            },
        )
        return self.ok(raw, summary)
