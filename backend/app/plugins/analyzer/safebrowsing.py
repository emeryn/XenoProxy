"""Google Safe Browsing: the list that paints a browser red.

This is the verdict a victim will actually meet. An analyst asking "is this
phishing page live" usually means "will our users be stopped", and no other
source answers that question — a URL can be unknown to every reputation feed
and still be blocked in Chrome, or flagged everywhere and still load silently.

The lookup sends the URL to Google, which is a disclosure: it tells them what
is being investigated. Hence TLP:GREEN at most.
"""

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
from app.services.observables import Observable

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# What a match means, in the words the analyst uses.
_THREAT_LABEL = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful application",
}


@register
class SafeBrowsingAnalyzer(BaseAnalyzer):
    """Whether Google blocks this URL in a browser."""

    name = "google_safebrowsing"
    label = "Google Safe Browsing"
    description = "Whether a browser would block this URL, and what for."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.URL,
        ObservableType.DOMAIN,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="A Google Cloud API key with the Safe Browsing API enabled.",
            placeholder="AIza…",
        ),
    )
    provider = ProviderInfo(
        name="Google Safe Browsing",
        url="https://safebrowsing.google.com/",
        api_base_url="https://safebrowsing.googleapis.com/v4/threatMatches:find",
        credential_url=(
            "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com "
            "(enable the API, then create an API key)"
        ),
        free_tier="Free, with a generous default quota per project.",
        rate_limit="10,000 requests a day by default; raisable in the Cloud console.",
        notes=(
            "The lookup sends the URL to Google, which reveals what is being investigated. "
            "Capped at TLP:GREEN for that reason."
        ),
    )
    # The URL is disclosed to Google on every lookup.
    max_tlp = Tlp.GREEN
    free_tier = True
    default_timeout = 25
    default_cache_ttl = 10800
    documentation_url = "https://developers.google.com/safe-browsing/v4/lookup-api"

    async def run(self, observable: Observable) -> PluginResult:
        target = observable.value
        if observable.type is ObservableType.DOMAIN:
            # The list is keyed by URL; a bare domain is asked about as a page.
            target = f"http://{observable.value}/"

        payload = {
            "client": {"clientId": "xenoproxy", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": list(_THREAT_LABEL),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }
        response = await http_client.post(
            ENDPOINT,
            params={"key": self.secret("api_key")},
            json=payload,
            timeout=self.timeout,
        )
        if response.status_code == 429:
            raise PluginQuotaError("Safe Browsing returned HTTP 429.")
        if response.status_code in (401, 403):
            raise PluginQuotaError("Safe Browsing rejected the configured API key.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        matches = [entry for entry in raw.get("matches") or [] if isinstance(entry, dict)]

        if not matches:
            # An empty answer is the whole point of the source: it means a
            # browser lets this through today.
            return self.ok(
                {"matches": [], "queried": target},
                PluginSummary(
                    verdict=Verdict.CLEAN,
                    headline="No browser warning: Safe Browsing does not block this today.",
                    extra={"queried": target},
                ),
            )

        kinds = sorted(
            {
                _THREAT_LABEL.get(
                    str(entry.get("threatType")), str(entry.get("threatType"))
                )
                for entry in matches
            }
        )
        return self.ok(
            raw,
            PluginSummary(
                verdict=Verdict.MALICIOUS,
                tags=kinds,
                headline=f"A browser would block this: {', '.join(kinds)}.",
                extra={
                    "queried": target,
                    "threat_types": kinds,
                    "platforms": sorted(
                        {str(entry.get("platformType") or "") for entry in matches if entry}
                    ),
                },
            ),
        )
