"""URLScan.io search and on-demand scan submission."""

from __future__ import annotations

import asyncio
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

_BASE = "https://urlscan.io/api/v1"


@register
class UrlScanAnalyzer(BaseAnalyzer):
    """Existing scans for a URL or domain, with optional live submission."""

    name = "urlscan"
    label = "URLScan.io"
    description = "Page scan results, screenshot, contacted IPs and verdicts."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.URL,
        ObservableType.DOMAIN,
        ObservableType.IP,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            required=False,
            help_text="Needed only to submit new scans; search works anonymously.",
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "submit_new_scan": {
            "type": "boolean",
            "default": False,
            "label": "Submit a live scan when no recent result exists",
        },
        "visibility": {
            "type": "string",
            "default": "unlisted",
            "enum": ["public", "unlisted", "private"],
            "label": "Visibility of submitted scans",
        },
    }
    # Searching the index discloses the query to urlscan.io and nothing more,
    # which is what every other provider lookup does — so it sits at AMBER
    # like them.
    #
    # Submitting is a different act: the scan is published, and a published
    # scan is TLP:CLEAR. That is why submission refuses to run unless the job
    # itself is CLEAR, checked below rather than through this cap. Capping the
    # whole analyzer at CLEAR is what made it unusable: the default job TLP is
    # AMBER, so the search — keyless, harmless and enabled by default — never
    # ran at all.
    default_timeout = 90
    provider = ProviderInfo(
        name="urlscan.io",
        url="https://urlscan.io/",
        api_base_url="https://urlscan.io/api/v1/search/ and /api/v1/scan/",
        credential_url="https://urlscan.io/user/apikey",
        free_tier=(
            "Searching indexed scans needs no key at all. A key is only required to submit a new "
            "scan."
        ),
        rate_limit="Free key: 100 private and 5 000 public scans per month.",
        notes=(
            "Searching the index needs no key and runs at TLP:AMBER. Submitting a live scan "
            "publishes it, so it only runs when the job itself is TLP:CLEAR."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://urlscan.io/docs/api/"
    free_tier = True

    async def run(self, observable: Observable) -> PluginResult:
        query = self._search_query(observable)
        response = await http_client.get(
            f"{_BASE}/search/", params={"q": query, "size": 10}, timeout=self.timeout
        )
        if response.status_code == 429:
            raise PluginQuotaError("URLScan returned HTTP 429.")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        results = [item for item in raw.get("results") or [] if isinstance(item, dict)]

        if (
            not results
            and self.option("submit_new_scan", False)
            and (observable.type is ObservableType.URL)
            # A submitted scan is published, so it may only carry an observable
            # that may be published. The job's own TLP decides, not the
            # analyzer's cap, because the same analyzer does both things.
            and self.job_tlp is Tlp.CLEAR
        ):
            submitted = await self._submit(observable)
            if submitted is not None:
                return submitted

        if not results:
            return self.not_found("URLScan has no indexed scan for this observable.")

        latest = results[0]
        latest_time = (latest.get("task") or {}).get("time")
        page = latest.get("page") or {}
        verdicts = latest.get("verdicts") or {}
        malicious = bool(verdicts.get("overall", {}).get("malicious")) if verdicts else False
        score = (verdicts.get("overall") or {}).get("score") if verdicts else None

        summary = PluginSummary(
            verdict=Verdict.MALICIOUS if malicious else Verdict.CLEAN,
            score=int(score) if isinstance(score, int) else None,
            tags=[str(tag) for tag in (verdicts.get("overall") or {}).get("categories") or []],
            country=page.get("country"),
            asn=page.get("asn"),
            organisation=page.get("asnname"),
            hostnames=sorted(
                {str(item.get("page", {}).get("domain")) for item in results if item.get("page")}
            ),
            headline=f"{len(results)} indexed scan(s); latest from {latest_time}.",
            screenshot_url=str(latest.get("screenshot") or "") or None,
            links=[
                {"label": "Latest scan", "url": str(latest.get("result") or "")},
            ],
            extra={
                "latest_url": page.get("url"),
                "ip": page.get("ip"),
                "server": page.get("server"),
                "scans": [
                    {
                        "time": (item.get("task") or {}).get("time"),
                        "url": (item.get("page") or {}).get("url"),
                        "result": item.get("result"),
                        "screenshot": item.get("screenshot"),
                    }
                    for item in results[:10]
                ],
            },
        )
        return self.ok(raw, summary)

    def _search_query(self, observable: Observable) -> str:
        if observable.type is ObservableType.IP:
            return f"ip:{observable.value}"
        if observable.type is ObservableType.URL:
            return f"page.domain:{hostname_of(observable)}"
        return f"domain:{observable.value}"

    async def _submit(self, observable: Observable) -> PluginResult | None:
        """Submit a live scan and poll briefly for its result."""
        api_key = self.optional_secret("api_key")
        if not api_key:
            return None
        submission = await http_client.post(
            f"{_BASE}/scan/",
            headers={"API-Key": api_key, "Content-Type": "application/json"},
            json={
                "url": observable.value,
                "visibility": str(self.option("visibility", "unlisted")),
            },
            timeout=self.timeout,
        )
        if submission.status_code == 429:
            raise PluginQuotaError("URLScan refused the submission with HTTP 429.")
        if not submission.ok:
            return self.provider_http_error(submission.status_code)

        body = submission.json_body or {}
        scan_uuid = body.get("uuid")
        if not scan_uuid:
            return self.failed("URLScan accepted the submission but returned no scan identifier.")

        for _ in range(10):
            await asyncio.sleep(6)
            result = await http_client.get(f"{_BASE}/result/{scan_uuid}/", timeout=self.timeout)
            if result.status_code == 200:
                raw = result.json_body or {}
                verdicts = (raw.get("verdicts") or {}).get("overall") or {}
                malicious = bool(verdicts.get("malicious"))
                return self.ok(
                    raw,
                    PluginSummary(
                        verdict=Verdict.MALICIOUS if malicious else Verdict.CLEAN,
                        score=verdicts.get("score")
                        if isinstance(verdicts.get("score"), int)
                        else None,
                        headline="Live scan completed.",
                        links=[
                            {
                                "label": "Scan result",
                                "url": f"https://urlscan.io/result/{scan_uuid}/",
                            }
                        ],
                        extra={"uuid": scan_uuid},
                    ),
                )
        return self.ok(
            {"uuid": scan_uuid, "pending": True},
            PluginSummary(
                headline="Live scan submitted; results were not ready in time.",
                links=[{"label": "Scan result", "url": f"https://urlscan.io/result/{scan_uuid}/"}],
            ),
        )
