"""VirusTotal API v3 lookup for IP addresses, domains, URLs and file hashes."""

from __future__ import annotations

import base64
from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import (
    Detection,
    PluginQuotaError,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register
from app.plugins.user_keys import USER_KEY_HELP
from app.services.observables import Observable

_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    """VirusTotal identifies URLs by their unpadded base64url form."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


@register
class VirusTotalAnalyzer(BaseAnalyzer):
    """Detection ratios, reputation and categorisation from VirusTotal."""

    name = "virustotal"
    label = "VirusTotal"
    description = "Engine detection ratio, reputation score and categories."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.HASH,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="VirusTotal API v3 key. " + USER_KEY_HELP,
            user_overridable=True,
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "malicious_threshold": {
            "type": "integer",
            "default": 3,
            "label": "Engines flagging as malicious before the verdict is Malicious",
        },
        "suspicious_threshold": {
            "type": "integer",
            "default": 2,
            "label": "Engines flagging at all before the verdict is Suspicious",
        },
    }
    provider = ProviderInfo(
        name="VirusTotal",
        url="https://www.virustotal.com/",
        api_base_url="https://www.virustotal.com/api/v3/{ip_addresses|domains|urls|files}/{id}",
        credential_url="https://www.virustotal.com/gui/my-apikey",
        free_tier="A public key works for lookups.",
        rate_limit=(
            "Public key: 4 requests per minute, 500 per day. Raise the cache lifetime rather than "
            "the quota."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://docs.virustotal.com/reference/overview"

    def _endpoint(self, observable: Observable) -> tuple[str, str]:
        if observable.type is ObservableType.IP:
            return f"{_BASE}/ip_addresses/{observable.value}", (
                f"https://www.virustotal.com/gui/ip-address/{observable.value}"
            )
        if observable.type is ObservableType.DOMAIN:
            return f"{_BASE}/domains/{observable.value}", (
                f"https://www.virustotal.com/gui/domain/{observable.value}"
            )
        if observable.type is ObservableType.URL:
            identifier = _url_id(observable.value)
            return f"{_BASE}/urls/{identifier}", (
                f"https://www.virustotal.com/gui/url/{identifier}"
            )
        return f"{_BASE}/files/{observable.value}", (
            f"https://www.virustotal.com/gui/file/{observable.value}"
        )

    async def run(self, observable: Observable) -> PluginResult:
        endpoint, gui_url = self._endpoint(observable)
        response = await http_client.get(
            endpoint,
            headers={"x-apikey": self.secret("api_key")},
            timeout=self.timeout,
        )
        if response.status_code == 404:
            return self.not_found("VirusTotal has no record for this observable.")
        if response.status_code == 429:
            raise PluginQuotaError("VirusTotal returned HTTP 429 (quota exhausted).")
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        attributes = ((raw.get("data") or {}).get("attributes") or {}) if raw else {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        total = sum(int(value or 0) for value in stats.values()) or 0

        threshold = int(self.option("malicious_threshold", 3))
        flagging = max(int(self.option("suspicious_threshold", 2)), 1)

        # One engine out of seventy is not a finding.
        #
        # VirusTotal runs dozens of engines, several of which are heuristic and
        # flag on packing, on a young domain or on a rare file. A single one of
        # them disagreeing with all the others is the ordinary background noise
        # of the service, and promoting it to Suspicious promoted the whole job
        # with it — which taught analysts to ignore the verdict, the one thing
        # it must never do. The ratio and the engine list below stay visible
        # whatever the verdict, so a lone detection is never hidden, only
        # stopped from shouting.
        if malicious >= threshold:
            verdict = Verdict.MALICIOUS
        elif malicious + suspicious >= flagging:
            verdict = Verdict.SUSPICIOUS
        elif total:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN

        results = attributes.get("last_analysis_results") or {}
        detections: list[Detection] = []
        if isinstance(results, dict):
            for engine, outcome in results.items():
                if not isinstance(outcome, dict):
                    continue
                category = str(outcome.get("category") or "")
                if category not in {"malicious", "suspicious"}:
                    continue
                detections.append(
                    Detection(
                        engine=str(outcome.get("engine_name") or engine)[:64],
                        category=category,
                        result=str(outcome["result"])[:96] if outcome.get("result") else None,
                    )
                )
        # Malicious before suspicious, then alphabetically, so the list reads
        # the same way twice and the strongest opinion is at the top.
        detections.sort(key=lambda entry: (entry.category != "malicious", entry.engine.lower()))

        tags = [str(tag) for tag in attributes.get("tags") or []]
        categories = attributes.get("categories") or {}
        if isinstance(categories, dict):
            tags.extend(sorted({str(value) for value in categories.values()}))

        summary = PluginSummary(
            verdict=verdict,
            score=int(attributes.get("reputation"))
            if attributes.get("reputation") is not None
            else None,
            tags=tags,
            country=attributes.get("country"),
            asn=f"AS{attributes.get('asn')}" if attributes.get("asn") else None,
            organisation=attributes.get("as_owner"),
            detection_ratio=f"{malicious + suspicious}/{total}" if total else None,
            detections=detections,
            headline=(
                f"{malicious} engine(s) flag this observable as malicious and "
                f"{suspicious} as suspicious, out of {total}."
                if total
                else "No engine verdict available."
            ),
            links=[{"label": "Open in VirusTotal", "url": gui_url}],
            extra={
                "last_analysis_stats": stats,
                "meaningful_name": attributes.get("meaningful_name"),
                "file_type": attributes.get("type_description"),
                "size": attributes.get("size"),
                "names": [str(name) for name in attributes.get("names") or []][:20],
                "last_analysis_date": attributes.get("last_analysis_date"),
                "crowdsourced_ids": [
                    rule.get("rule_msg")
                    for rule in attributes.get("crowdsourced_ids_results") or []
                    if isinstance(rule, dict)
                ][:20],
            },
        )
        return self.ok(raw, summary)
