"""Generic n8n webhook analyzer.

Asks an existing n8n workflow about an observable and folds its JSON answer into
the job like any other analyzer. The target URL is operator-supplied, so it goes
through the SSRF validation of the central HTTP client.

This is the enrichment half of the n8n integration. The notification half — tell
a workflow that a job finished, with its verdict — is the `n8n_webhook`
connector, which runs in the connector phase instead.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo, SecretSpec
from app.plugins.base.registry import register
from app.plugins.webhook import coerce_json_object, post_signed
from app.services.observables import Observable

VERDICT_WORDS = {
    "clean": Verdict.CLEAN,
    "benign": Verdict.CLEAN,
    "suspicious": Verdict.SUSPICIOUS,
    "malicious": Verdict.MALICIOUS,
}


@register
class N8nAnalyzer(BaseAnalyzer):
    """Posts the observable to an n8n webhook and normalises the workflow answer."""

    name = "n8n"
    label = "n8n workflow"
    description = "Asks an existing n8n workflow about the observable and integrates its answer."
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.HASH,
        ObservableType.GENERIC,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "webhook_url",
            "Webhook URL",
            help_text="Full n8n production webhook URL.",
        ),
        SecretSpec(
            "signing_key",
            "Signing key",
            required=False,
            help_text=(
                "When set, requests carry X-XenoProxy-Signature (HMAC-SHA256) and "
                "X-XenoProxy-Timestamp."
            ),
        ),
        SecretSpec(
            "auth_token",
            "Header token",
            required=False,
            help_text="Sent as the value of the header named by the 'auth_header' option.",
        ),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "auth_header": {
            "type": "string",
            "default": "X-Webhook-Token",
            "label": "Auth header name",
        },
        "allow_private_target": {
            "type": "boolean",
            "default": True,
            "label": "Allow a webhook on the internal network",
        },
        "verdict_field": {
            "type": "string",
            "default": "verdict",
            "label": "Field of the answer holding the verdict",
        },
    }
    # The workflow runs on infrastructure the team controls, so an observable may
    # reach it at any handling level.
    provider = ProviderInfo(
        name="n8n",
        url="https://n8n.io/",
        api_base_url="The production webhook URL of your own workflow",
        free_tier="Self-hosted and free; the address is yours.",
        notes=(
            "Requests carry X-XenoProxy-Signature (HMAC-SHA256) and "
            "X-XenoProxy-Timestamp when a signing "
            "key is set, so the workflow can verify them."
        ),
        self_hosted=True,
    )
    max_tlp = Tlp.RED
    default_timeout = 90
    default_cache_ttl = 3600
    documentation_url = (
        "https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/"
    )

    async def run(self, observable: Observable) -> PluginResult:
        response = await post_signed(
            self.secret("webhook_url"),
            {
                "event": "observable.analyze",
                "observable": observable.value,
                "observable_type": observable.type.value,
                "hash_algorithm": observable.hash_algorithm,
                "source": "xenoproxy",
            },
            timeout=self.timeout,
            allow_private=bool(self.option("allow_private_target", True)),
            signing_key=self.optional_secret("signing_key"),
            auth_header=str(self.option("auth_header", "X-Webhook-Token")),
            auth_token=self.optional_secret("auth_token"),
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        if response.json_body is None:
            return self.ok(
                {"response_text": response.text[:10000]},
                PluginSummary(
                    verdict=Verdict.UNKNOWN,
                    headline="The workflow answered with a non-JSON payload.",
                ),
            )

        raw = coerce_json_object(response.json_body)
        verdict_field = str(self.option("verdict_field", "verdict"))
        verdict = VERDICT_WORDS.get(str(raw.get(verdict_field) or "").lower(), Verdict.UNKNOWN)

        return self.ok(
            raw,
            PluginSummary(
                verdict=verdict,
                score=int(raw["score"]) if isinstance(raw.get("score"), int) else None,
                tags=[str(tag).lower() for tag in raw.get("tags") or [] if tag],
                headline=str(raw.get("summary") or "Workflow completed."),
                extra={"workflow_keys": sorted(raw.keys())[:40]},
            ),
        )
