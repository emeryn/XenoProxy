"""n8n notification connector.

Tells an n8n workflow that a job finished, handing it the aggregated verdict,
the tags, the synthetic summary and — optionally — every analyzer's raw payload.
This is what drives downstream automation: open a ticket, post to a channel,
block an address, file an abuse report.

It shares its signing scheme with the `n8n` analyzer, so one workflow can
authenticate both. The `event` field tells the two apart.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.connector import BaseConnector
from app.plugins.base.plugin import (
    JobContext,
    PluginResult,
    PluginSummary,
    ProviderInfo,
    SecretSpec,
)
from app.plugins.base.registry import register
from app.plugins.webhook import coerce_json_object, post_signed


@register
class N8nWebhookConnector(BaseConnector):
    """Posts a finished job to an n8n webhook so a workflow can act on it."""

    name = "n8n_webhook"
    label = "n8n notification"
    description = "Posts the finished job, with its verdict and tags, to an n8n workflow."
    supported_types: ClassVar[tuple[ObservableType, ...]] = ()
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "webhook_url",
            "Webhook URL",
            help_text="Full n8n production webhook URL that receives finished jobs.",
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
        "include_raw_reports": {
            "type": "boolean",
            "default": False,
            "label": "Include each analyzer's raw payload (large)",
        },
        "minimum_verdict": {
            "type": "string",
            "default": "unknown",
            "label": "Notify only from this verdict upwards",
            "enum": ["clean", "unknown", "suspicious", "malicious"],
        },
    }
    provider = ProviderInfo(
        name="n8n",
        url="https://n8n.io/",
        api_base_url="The production webhook URL that receives finished jobs",
        free_tier="Self-hosted and free; the address is yours.",
        notes=(
            "Signed the same way as the n8n analyzer, so one workflow can authenticate both. The "
            "`event` field tells them apart."
        ),
        self_hosted=True,
    )
    max_tlp = Tlp.RED
    default_timeout = 60
    default_cache_ttl = 0
    documentation_url = (
        "https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook/"
    )

    _SEVERITY: ClassVar[dict[Verdict, int]] = {
        Verdict.CLEAN: 0,
        Verdict.UNKNOWN: 1,
        Verdict.SUSPICIOUS: 2,
        Verdict.MALICIOUS: 3,
    }

    def refusal_reason(self, context: JobContext, job_status: Any) -> str | None:
        """Apply the operator's verdict floor on top of the shared checks."""
        base = super().refusal_reason(context, job_status)
        if base is not None:
            return base

        configured = str(self.option("minimum_verdict", "unknown") or "unknown").lower()
        try:
            floor = Verdict(configured)
        except ValueError:
            # A typo in the option must not silently disable the connector.
            return f"the configured minimum_verdict '{configured}' is not a verdict"
        if self._SEVERITY[context.verdict] < self._SEVERITY[floor]:
            return f"verdict is {context.verdict.value}, below the configured floor {floor.value}"
        return None

    def _payload(self, context: JobContext) -> dict[str, Any]:
        include_raw = bool(self.option("include_raw_reports", False))
        return {
            "event": "job.finished",
            "source": "xenoproxy",
            "job_id": str(context.job_id),
            "observable": context.observable.value,
            "observable_type": context.observable.type.value,
            "verdict": context.verdict.value,
            "tlp": context.tlp.value,
            "tags": context.tags,
            "requested_by": context.requested_by,
            "summary": context.summary,
            "reports": [
                {
                    "plugin": report.plugin_name,
                    "status": report.status.value,
                    "summary": report.summary,
                    **({"raw_output": report.raw_output} if include_raw else {}),
                }
                for report in context.reports
            ],
        }

    async def run(self, context: JobContext) -> PluginResult:
        response = await post_signed(
            self.secret("webhook_url"),
            self._payload(context),
            timeout=self.timeout,
            allow_private=bool(self.option("allow_private_target", True)),
            signing_key=self.optional_secret("signing_key"),
            auth_header=str(self.option("auth_header", "X-Webhook-Token")),
            auth_token=self.optional_secret("auth_token"),
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw = (
            coerce_json_object(response.json_body)
            if response.json_body is not None
            else {"response_text": response.text[:4000]}
        )
        return self.ok(
            raw,
            PluginSummary(
                verdict=context.verdict,
                headline=f"Workflow notified (HTTP {response.status_code}).",
                extra={"workflow_keys": sorted(raw.keys())[:40]},
            ),
        )
