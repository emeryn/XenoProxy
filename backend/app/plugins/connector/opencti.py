"""OpenCTI export connector.

Pushes a finished job's observable into OpenCTI as a STIX cyber observable,
carrying the aggregated verdict as the confidence score and the job's tags as
labels.

Running this as a connector rather than an analyzer is what makes the verdict
usable: during the analysis phase no verdict exists yet, so the previous
analyzer-shaped version could only ever export `unknown`.
"""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
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
from app.services.observables import Observable

_STIX_TYPES = {
    ObservableType.IP: "IPv4-Addr",
    ObservableType.DOMAIN: "Domain-Name",
    ObservableType.URL: "Url",
    ObservableType.HASH: "StixFile",
    ObservableType.GENERIC: "Text",
}

# OpenCTI reads `x_opencti_score` as a 0-100 confidence that the observable is
# malicious, so the XenoProxy verdict maps onto it directly.
_VERDICT_SCORES = {
    Verdict.CLEAN: 10,
    Verdict.UNKNOWN: 50,
    Verdict.SUSPICIOUS: 70,
    Verdict.MALICIOUS: 90,
}

_CREATE_MUTATION = """
mutation XenoProxyCreateObservable($type: String!, $x_opencti_score: Int, $createdBy: String,
                               $objectLabel: [String], $IPv4Addr: IPv4AddrAddInput,
                               $DomainName: DomainNameAddInput, $Url: UrlAddInput,
                               $StixFile: StixFileAddInput, $Text: TextAddInput) {
  stixCyberObservableAdd(
    type: $type
    x_opencti_score: $x_opencti_score
    createdBy: $createdBy
    objectLabel: $objectLabel
    IPv4Addr: $IPv4Addr
    DomainName: $DomainName
    Url: $Url
    StixFile: $StixFile
    Text: $Text
  ) {
    id
    standard_id
    observable_value
  }
}
"""


@register
class OpenCtiConnector(BaseConnector):
    """Exports the analysed observable and its verdict to an OpenCTI platform."""

    name = "opencti_export"
    label = "OpenCTI export"
    description = (
        "Creates or updates the observable in OpenCTI with the XenoProxy verdict and tags."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.IP,
        ObservableType.DOMAIN,
        ObservableType.URL,
        ObservableType.HASH,
        ObservableType.GENERIC,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec("base_url", "Platform URL", help_text="For example https://opencti.example.com"),
        SecretSpec("api_token", "API token", help_text="OpenCTI user or connector token."),
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "score_override": {
            "type": "integer",
            "default": 0,
            "label": "Fixed confidence score; 0 derives it from the XenoProxy verdict",
        },
        "labels": {
            "type": "string",
            "default": "xenoproxy",
            "label": "Comma-separated label identifiers always applied",
        },
        "export_job_tags": {
            "type": "boolean",
            "default": True,
            "label": "Also apply the job's tags as OpenCTI labels",
        },
        "allow_private_target": {
            "type": "boolean",
            "default": True,
            "label": "Allow an OpenCTI platform on the internal network",
        },
    }
    # The export leaves the instance, so it is barred at TLP:RED like any other
    # outbound integration. An on-premises OpenCTI is still a third party as far
    # as the observable's handling caveat is concerned.
    provider = ProviderInfo(
        name="OpenCTI",
        url="https://filigran.io/solutions/open-cti/",
        api_base_url="{your platform}/graphql",
        credential_url=(
            "Your platform: Settings, Security, Users, the token of a user or connector account"
        ),
        free_tier="Open source and self-hosted.",
        notes=(
            "The export creates a STIX cyber observable carrying the XenoProxy verdict as its "
            "confidence score."
        ),
        self_hosted=True,
    )
    max_tlp = Tlp.AMBER
    default_timeout = 60
    default_cache_ttl = 0
    documentation_url = "https://docs.opencti.io/latest/deployment/connectors/"
    # An archival target: a partial analysis is still worth recording.
    run_on_partial_failure = True

    def _value_input(self, observable: Observable) -> tuple[str, dict[str, Any]]:
        stix_type = _STIX_TYPES.get(observable.type, "Text")
        if stix_type == "StixFile":
            key = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(observable.value), "SHA-256")
            return stix_type, {
                "StixFile": {"hashes": [{"algorithm": key, "hash": observable.value}]}
            }
        field = {
            "IPv4-Addr": "IPv4Addr",
            "Domain-Name": "DomainName",
            "Url": "Url",
            "Text": "Text",
        }[stix_type]
        return stix_type, {field: {"value": observable.value}}

    def _labels(self, context: JobContext) -> list[str]:
        """Merge the operator's fixed labels with the job's own tags."""
        labels = [
            label.strip()
            for label in str(self.option("labels", "xenoproxy")).split(",")
            if label.strip()
        ]
        if self.option("export_job_tags", True):
            labels.extend(context.tags)
        labels.append(f"xenoproxy-verdict-{context.verdict.value}")
        return list(dict.fromkeys(labels))[:40]

    async def run(self, context: JobContext) -> PluginResult:
        base_url = self.secret("base_url").rstrip("/")
        stix_type, value_input = self._value_input(context.observable)
        labels = self._labels(context)

        override = int(self.option("score_override", 0) or 0)
        score = override if override > 0 else _VERDICT_SCORES[context.verdict]

        variables: dict[str, Any] = {
            "type": stix_type,
            "x_opencti_score": score,
            "objectLabel": labels,
            **value_input,
        }

        response = await http_client.post(
            f"{base_url}/graphql",
            headers={
                "Authorization": f"Bearer {self.secret('api_token')}",
                "Content-Type": "application/json",
            },
            json={"query": _CREATE_MUTATION, "variables": variables},
            timeout=self.timeout,
            allow_private=bool(self.option("allow_private_target", True)),
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        if raw.get("errors"):
            message = str((raw["errors"][0] or {}).get("message") or "unknown error")[:300]
            return self.failed(f"OpenCTI rejected the export: {message}")

        created = (raw.get("data") or {}).get("stixCyberObservableAdd") or {}
        identifier = created.get("id")
        if not identifier:
            return self.failed("OpenCTI did not return an observable identifier.")

        return self.ok(
            raw,
            PluginSummary(
                verdict=context.verdict,
                score=score,
                tags=labels,
                headline=f"Exported to OpenCTI as {stix_type} with score {score}.",
                links=[
                    {
                        "label": "Open in OpenCTI",
                        "url": f"{base_url}/dashboard/observations/observables/{identifier}",
                    }
                ],
                extra={"opencti_id": identifier, "standard_id": created.get("standard_id")},
            ),
        )
