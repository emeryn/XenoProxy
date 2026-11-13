"""Joe Sandbox, in its two deployments.

They are two analyzers rather than one with a switch, because the difference is
not a setting: it changes where the observable goes and who can read the result.

**Cloud Basic** is free and **public**. Every submission is published on
joesandbox.com, which makes it a disclosure, not a lookup. It is therefore
capped at TLP:CLEAR, and an administrator who enables submission has to say so
explicitly.

**Enterprise** runs on an appliance the operator owns. Submissions stay inside,
so it goes up to TLP:RED, the base URL is theirs to give, and the options that
only an appliance has — choosing a sandbox, allowing the sample internet access,
fetching the full report — exist only there.

Both search existing analyses first, so a submission quota is only ever spent
when nothing is already indexed.
"""

from __future__ import annotations

import asyncio
from typing import Any, ClassVar

from app.core import http_client
from app.core.http_client import HttpResult
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

CLOUD_API = "https://jbxcloud.joesecurity.org/api"

_DETECTIONS = {
    "clean": Verdict.CLEAN,
    "suspicious": Verdict.SUSPICIOUS,
    "malicious": Verdict.MALICIOUS,
}


class BaseJoeSandbox(BaseAnalyzer):
    """What both deployments share: search, submit, read the verdict."""

    supported_types: ClassVar[tuple[ObservableType, ...]] = (
        ObservableType.HASH,
        ObservableType.URL,
        ObservableType.FILE,
    )
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec(
            "api_key",
            "API key",
            help_text="From your Joe Sandbox account page.",
            placeholder="a 40-character key",
        ),
    )
    default_timeout = 120
    default_cache_ttl = 86400
    documentation_url = "https://jbxcloud.joesecurity.org/userguide"

    # How long to wait for a submitted analysis, as attempts of this interval.
    poll_attempts: ClassVar[int] = 10
    poll_interval: ClassVar[int] = 15

    def base_url(self) -> str:
        raise NotImplementedError

    def submission_fields(self) -> dict[str, str]:
        """Extra form fields this deployment sends with a submission."""
        return {}

    async def run(self, observable: Observable) -> PluginResult:
        api_key = self.secret("api_key")
        search = await http_client.post(
            f"{self.base_url()}/v2/analysis/search",
            data={"apikey": api_key, "q": observable.value},
            timeout=self.timeout,
            allow_private=True,
        )
        if search.status_code == 429:
            raise PluginQuotaError("Joe Sandbox returned HTTP 429.")
        if not search.ok:
            return self.provider_http_error(search.status_code)

        matches = [
            item for item in (search.json_body or {}).get("data") or [] if isinstance(item, dict)
        ]
        if matches:
            return await self._fetch_info(api_key, str(matches[0].get("webid") or ""))

        if not self.option("submit_new_analysis", False):
            return self.not_found("No Joe Sandbox analysis is indexed for this observable.")

        # A submitted sample leaves the instance, so the deployment's policy
        # decides. Saying it plainly matters: an analyst who thinks a sample
        # was detonated and reads "nothing found" would draw the wrong
        # conclusion from a scan that never ran.
        if self.sample is not None and not self.sample.may_leave:
            return self.failed(
                "This instance does not send submitted files to providers, so the sample was "
                "not detonated. An administrator can allow it in Settings, Scanning."
            )

        payload = self.sample_bytes()
        if payload is not None:
            return await self._submit_file(api_key, payload)
        if observable.type is not ObservableType.URL:
            # A hash on its own is not something to submit: there is no sample.
            return self.not_found(
                "No analysis is indexed, and no sample was submitted with this job."
            )
        return await self._submit_url(api_key, observable)

    async def _submit_file(self, api_key: str, payload: bytes) -> PluginResult:
        """Send the sample itself, which is what a sandbox is for."""
        if not self.option("accept_tac", False):
            return self.failed(
                "Submitting requires an administrator to accept the Joe Sandbox terms of "
                "service, with the 'accept_tac' option."
            )

        name = (self.sample.file_name if self.sample else "") or "sample.bin"
        submission = await http_client.post(
            f"{self.base_url()}/v2/submission/new",
            data={"apikey": api_key, "accept-tac": "1", **self.submission_fields()},
            files={"sample": (name, payload)},
            timeout=self.timeout,
            allow_private=True,
        )
        return await self._await_submission(api_key, submission)

    async def _submit_url(self, api_key: str, observable: Observable) -> PluginResult:
        if not self.option("accept_tac", False):
            return self.failed(
                "Submitting requires an administrator to accept the Joe Sandbox terms of "
                "service, with the 'accept_tac' option."
            )

        submission = await http_client.post(
            f"{self.base_url()}/v2/submission/new",
            data={
                "apikey": api_key,
                "accept-tac": "1",
                "url": observable.value,
                **self.submission_fields(),
            },
            timeout=self.timeout,
            allow_private=True,
        )
        return await self._await_submission(api_key, submission)

    async def _await_submission(self, api_key: str, submission: HttpResult) -> PluginResult:
        """Poll a fresh submission until the analysis appears, or time out."""
        if not submission.ok:
            return self.provider_http_error(submission.status_code)
        submission_id = str(
            ((submission.json_body or {}).get("data") or {}).get("submission_id") or ""
        )
        if not submission_id:
            return self.failed("Joe Sandbox accepted the submission but returned no identifier.")

        for _ in range(self.poll_attempts):
            await asyncio.sleep(self.poll_interval)
            info = await http_client.post(
                f"{self.base_url()}/v2/submission/info",
                data={"apikey": api_key, "submission_id": submission_id},
                timeout=self.timeout,
                allow_private=True,
            )
            data = ((info.json_body or {}).get("data") or {}) if info.ok else {}
            if data.get("status") == "finished":
                analyses = [
                    entry for entry in data.get("analyses") or [] if isinstance(entry, dict)
                ]
                if analyses:
                    return await self._fetch_info(api_key, str(analyses[0].get("webid") or ""))

        # The analysis is running, not failed. Saying so beats a FAILED report
        # that an analyst would re-run, spending the quota a second time.
        return self.ok(
            {"submission_id": submission_id, "pending": True},
            PluginSummary(
                headline=(
                    f"Submitted as {submission_id}; the report was not ready within "
                    f"{self.poll_attempts * self.poll_interval} seconds. Re-run this plugin "
                    "later to pick it up."
                ),
                extra={"submission_id": submission_id, "pending": True},
            ),
        )

    async def _fetch_info(self, api_key: str, web_id: str) -> PluginResult:
        if not web_id:
            return self.failed("Joe Sandbox returned an analysis without an identifier.")

        response = await http_client.post(
            f"{self.base_url()}/v2/analysis/info",
            data={"apikey": api_key, "webid": web_id},
            timeout=self.timeout,
            allow_private=True,
        )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        data = raw.get("data") or {}
        detection = str(data.get("detection") or "unknown").lower()
        score = data.get("score")
        threat = str(data.get("threatname") or "")

        headline = f"Detection: {detection}"
        if isinstance(score, int):
            headline += f" (score {score}/100)"
        if threat and threat.lower() not in {"unknown", "none"}:
            headline += f", {threat}"

        return self.ok(
            raw,
            PluginSummary(
                verdict=_DETECTIONS.get(detection, Verdict.UNKNOWN),
                score=int(score) if isinstance(score, int) else None,
                tags=[tag for tag in (detection, data.get("classification"), threat) if tag],
                headline=headline,
                links=[
                    {
                        "label": "Open the report",
                        "url": f"{self.base_url().removesuffix('/api')}/analysis/{web_id}",
                    }
                ],
                extra={
                    "webid": web_id,
                    "status": data.get("status"),
                    "classification": data.get("classification"),
                    "threatname": threat,
                    "runs": data.get("runs"),
                },
            ),
        )


@register
class JoeSandboxCloudAnalyzer(BaseJoeSandbox):
    """Joe Sandbox Cloud Basic: free, and public."""

    name = "joesandbox_cloud"
    label = "Joe Sandbox Cloud Basic"
    description = (
        "Behavioural verdicts from the free Joe Sandbox cloud. Submissions are published."
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "submit_new_analysis": {
            "type": "boolean",
            "default": False,
            "label": "Submit a URL when nothing is indexed (the submission becomes public)",
        },
        "accept_tac": {
            "type": "boolean",
            "default": False,
            "label": "Accept the Joe Sandbox terms of service on submission",
        },
    }
    provider = ProviderInfo(
        name="Joe Sandbox Cloud Basic",
        url="https://www.joesandbox.com/",
        api_base_url="https://jbxcloud.joesecurity.org/api/v2/",
        credential_url="https://jbxcloud.joesecurity.org/account (API key)",
        free_tier="Free. Searching existing reports costs no submission quota.",
        rate_limit="A handful of submissions per day on Basic.",
        notes=(
            "Every submission is published on joesandbox.com and is readable by anyone. That "
            "makes submitting a disclosure rather than a lookup, which is why this is capped "
            "at TLP:CLEAR and why submission is off by default."
        ),
    )
    # Submissions are published, so the observable must be one that may be
    # disclosed. Searching alone would be safe at a higher level, but the plugin
    # can submit, and the cap has to cover what it can do.
    max_tlp = Tlp.CLEAR
    free_tier = True

    def base_url(self) -> str:
        return CLOUD_API


@register
class JoeSandboxEnterpriseAnalyzer(BaseJoeSandbox):
    """Joe Sandbox Enterprise, on an appliance the operator owns."""

    name = "joesandbox_enterprise"
    label = "Joe Sandbox Enterprise"
    description = (
        "Behavioural verdicts from your own Joe Sandbox appliance. Submissions stay private."
    )
    options_schema: ClassVar[dict[str, Any]] = {
        "base_url": {
            "type": "string",
            "default": "",
            "label": "API base URL of your appliance, for example https://jbx.internal/api",
        },
        "submit_new_analysis": {
            "type": "boolean",
            "default": False,
            "label": "Submit a URL when nothing is indexed",
        },
        "accept_tac": {
            "type": "boolean",
            "default": True,
            "label": "Accept the terms of service on submission",
        },
        "systems": {
            "type": "string",
            "default": "",
            "label": "Analysis systems, comma-separated (empty lets the appliance choose)",
        },
        "internet_access": {
            "type": "boolean",
            "default": True,
            "label": "Allow the sample internet access during the run",
        },
        "hybrid_code_analysis": {
            "type": "boolean",
            "default": True,
            "label": "Enable hybrid code analysis",
        },
        "allow_private_target": {
            "type": "boolean",
            "default": True,
            "label": "Allow an appliance on the internal network",
        },
    }
    provider = ProviderInfo(
        name="Joe Sandbox Enterprise",
        url="https://www.joesecurity.org/joe-sandbox-enterprise",
        api_base_url="The /api path of your own appliance",
        credential_url="Your appliance: the account page of the user the key belongs to",
        free_tier="Licensed; there is no free tier for the on-premise edition.",
        rate_limit="Whatever your appliance is sized for.",
        notes=(
            "Submissions stay on your appliance, so this is allowed up to TLP:RED — unlike "
            "Cloud Basic, where every submission is published."
        ),
        self_hosted=True,
    )
    # Nothing leaves the operator's own infrastructure.
    max_tlp = Tlp.RED
    # An appliance is sized for the operator's own load, so waiting longer for a
    # report is reasonable where it is not on a shared free tier.
    poll_attempts = 20

    def base_url(self) -> str:
        configured = str(self.option("base_url", "") or "").strip().rstrip("/")
        if not configured:
            # Falling back to the public cloud would silently send an internal
            # observable to a published sandbox.
            raise ValueError(
                "The appliance URL is not configured; set it in Admin, Plugins & keys."
            )
        return configured

    def submission_fields(self) -> dict[str, str]:
        fields = {
            "internet-access": "1" if self.option("internet_access", True) else "0",
            "hybrid-code-analysis": "1" if self.option("hybrid_code_analysis", True) else "0",
        }
        systems = str(self.option("systems", "") or "").strip()
        if systems:
            fields["systems"] = systems
        return fields

    async def run(self, observable: Observable) -> PluginResult:
        try:
            self.base_url()
        except ValueError as exc:
            return self.failed(str(exc))
        return await super().run(observable)
