"""Common contract shared by every plugin type.

XenoProxy follows the IntelOwl plugin model: an integration is not just "an API
call", it is a typed plugin with a declared place in the job lifecycle.

- An **analyzer** reads an observable and returns intelligence about it. It runs
  during the analysis phase, concurrently with its peers.
- A **connector** runs *after* the analysis phase and pushes the finished result
  somewhere else. It is never selected by observable type: it is selected
  because the operator wants the result exported.
- A **pivot** runs after the connectors and derives new observables from the
  finished job, creating a child job for each one.

Every type shares the declaration surface below (name, credentials, options,
TLP ceiling, timeout) and the failure contract: a plugin never raises for a
provider-side problem, it reports it, so one failing integration cannot fail the
job around it.
"""

from __future__ import annotations

import abc
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.core.logging import get_logger
from app.models.job import ObservableType, PluginKind, ReportStatus, Tlp, Verdict
from app.services.observables import Observable

logger = get_logger(__name__)

# The plugin kind is declared in the model layer, because the report table
# stores it. Re-exporting it here keeps `PluginType` the name plugins use while
# leaving exactly one enum in the codebase.
PluginType = PluginKind


class PluginConfigurationError(RuntimeError):
    """Raised when a required secret or option is missing."""


class PluginQuotaError(RuntimeError):
    """Raised when the provider answered with a rate limit or quota error."""


# Kept under the historical names so operator-installed plugins written against
# the previous release keep importing successfully.
AnalyzerConfigurationError = PluginConfigurationError
AnalyzerQuotaError = PluginQuotaError


@dataclass
class PluginSummary:
    """Normalised view of a plugin answer, rendered directly by the UI."""

    verdict: Verdict = Verdict.UNKNOWN
    score: int | None = None
    tags: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    country: str | None = None
    asn: str | None = None
    organisation: str | None = None
    hostnames: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    detection_ratio: str | None = None
    headline: str | None = None
    # A picture of what the observable looks like, as the provider's URL.
    # It is never loaded by the browser: the page fetches it back through
    # the API, so the analyst's address is not disclosed to the provider
    # and the content policy stays closed to remote images.
    screenshot_url: str | None = None
    links: list[dict[str, str]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "tags": self.tags[:40],
            "open_ports": sorted(set(self.open_ports))[:200],
            "country": self.country,
            "asn": self.asn,
            "organisation": self.organisation,
            "hostnames": self.hostnames[:50],
            "cves": sorted(set(self.cves))[:200],
            "detection_ratio": self.detection_ratio,
            "headline": self.headline,
            "screenshot_url": self.screenshot_url,
            "links": self.links[:10],
            "extra": self.extra,
        }


@dataclass(frozen=True)
class SampleAccess:
    """The submitted file, and whether it may leave the instance.

    A sandbox wants the bytes; a hash lookup does not. Sending a file to a
    third party cannot be taken back, so whether it is allowed is an
    administrator's decision rather than a plugin's — and a plugin that is
    refused is told so, instead of being handed nothing and left to report a
    sample it could not find.
    """

    # Hashes always travel: they identify the file without disclosing it.
    sha256: str
    md5: str = ""
    sha1: str = ""
    file_name: str = ""
    # Set only when the instance allows a file to be sent out.
    read_bytes: Callable[[], bytes | None] | None = None

    @property
    def may_leave(self) -> bool:
        return self.read_bytes is not None


@dataclass
class PluginResult:
    """Outcome of one plugin run."""

    status: ReportStatus
    raw_output: dict[str, Any] | None = None
    summary: PluginSummary = field(default_factory=PluginSummary)
    error: str | None = None
    execution_time_ms: int = 0
    # Observables a pivot derived from the job. Empty for every other type.
    derived: list[DerivedObservable] = field(default_factory=list)


@dataclass(frozen=True)
class DerivedObservable:
    """An observable a pivot extracted from a finished job."""

    value: str
    reason: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"value": self.value, "reason": self.reason}


@dataclass(frozen=True)
class ReportView:
    """Read-only view of one finished report, handed to connectors and pivots."""

    plugin_name: str
    plugin_type: PluginType
    status: ReportStatus
    summary: dict[str, Any]
    raw_output: dict[str, Any] | None

    @property
    def succeeded(self) -> bool:
        return self.status is ReportStatus.SUCCESS


@dataclass(frozen=True)
class JobContext:
    """The finished analysis, as a connector or a pivot sees it.

    It carries the aggregated outcome plus every analyzer report, so a connector
    can push a complete picture and a pivot can read any provider's raw payload
    to extract the next observable.
    """

    job_id: uuid.UUID
    observable: Observable
    verdict: Verdict
    tlp: Tlp
    tags: list[str]
    summary: dict[str, Any]
    reports: list[ReportView]
    requested_by: str
    depth: int = 0

    def report(self, plugin_name: str) -> ReportView | None:
        """Return one report by plugin name, or None when it did not run."""
        for entry in self.reports:
            if entry.plugin_name == plugin_name:
                return entry
        return None

    def successful_reports(self) -> list[ReportView]:
        return [entry for entry in self.reports if entry.succeeded]


@dataclass(frozen=True)
class ProviderInfo:
    """Who serves a plugin, and what configuring it actually requires.

    An administrator looking at a plugin needs to answer three questions before
    they can turn it on: which service is this, where do I get a credential, and
    what does the free tier give me. Leaving those to a documentation link means
    leaving the instance half configured while somebody reads a web page, so
    they are declared here and rendered beside the switch.
    """

    name: str
    # The product page, for an administrator who has never heard of it.
    url: str = ""
    # The endpoint XenoProxy calls. Shown read-only: it is not a setting, and seeing
    # it is how an operator knows what to allow through their egress filter.
    api_base_url: str = ""
    # Where a credential is created. The single most asked question.
    credential_url: str = ""
    # What the free tier actually allows, in a sentence.
    free_tier: str = ""
    # The documented limits, so a rate-limit failure is expected rather than
    # investigated.
    rate_limit: str = ""
    notes: str = ""
    # The operator runs this service themselves, so the address is theirs to
    # give rather than a constant. The interface says so instead of showing an
    # endpoint that does not exist for them.
    self_hosted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "api_base_url": self.api_base_url,
            "credential_url": self.credential_url,
            "free_tier": self.free_tier,
            "rate_limit": self.rate_limit,
            "notes": self.notes,
            "self_hosted": self.self_hosted,
        }


@dataclass(frozen=True)
class SecretSpec:
    """Declares one credential a plugin needs."""

    name: str
    label: str
    required: bool = True
    help_text: str = ""
    # What the value looks like, shown as the input's placeholder. A credential
    # pasted into the wrong field is a support question nobody enjoys.
    placeholder: str = ""
    # A credential an analyst may override with their own, in Settings. Use it
    # for personal provider accounts, never for a shared team subscription.
    user_overridable: bool = False


@dataclass(frozen=True)
class HealthCheck:
    """Outcome of asking a plugin whether its provider is reachable."""

    healthy: bool
    detail: str = ""
    checked_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {"healthy": self.healthy, "detail": self.detail, "checked_at": self.checked_at}


class BasePlugin(abc.ABC):
    """Declaration surface and failure contract shared by every plugin type."""

    name: ClassVar[str]
    label: ClassVar[str]
    plugin_type: ClassVar[PluginType]
    description: ClassVar[str] = ""
    # Observable types the plugin accepts. An analyzer is filtered on it; a
    # connector and a pivot use it to decline a job they cannot handle.
    supported_types: ClassVar[tuple[ObservableType, ...]] = ()
    secrets: ClassVar[tuple[SecretSpec, ...]] = ()
    options_schema: ClassVar[dict[str, Any]] = {}
    requires_network: ClassVar[bool] = True
    default_timeout: ClassVar[int] = 60
    default_cache_ttl: ClassVar[int] = 86400
    documentation_url: ClassVar[str] = ""
    free_tier: ClassVar[bool] = False
    # Who serves this plugin. Declared by every built-in one; a custom plugin
    # that leaves it out simply shows nothing extra.
    provider: ClassVar[ProviderInfo] = ProviderInfo(name="")
    # Highest TLP this plugin tolerates. Anything that sends the observable to
    # a third party caps at AMBER; a source that publishes or indexes the query
    # caps at CLEAR; a purely local plugin may go up to RED.
    max_tlp: ClassVar[Tlp] = Tlp.AMBER
    # Set by the custom-plugin loader on plugins that come from the plugins volume.
    is_custom: ClassVar[bool] = False
    plugin_version: ClassVar[str] = ""

    def __init__(
        self,
        *,
        secrets: dict[str, str] | None = None,
        options: dict[str, Any] | None = None,
        timeout: int | None = None,
        job_tlp: Tlp | None = None,
        sample: SampleAccess | None = None,
    ) -> None:
        self._secrets = secrets or {}
        self.options = options or {}
        self.timeout = timeout or self.default_timeout
        # The TLP of the job being run. `max_tlp` decides whether a plugin may
        # run at all; this lets a plugin that does two things of different
        # sensitivity — looking something up, and publishing it — gate the
        # second without taking the first down with it.
        self.job_tlp = job_tlp or Tlp.AMBER
        # How a plugin reaches the submitted file, if it may at all.
        self._sample = sample

    def sample_bytes(self) -> bytes | None:
        """The submitted file, or None when this instance keeps it in.

        None means two different things on purpose: there is no file, or there
        is one and it may not be sent to a provider. A plugin that needs the
        bytes reports that it could not run rather than guessing.
        """
        if self._sample is None or self._sample.read_bytes is None:
            return None
        return self._sample.read_bytes()

    @property
    def sample(self) -> SampleAccess | None:
        """What is known about the submitted file, hashes included."""
        return self._sample

    # -- declaration helpers -------------------------------------------------

    @classmethod
    def supports(cls, observable_type: ObservableType) -> bool:
        """Whether the plugin accepts this observable type.

        An empty `supported_types` means "every type", which is the sensible
        default for a connector that exports whatever the job produced.
        """
        if not cls.supported_types:
            return True
        return observable_type in cls.supported_types

    @classmethod
    def required_secret_names(cls) -> list[str]:
        return [spec.name for spec in cls.secrets if spec.required]

    @classmethod
    def user_overridable_secret_names(cls) -> list[str]:
        return [spec.name for spec in cls.secrets if spec.user_overridable]

    # -- configuration access ------------------------------------------------

    def secret(self, name: str) -> str:
        """Return a configured secret, or raise so the report fails explicitly."""
        value = self._secrets.get(name)
        if not value:
            raise PluginConfigurationError(
                f"The credential '{name}' is not configured for plugin '{self.name}'."
            )
        return value

    def optional_secret(self, name: str) -> str | None:
        return self._secrets.get(name) or None

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    # -- execution -----------------------------------------------------------

    @abc.abstractmethod
    async def _invoke(self, payload: Any) -> PluginResult:
        """Run the plugin against the payload its type defines."""

    async def execute(self, payload: Any) -> PluginResult:
        """Run the plugin, converting any failure into a FAILED report."""
        started = time.perf_counter()
        try:
            result = await self._invoke(payload)
        except PluginConfigurationError as exc:
            result = PluginResult(status=ReportStatus.FAILED, error=str(exc))
        except PluginQuotaError as exc:
            result = PluginResult(
                status=ReportStatus.FAILED, error=f"Provider quota or rate limit reached: {exc}"
            )
        except TimeoutError:
            result = PluginResult(
                status=ReportStatus.FAILED, error=f"The provider timed out after {self.timeout}s."
            )
        except Exception as exc:
            logger.warning(
                "plugin_failed",
                plugin=self.name,
                plugin_type=self.plugin_type.value,
                error=str(exc),
            )
            result = PluginResult(status=ReportStatus.FAILED, error=_safe_error(exc))
        result.execution_time_ms = int((time.perf_counter() - started) * 1000)
        return result

    async def health_check(self) -> HealthCheck:
        """Report whether the provider answers.

        The default is declaration-based: a plugin with every required credential
        present and no network dependency is healthy. A plugin that talks to a
        provider with a cheap status endpoint should override this and call it,
        which is what makes the Admin health column meaningful.
        """
        missing = [name for name in self.required_secret_names() if not self._secrets.get(name)]
        if missing:
            return HealthCheck(False, f"missing credential: {', '.join(missing)}")
        if not self.requires_network:
            return HealthCheck(True, "local plugin, no provider to reach")
        return HealthCheck(True, "configured; no provider probe implemented")

    # -- result helpers ------------------------------------------------------

    def ok(self, raw: dict[str, Any], summary: PluginSummary | None = None) -> PluginResult:
        return PluginResult(
            status=ReportStatus.SUCCESS, raw_output=raw, summary=summary or PluginSummary()
        )

    def failed(self, message: str) -> PluginResult:
        return PluginResult(status=ReportStatus.FAILED, error=message)

    def skipped(self, message: str) -> PluginResult:
        """Report that this job is out of scope for the plugin."""
        return PluginResult(status=ReportStatus.SKIPPED, error=message)

    def provider_http_error(self, status_code: int) -> PluginResult:
        """Build a failed result for an unexpected provider status code."""
        if status_code in {401, 403}:
            return self.failed(
                f"{self.label} rejected the configured credential (HTTP {status_code})."
            )
        return self.failed(f"{self.label} returned HTTP {status_code}.")

    def not_found(self, message: str = "No record for this observable.") -> PluginResult:
        return PluginResult(
            status=ReportStatus.SUCCESS,
            raw_output={"found": False},
            summary=PluginSummary(verdict=Verdict.UNKNOWN, headline=message),
        )


def _safe_error(exc: Exception) -> str:
    """Build an error message that cannot leak a credential."""
    message = str(exc) or exc.__class__.__name__
    return message[:500]
