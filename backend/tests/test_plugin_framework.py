"""The typed plugin framework: registry rules, phase contracts, precedence."""

from __future__ import annotations

import uuid
from typing import ClassVar

import pytest

from app.models.job import JobStatus, ObservableType, PluginKind, ReportStatus, Tlp, Verdict
from app.plugins import load_all
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.connector import BaseConnector
from app.plugins.base.pivot import BasePivot
from app.plugins.base.plugin import (
    DerivedObservable,
    JobContext,
    PluginResult,
    PluginSummary,
    ReportView,
    SecretSpec,
)
from app.plugins.base.registry import describe, iter_plugins, register
from app.plugins.connector.n8n_webhook import N8nWebhookConnector
from app.plugins.pivot.domain_to_ip import DomainToIpPivot
from app.plugins.pivot.url_to_domain import UrlToDomainPivot
from app.services import plugin_runtime
from app.services.observables import Observable, classify
from app.services.verdict import aggregate_status, aggregate_verdict, build_summary

# --------------------------------------------------------------------------
# Registry rules
# --------------------------------------------------------------------------


def test_every_plugin_declares_a_type_and_a_matching_base() -> None:
    load_all()
    bases = {
        PluginKind.ANALYZER: BaseAnalyzer,
        PluginKind.CONNECTOR: BaseConnector,
        PluginKind.PIVOT: BasePivot,
    }
    for cls in iter_plugins():
        assert isinstance(cls.plugin_type, PluginKind), cls.__name__
        assert issubclass(cls, bases[cls.plugin_type]), cls.__name__
        assert describe(cls)["plugin_type"] == cls.plugin_type.value


def test_the_registry_refuses_an_analyzer_with_no_supported_types() -> None:
    class Nameless(BaseAnalyzer):
        name = "test_no_supported_types"
        label = "x"

        async def run(self, observable: Observable) -> PluginResult:  # pragma: no cover
            return self.ok({})

    with pytest.raises(ValueError, match="supported_types"):
        register(Nameless)


def test_the_registry_refuses_a_pivot_with_no_child_playbook() -> None:
    class Rootless(BasePivot):
        name = "test_no_child_playbook"
        label = "x"
        supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)

        async def run(self, context: JobContext) -> PluginResult:  # pragma: no cover
            return self.no_pivot()

    with pytest.raises(ValueError, match="child jobs run"):
        register(Rootless)


def test_the_registry_refuses_a_declared_type_that_contradicts_the_base() -> None:
    class Liar(BaseAnalyzer):
        name = "test_type_mismatch"
        label = "x"
        plugin_type = PluginKind.CONNECTOR
        supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)

        async def run(self, observable: Observable) -> PluginResult:  # pragma: no cover
            return self.ok({})

    with pytest.raises(ValueError, match="does not inherit"):
        register(Liar)


def test_connectors_are_not_selected_by_observable_type() -> None:
    """A connector with no declared types exports whatever the job produced."""
    assert N8nWebhookConnector.supported_types == ()
    for observable_type in ObservableType:
        assert N8nWebhookConnector.supports(observable_type)


# --------------------------------------------------------------------------
# Phase contracts
# --------------------------------------------------------------------------


def _context(
    value: str = "example.com",
    verdict: Verdict = Verdict.MALICIOUS,
    reports: list[ReportView] | None = None,
) -> JobContext:
    return JobContext(
        job_id=uuid.uuid4(),
        observable=classify(value),
        verdict=verdict,
        tlp=Tlp.AMBER,
        tags=["phishing"],
        summary={},
        reports=reports or [],
        requested_by="analyst",
    )


def test_a_connector_declines_a_verdict_below_its_floor() -> None:
    connector = N8nWebhookConnector(
        secrets={"webhook_url": "https://n8n.example.com/webhook/x"},
        options={"minimum_verdict": "malicious"},
    )
    assert connector.refusal_reason(_context(verdict=Verdict.MALICIOUS), JobStatus.SUCCESS) is None

    refusal = connector.refusal_reason(_context(verdict=Verdict.CLEAN), JobStatus.SUCCESS)
    assert refusal is not None
    assert "below the configured floor" in refusal


def test_a_typo_in_the_verdict_floor_does_not_silently_disable_the_connector() -> None:
    connector = N8nWebhookConnector(
        secrets={"webhook_url": "https://n8n.example.com/webhook/x"},
        options={"minimum_verdict": "maliciuos"},
    )
    refusal = connector.refusal_reason(_context(), JobStatus.SUCCESS)
    assert refusal is not None
    assert "is not a verdict" in refusal


def test_a_connector_declines_a_job_where_everything_failed() -> None:
    connector = N8nWebhookConnector(secrets={"webhook_url": "https://n8n.example.com/webhook/x"})
    refusal = connector.refusal_reason(_context(), JobStatus.FAILED)
    assert refusal is not None
    assert "nothing to export" in refusal


async def test_a_pivot_extracts_the_host_of_a_flagged_url() -> None:
    result = await UrlToDomainPivot().execute(_context("https://bad.example.com/login"))
    assert result.status is ReportStatus.SUCCESS
    assert [entry.value for entry in result.derived] == ["bad.example.com"]


async def test_a_pivot_declines_a_url_that_points_at_a_literal_address() -> None:
    result = await UrlToDomainPivot().execute(_context("http://203.0.113.9/payload"))
    assert result.status is ReportStatus.SUCCESS
    assert result.derived == []


def test_a_pivot_declines_a_clean_verdict() -> None:
    refusal = UrlToDomainPivot().refusal_reason(
        _context("https://ok.example.com/", verdict=Verdict.CLEAN)
    )
    assert refusal is not None
    assert "pivots only on" in refusal


async def test_a_pivot_reads_the_addresses_the_dns_analyzer_already_resolved() -> None:
    dns_report = ReportView(
        plugin_name="dns",
        plugin_type=PluginKind.ANALYZER,
        status=ReportStatus.SUCCESS,
        summary={"extra": {"records": {"A": ["203.0.113.5"], "AAAA": ["2001:db8::1"]}}},
        raw_output=None,
    )
    result = await DomainToIpPivot().execute(_context(reports=[dns_report]))
    assert [entry.value for entry in result.derived] == ["203.0.113.5", "2001:db8::1"]


def test_a_pivot_without_a_dns_report_declines_instead_of_resolving_itself() -> None:
    refusal = DomainToIpPivot().refusal_reason(_context())
    assert refusal is not None
    assert "did not run the DNS analyzer" in refusal


async def test_the_fan_out_guard_is_enforced_by_the_base_class() -> None:
    class Greedy(BasePivot):
        name = "test_greedy_pivot"
        label = "Greedy"
        supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.DOMAIN,)
        child_playbook = "Fast IP triage"
        max_children = 2

        async def run(self, context: JobContext) -> PluginResult:
            return PluginResult(
                status=ReportStatus.SUCCESS,
                summary=PluginSummary(),
                derived=[DerivedObservable(value=f"10.0.0.{i}") for i in range(10)],
            )

    result = await Greedy().execute(_context())
    assert len(result.derived) == 2


# --------------------------------------------------------------------------
# Configuration precedence
# --------------------------------------------------------------------------


class _Configurable(BaseAnalyzer):
    name = "test_configurable"
    label = "Configurable"
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.IP,)
    options_schema: ClassVar[dict[str, dict[str, object]]] = {
        "shared": {"type": "string", "default": "class", "label": "Administrator-only"},
        "personal": {
            "type": "string",
            "default": "class",
            "label": "Per analyst",
            "user_overridable": True,
        },
    }
    secrets: ClassVar[tuple[SecretSpec, ...]] = (
        SecretSpec("team_key", "Team key"),
        SecretSpec("own_key", "Your key", required=False, user_overridable=True),
    )

    async def run(self, observable: Observable) -> PluginResult:  # pragma: no cover
        return self.ok({})


def test_the_four_configuration_layers_apply_in_order() -> None:
    resolved = plugin_runtime.resolve_options(
        _Configurable,
        instance_options={"shared": "instance", "personal": "instance"},
        user_options={"personal": "user"},
        runtime_options={"personal": "runtime"},
    )
    assert resolved == {"shared": "instance", "personal": "runtime"}


def test_a_user_cannot_override_an_administrator_only_option() -> None:
    resolved = plugin_runtime.resolve_options(
        _Configurable,
        instance_options={"shared": "instance"},
        user_options={"shared": "user"},
    )
    assert resolved["shared"] == "instance"


def test_only_the_credentials_marked_personal_are_user_overridable() -> None:
    assert _Configurable.user_overridable_secret_names() == ["own_key"]
    assert plugin_runtime.user_overridable_options(_Configurable) == frozenset({"personal"})


def test_no_built_in_plugin_lets_a_user_redirect_it() -> None:
    """A per-user option must never be able to point a plugin somewhere else.

    An overridable `base_url`, `webhook_url` or `allow_private_target` would turn
    the personal configuration layer into a way around the instance's outbound
    policy, so the whole set is asserted here rather than left to review.
    """
    load_all()
    forbidden = {"base_url", "webhook_url", "allow_private_target", "lookup_path", "auth_header"}
    for cls in iter_plugins():
        personal = plugin_runtime.user_overridable_options(cls)
        assert not (personal & forbidden), f"{cls.name} exposes {personal & forbidden} per user"


# --------------------------------------------------------------------------
# Aggregation across phases
# --------------------------------------------------------------------------


class _Report:
    def __init__(
        self,
        status: ReportStatus,
        verdict: str = "unknown",
        plugin_type: PluginKind = PluginKind.ANALYZER,
    ) -> None:
        self.status = status
        self.summary_data = {"verdict": verdict}
        self.from_cache = False
        self.plugin_name = "test"
        self.plugin_type = plugin_type
        self.spawned_job_ids: list[uuid.UUID] = []


def test_only_analyzers_decide_the_verdict() -> None:
    reports = [
        _Report(ReportStatus.SUCCESS, "clean"),
        # A connector reporting success says the export worked, not that the
        # observable is malicious.
        _Report(ReportStatus.SUCCESS, "malicious", PluginKind.CONNECTOR),
    ]
    assert aggregate_verdict(reports) is Verdict.CLEAN  # type: ignore[arg-type]


def test_a_failed_export_degrades_the_job_without_touching_the_verdict() -> None:
    reports = [
        _Report(ReportStatus.SUCCESS, "clean"),
        _Report(ReportStatus.FAILED, plugin_type=PluginKind.CONNECTOR),
    ]
    assert aggregate_status(reports) is JobStatus.PARTIAL_FAILURE  # type: ignore[arg-type]
    assert aggregate_verdict(reports) is Verdict.CLEAN  # type: ignore[arg-type]


def test_a_job_whose_reports_were_all_killed_reports_as_killed() -> None:
    reports = [_Report(ReportStatus.KILLED), _Report(ReportStatus.KILLED)]
    assert aggregate_status(reports) is JobStatus.KILLED  # type: ignore[arg-type]


def test_a_partially_killed_job_keeps_what_finished() -> None:
    reports = [_Report(ReportStatus.SUCCESS, "suspicious"), _Report(ReportStatus.KILLED)]
    assert aggregate_status(reports) is JobStatus.PARTIAL_FAILURE  # type: ignore[arg-type]
    assert aggregate_verdict(reports) is Verdict.SUSPICIOUS  # type: ignore[arg-type]


def test_the_summary_counts_each_phase_separately() -> None:
    reports = [
        _Report(ReportStatus.SUCCESS, "clean"),
        _Report(ReportStatus.SUCCESS, plugin_type=PluginKind.CONNECTOR),
        _Report(ReportStatus.SKIPPED, plugin_type=PluginKind.PIVOT),
    ]
    summary = build_summary(reports)  # type: ignore[arg-type]
    assert summary["analyzers_succeeded"] == 1
    assert summary["connectors_succeeded"] == 1
    assert summary["pivots_skipped"] == 1
