"""Analyzer contract, registry consistency and failure isolation."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.models.job import ObservableType, PluginKind, ReportStatus, Verdict
from app.plugins import load_all
from app.plugins.analyzer.abuseipdb import AbuseIpdbAnalyzer
from app.plugins.analyzer.shodan import ShodanAnalyzer
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult
from app.plugins.base.registry import describe, iter_analyzers
from app.services.observables import Observable, classify
from app.services.verdict import aggregate_status, aggregate_verdict


def test_every_analyzer_declares_its_contract() -> None:
    load_all()
    for cls in iter_analyzers():
        assert cls.name and cls.name.islower()
        assert cls.label
        assert cls.description
        assert cls.supported_types
        assert cls.default_timeout > 0
        declaration = describe(cls)
        assert declaration["plugin_type"] == PluginKind.ANALYZER.value


def test_registry_names_are_unique() -> None:
    names = [cls.name for cls in iter_analyzers()]
    assert len(names) == len(set(names))


def test_declared_options_have_defaults() -> None:
    for cls in iter_analyzers():
        for option, spec in (cls.options_schema or {}).items():
            assert isinstance(spec, dict), f"{cls.name}.{option}"
            assert "default" in spec, f"{cls.name}.{option} has no default"
            assert "label" in spec, f"{cls.name}.{option} has no label"


class _ExplodingAnalyzer(BaseAnalyzer):
    name = "exploding_test_analyzer"
    label = "Exploding"
    description = "Raises on purpose."
    supported_types = (ObservableType.IP,)

    async def run(self, observable: Observable) -> PluginResult:
        raise RuntimeError("the provider went away")


async def test_a_raising_analyzer_produces_a_failed_report_not_an_exception() -> None:
    result = await _ExplodingAnalyzer().execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.FAILED
    assert "the provider went away" in (result.error or "")
    assert result.execution_time_ms >= 0


async def test_missing_credential_fails_only_that_analyzer() -> None:
    result = await ShodanAnalyzer(secrets={}).execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.FAILED
    assert "api_key" in (result.error or "")


@respx.mock
async def test_shodan_normalises_its_summary() -> None:
    respx.get(url__startswith="https://api.shodan.io/shodan/host/8.8.8.8").mock(
        return_value=httpx.Response(
            200,
            json={
                "ports": [53, 443],
                "tags": ["cdn"],
                "vulns": ["CVE-2021-1234"],
                "country_name": "United States",
                "asn": "AS15169",
                "org": "Google LLC",
                "hostnames": ["dns.google"],
                "data": [{"port": 443, "product": "nginx"}],
            },
        )
    )
    result = await ShodanAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.SUCCESS
    summary = result.summary.as_dict()
    assert summary["open_ports"] == [53, 443]
    assert summary["cves"] == ["CVE-2021-1234"]
    assert summary["asn"] == "AS15169"
    assert summary["verdict"] == Verdict.SUSPICIOUS.value


@respx.mock
async def test_quota_error_is_reported_without_leaking_the_key() -> None:
    respx.get(url__startswith="https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(429, json={"errors": [{"detail": "quota"}]})
    )
    key = "secret-abuseipdb-key"
    result = await AbuseIpdbAnalyzer(secrets={"api_key": key}).execute(classify("8.8.8.8"))
    assert result.status is ReportStatus.FAILED
    assert key not in (result.error or "")
    assert "429" in (result.error or "")


@respx.mock
async def test_abuseipdb_flags_a_reported_address() -> None:
    respx.get(url__startswith="https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 100,
                    "totalReports": 42,
                    "countryName": "Nowhere",
                    "isp": "Example ISP",
                    "reports": [{"categories": [18, 22]}],
                }
            },
        )
    )
    result = await AbuseIpdbAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("8.8.8.8"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.MALICIOUS.value
    assert summary["score"] == 100
    assert "Brute-force" in summary["tags"]


class _Report:
    """Minimal stand-in for PluginReport in the aggregation tests."""

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
        self.spawned_job_ids: list[str] = []


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        (["clean", "clean"], Verdict.CLEAN),
        (["clean", "suspicious"], Verdict.SUSPICIOUS),
        (["clean", "malicious", "suspicious"], Verdict.MALICIOUS),
        (["unknown"], Verdict.UNKNOWN),
    ],
)
def test_the_worst_verdict_wins(verdicts: list[str], expected: Verdict) -> None:
    reports = [_Report(ReportStatus.SUCCESS, verdict) for verdict in verdicts]
    assert aggregate_verdict(reports) is expected  # type: ignore[arg-type]


def test_one_failure_degrades_the_job_but_does_not_fail_it() -> None:
    reports = [_Report(ReportStatus.SUCCESS), _Report(ReportStatus.FAILED)]
    assert aggregate_status(reports).value == "PARTIAL_FAILURE"  # type: ignore[arg-type]


def test_all_failures_fail_the_job() -> None:
    reports = [_Report(ReportStatus.FAILED), _Report(ReportStatus.FAILED)]
    assert aggregate_status(reports).value == "FAILED"  # type: ignore[arg-type]
