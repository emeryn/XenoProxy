"""Analyzer contract, registry consistency and failure isolation."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.models.job import ObservableType, PluginKind, ReportStatus, Verdict
from app.plugins import load_all
from app.plugins.analyzer.abuseipdb import AbuseIpdbAnalyzer
from app.plugins.analyzer.shodan import ShodanAnalyzer
from app.plugins.analyzer.virustotal import VirusTotalAnalyzer
from app.plugins.base import technologies
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


@respx.mock
async def test_abuseipdb_does_not_flag_an_address_the_provider_scores_at_zero() -> None:
    """Report count is not evidence: AbuseIPDB already weighed it into the score.

    Anyone may report any address, so well-known infrastructure accumulates
    reports the way a public inbox accumulates spam — 8.8.8.8 carries close to
    two hundred of them at a confidence of 0%. Counting them on top of the score
    made every such address Suspicious, and the job verdict with it.
    """
    respx.get(url__startswith="https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 0,
                    "totalReports": 192,
                    "isWhitelisted": True,
                    "countryName": "Nowhere",
                    "reports": [{"categories": [14]}],
                }
            },
        )
    )
    result = await AbuseIpdbAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("8.8.8.8"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.CLEAN.value
    assert summary["extra"]["total_reports"] == 192


@respx.mock
async def test_abuseipdb_flags_a_middling_score_as_suspicious() -> None:
    respx.get(url__startswith="https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 30, "totalReports": 3}}
        )
    )
    result = await AbuseIpdbAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("1.2.3.4"))
    assert result.summary.as_dict()["verdict"] == Verdict.SUSPICIOUS.value


@respx.mock
async def test_virustotal_ignores_a_single_outlying_engine() -> None:
    """One engine out of seventy is noise, not a finding.

    Promoting it to Suspicious promoted the whole job with it, which is how a
    verdict stops being read at all.
    """
    respx.get(url__startswith="https://www.virustotal.com/api/v3/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 0,
                            "harmless": 69,
                        },
                        "last_analysis_results": {
                            "SomeEngine": {
                                "category": "malicious",
                                "engine_name": "SomeEngine",
                                "result": "Trojan.Generic",
                            },
                            "Major": {"category": "harmless", "result": None},
                        },
                    }
                }
            },
        )
    )
    result = await VirusTotalAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("1.2.3.4"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.CLEAN.value
    # Never hidden, only stopped from shouting: the one engine is still named.
    assert summary["detection_ratio"] == "1/70"
    assert summary["detections"] == [
        {"engine": "SomeEngine", "category": "malicious", "result": "Trojan.Generic"}
    ]


@respx.mock
async def test_virustotal_flags_two_agreeing_engines_as_suspicious() -> None:
    respx.get(url__startswith="https://www.virustotal.com/api/v3/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 1,
                            "harmless": 68,
                        },
                        "last_analysis_results": {
                            "Beta": {"category": "suspicious", "result": "Heuristic"},
                            "Alpha": {"category": "malicious", "result": "Phishing"},
                        },
                    }
                }
            },
        )
    )
    result = await VirusTotalAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("1.2.3.4"))
    summary = result.summary.as_dict()
    assert summary["verdict"] == Verdict.SUSPICIOUS.value
    # Malicious first, so the strongest opinion is at the top of the list.
    assert [entry["engine"] for entry in summary["detections"]] == ["Alpha", "Beta"]


def test_cpe_strings_become_names_an_analyst_reads() -> None:
    # Vendor and product stutter, so only one of them is kept.
    assert technologies.from_cpe("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*") == "nginx 1.24.0"
    # Here the product alone ("http server") names nothing an analyst would
    # recognise, and the vendor is the whole of the answer.
    assert technologies.from_cpe("cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*") == (
        "apache http server 2.4.7"
    )
    # No version pinned: no trailing "*".
    assert technologies.from_cpe("cpe:2.3:a:redhat:jboss:*:*:*:*:*:*:*:*") == "redhat jboss"
    assert technologies.from_cpe("cpe:/a:openbsd:openssh:9.6") == "openbsd openssh 9.6"
    assert technologies.from_cpe("not a cpe") is None


def test_an_empty_or_unknown_product_is_not_a_technology() -> None:
    assert technologies.clean("", "1.0") is None
    assert technologies.clean("unknown") is None
    assert technologies.clean("nginx", "  ") == "nginx"


@respx.mock
async def test_shodan_reports_what_is_running_on_the_host() -> None:
    respx.get(url__startswith="https://api.shodan.io/shodan/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "ports": [80, 22],
                "os": "Ubuntu",
                "data": [
                    {"port": 80, "product": "nginx", "version": "1.24.0"},
                    {"port": 22, "product": "OpenSSH", "version": "9.6p1"},
                    {"port": 443},
                ],
            },
        )
    )
    result = await ShodanAnalyzer(secrets={"api_key": "x" * 16}).execute(classify("1.2.3.4"))
    assert result.summary.as_dict()["technologies"] == ["OpenSSH 9.6p1", "Ubuntu", "nginx 1.24.0"]
