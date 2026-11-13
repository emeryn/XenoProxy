"""CIRCL.LU hashlookup: identify known-good files from software distributions."""

from __future__ import annotations

from typing import Any, ClassVar

from app.core import http_client
from app.models.job import ObservableType, Tlp, Verdict
from app.plugins.base.analyzer import BaseAnalyzer
from app.plugins.base.plugin import PluginResult, PluginSummary, ProviderInfo
from app.plugins.base.registry import register
from app.services.observables import Observable

_BASE = "https://hashlookup.circl.lu"


@register
class CirclHashLookupAnalyzer(BaseAnalyzer):
    """Tells whether a hash belongs to a known legitimate software distribution.

    A hit is strong evidence that the file is benign, which lets an analyst
    discard known-good binaries without spending a paid-API lookup on them.
    """

    name = "circl_hashlookup"
    label = "CIRCL hashlookup"
    description = (
        "Known-good file identification from public software distributions (NSRL and others)."
    )
    supported_types: ClassVar[tuple[ObservableType, ...]] = (ObservableType.HASH,)
    provider = ProviderInfo(
        name="CIRCL hashlookup",
        url="https://www.circl.lu/services/hashlookup/",
        api_base_url="https://hashlookup.circl.lu/lookup/{md5|sha1|sha256}/{hash}",
        free_tier="Free and unauthenticated.",
        rate_limit="Fair use; no published quota.",
        notes=(
            "Answers whether a hash is *known good* — a match means the file ships with a known "
            "product, not that it is malicious."
        ),
    )
    max_tlp = Tlp.AMBER
    documentation_url = "https://hashlookup.circl.lu/"
    free_tier = True
    default_timeout = 20
    default_cache_ttl = 604800

    async def run(self, observable: Observable) -> PluginResult:
        algorithm = observable.hash_algorithm or _guess_algorithm(observable.value)
        if algorithm not in {"md5", "sha1", "sha256"}:
            return self.skipped(f"CIRCL hashlookup does not index {algorithm or 'this'} hashes.")

        response = await http_client.get(
            f"{_BASE}/lookup/{algorithm}/{observable.value}", timeout=self.timeout
        )
        if response.status_code == 404:
            return self.ok(
                {"known": False},
                PluginSummary(
                    verdict=Verdict.UNKNOWN,
                    headline="Not a known distribution file; it needs further analysis.",
                ),
            )
        if not response.ok:
            return self.provider_http_error(response.status_code)

        raw: dict[str, Any] = response.json_body or {}
        trust = raw.get("hashlookup:trust")
        source = raw.get("source") or raw.get("KnownMalicious")
        malicious = bool(raw.get("KnownMalicious"))
        known_as = raw.get("FileName") or raw.get("hashlookup:parent-total") or source

        return self.ok(
            raw,
            PluginSummary(
                verdict=Verdict.MALICIOUS if malicious else Verdict.CLEAN,
                score=int(trust) if isinstance(trust, int) else None,
                tags=["known-good"] if not malicious else ["known-malicious"],
                headline=f"Known file: {known_as}",
                links=[
                    {
                        "label": "Open in hashlookup",
                        "url": f"{_BASE}/lookup/{algorithm}/{observable.value}",
                    }
                ],
                extra={
                    "file_name": raw.get("FileName"),
                    "file_size": raw.get("FileSize"),
                    "product_code": raw.get("ProductCode"),
                    "source": source,
                    "trust": trust,
                },
            ),
        )


def _guess_algorithm(value: str) -> str | None:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value))
