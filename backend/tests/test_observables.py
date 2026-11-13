"""Observable classification, defanging and private-target refusal."""

from __future__ import annotations

import pytest

from app.core.errors import ValidationFailedError
from app.models.job import ObservableType
from app.services.observables import classify, ensure_scannable, refang


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_value"),
    [
        ("8.8.8.8", ObservableType.IP, "8.8.8.8"),
        ("1.1.1[.]1", ObservableType.IP, "1.1.1.1"),
        ("2606:4700:4700::1111", ObservableType.IP, "2606:4700:4700::1111"),
        ("example[.]com", ObservableType.DOMAIN, "example.com"),
        ("EXAMPLE.COM.", ObservableType.DOMAIN, "example.com"),
        ("hxxps://evil[.]test/path", ObservableType.URL, "https://evil.test/path"),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            ObservableType.HASH,
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
        ("analyst[at]example[.]com", ObservableType.GENERIC, "analyst@example.com"),
        ("AS15169", ObservableType.GENERIC, "as15169"),
    ],
)
def test_classification(raw: str, expected_type: ObservableType, expected_value: str) -> None:
    observable = classify(raw)
    assert observable.type is expected_type
    assert observable.value == expected_value


def test_hash_algorithm_is_detected() -> None:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert classify(sha256).hash_algorithm == "sha256"
    assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709").hash_algorithm == "sha1"


def test_refang_leaves_clean_input_untouched() -> None:
    assert refang("https://example.com/a") == "https://example.com/a"


def test_empty_input_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        classify("   ")


def test_control_characters_are_refused() -> None:
    with pytest.raises(ValidationFailedError):
        classify("example.com\r\nHost: evil.test")


def test_oversized_input_is_refused() -> None:
    with pytest.raises(ValidationFailedError):
        classify("a" * 3000)


@pytest.mark.parametrize("value", ["127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254"])
def test_private_targets_are_refused_by_default(value: str) -> None:
    observable = classify(value)
    assert observable.is_private is True
    with pytest.raises(ValidationFailedError):
        ensure_scannable(observable, allow_private=False)


def test_private_targets_can_be_allowed_explicitly() -> None:
    ensure_scannable(classify("10.0.0.1"), allow_private=True)
