"""Security controls: SSRF guard, secret sealing, log redaction, password policy."""

from __future__ import annotations

import httpx
import pytest
import respx

from app.core import crypto, http_client
from app.core.errors import ValidationFailedError
from app.core.http_client import (
    OutboundRequestError,
    is_private_address,
    request,
    validate_destination,
)
from app.core.logging import _CredentialScrubber, _redact
from app.services.password_policy import assert_acceptable


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://localhost:8080/",
        "https://10.0.0.5/api",
        "https://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "https://[::1]/",
    ],
)
def test_ssrf_guard_refuses_non_routable_destinations(url: str) -> None:
    with pytest.raises(OutboundRequestError):
        validate_destination(url, allow_private=False)


@pytest.mark.parametrize("url", ["ftp://example.com/x", "file:///etc/passwd", "gopher://a/"])
def test_ssrf_guard_refuses_non_http_schemes(url: str) -> None:
    with pytest.raises(OutboundRequestError):
        validate_destination(url, allow_private=False)


def test_ssrf_guard_refuses_blocked_ports() -> None:
    with pytest.raises(OutboundRequestError):
        validate_destination("https://example.com:22/", allow_private=True)


def test_private_address_detection() -> None:
    assert is_private_address("10.0.0.1")
    assert is_private_address("::1")
    assert not is_private_address("8.8.8.8")
    assert not is_private_address("not-an-ip")


def test_secret_round_trip() -> None:
    sealed = crypto.seal("shodan-api-key-value")
    assert "shodan" not in sealed.ciphertext
    assert crypto.unseal(sealed) == "shodan-api-key-value"


def test_each_sealing_uses_a_fresh_data_key() -> None:
    first = crypto.seal("same-value")
    second = crypto.seal("same-value")
    assert first.ciphertext != second.ciphertext
    assert first.wrapped_key != second.wrapped_key


def test_blind_index_is_deterministic_and_case_insensitive() -> None:
    assert crypto.blind_index("Example.COM") == crypto.blind_index("example.com")
    assert crypto.blind_index("a") != crypto.blind_index("b")


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = crypto.hash_password("a-long-enough-passphrase")
    assert hashed.startswith("$argon2id$")
    assert crypto.verify_password(hashed, "a-long-enough-passphrase")
    assert not crypto.verify_password(hashed, "wrong-passphrase-entirely")


def test_logs_redact_credentials_and_strip_control_characters() -> None:
    event = _redact(
        None,
        "info",
        {
            "api_key": "super-secret",
            "authorization": "Bearer abc",
            "observable": "example.com\r\ninjected: 1",
        },
    )
    assert event["api_key"] == "[redacted]"
    assert event["authorization"] == "[redacted]"
    assert "\n" not in str(event["observable"])


@pytest.mark.parametrize("password", ["short", "password123", "aaaaaaaaaaaaaaa"])
def test_weak_passwords_are_refused(password: str) -> None:
    with pytest.raises(ValidationFailedError):
        assert_acceptable(password, username="analyst")


def test_password_cannot_contain_the_username() -> None:
    with pytest.raises(ValidationFailedError):
        assert_acceptable("analyst-strong-phrase", username="analyst")


def test_acceptable_password_passes() -> None:
    assert_acceptable("correct-horse-battery-7", username="analyst")


@pytest.fixture
def resolving(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve the test hostnames without touching the network."""

    def fake_resolve(host: str) -> list[str]:
        return ["127.0.0.1"] if host in {"localhost", "127.0.0.1"} else ["93.184.216.34"]

    monkeypatch.setattr(http_client, "_resolve", fake_resolve)


@respx.mock
async def test_a_redirect_to_a_private_address_is_refused(resolving: None) -> None:
    """A provider must not be able to walk a redirect onto the internal network."""
    respx.get("https://example.test/start").mock(
        return_value=httpx.Response(302, headers={"location": "http://127.0.0.1:9999/admin"})
    )
    with pytest.raises(OutboundRequestError):
        await request("GET", "https://example.test/start", max_redirects=2, allow_private=False)


@respx.mock
async def test_an_allowed_redirect_is_followed_and_revalidated(resolving: None) -> None:
    respx.get("https://example.test/start").mock(
        return_value=httpx.Response(302, headers={"location": "https://example.test/final"})
    )
    respx.get("https://example.test/final").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    result = await request("GET", "https://example.test/start", max_redirects=2)
    assert result.status_code == 200
    assert result.json_body == {"ok": True}


@respx.mock
async def test_a_redirect_is_refused_when_not_opted_in(resolving: None) -> None:
    respx.get("https://example.test/start").mock(
        return_value=httpx.Response(302, headers={"location": "https://example.test/final"})
    )
    with pytest.raises(OutboundRequestError):
        await request("GET", "https://example.test/start")


def test_a_credential_in_a_logged_url_is_scrubbed() -> None:
    """Providers that authenticate by query parameter must not leak through httpx logs."""
    import logging

    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=(
            "HTTP Request: GET "
            'https://api.shodan.io/shodan/host/8.8.8.8?key=super-secret-key "200 OK"'
        ),
        args=(),
        exc_info=None,
    )
    assert _CredentialScrubber().filter(record) is True
    assert "super-secret-key" not in record.getMessage()
    assert "key=[redacted]" in record.getMessage()


def test_credentials_in_a_url_userinfo_are_scrubbed() -> None:
    import logging

    record = logging.LogRecord(
        name="arq",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="connecting to redis://:hunter2hunter2@queue:6379/0",
        args=(),
        exc_info=None,
    )
    _CredentialScrubber().filter(record)
    assert "hunter2hunter2" not in record.getMessage()
