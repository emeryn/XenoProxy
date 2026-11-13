"""Observable normalisation, defanging and classification.

User input is never trusted: it is refanged, normalised, classified and checked
against the non-routable ranges before any analyzer is allowed to run on it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.errors import ValidationFailedError
from app.core.http_client import is_private_address
from app.models.job import ObservableType

MAX_OBSERVABLE_LENGTH = 2048

_DEFANG_SCHEMES = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hXXps://", "https://"),
    ("hXXp://", "http://"),
    ("fxp://", "ftp://"),
)
_DEFANG_SEPARATORS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("[@]", "@"),
)

# Zero-width and non-breaking characters are stripped before classification so a
# value pasted from a report or an email client classifies like a typed one.
_INVISIBLE = {
    0x200B: None,
    0x200C: None,
    0x200D: None,
    0xFEFF: None,
    0x00A0: 0x20,
}

_HASH_PATTERNS = {
    32: ("md5", re.compile(r"^[a-f0-9]{32}$")),
    40: ("sha1", re.compile(r"^[a-f0-9]{40}$")),
    64: ("sha256", re.compile(r"^[a-f0-9]{64}$")),
    128: ("sha512", re.compile(r"^[a-f0-9]{128}$")),
}
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@(?=.{1,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_ASN_RE = re.compile(r"^as\d{1,10}$")


@dataclass(frozen=True)
class Observable:
    """A validated observable ready to be dispatched to analyzers."""

    value: str
    type: ObservableType
    hash_algorithm: str | None = None
    is_private: bool = False

    def as_dict(self) -> dict[str, str | bool | None]:
        return {
            "value": self.value,
            "type": self.type.value,
            "hash_algorithm": self.hash_algorithm,
            "is_private": self.is_private,
        }


def refang(raw: str) -> str:
    """Undo common defanging so that `1.1.1[.]1` and `hxxps://x` become usable."""
    value = raw.strip().translate(_INVISIBLE).strip()
    for needle, replacement in _DEFANG_SCHEMES:
        value = value.replace(needle, replacement)
    for needle, replacement in _DEFANG_SEPARATORS:
        value = value.replace(needle, replacement)
        value = value.replace(needle.upper(), replacement)
    return value.strip().strip(".,;")


def _classify_ip(value: str) -> Observable | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return Observable(
        value=str(address), type=ObservableType.IP, is_private=is_private_address(str(address))
    )


def _classify_hash(value: str) -> Observable | None:
    lowered = value.lower()
    entry = _HASH_PATTERNS.get(len(lowered))
    if entry and entry[1].match(lowered):
        return Observable(value=lowered, type=ObservableType.HASH, hash_algorithm=entry[0])
    return None


def _classify_url(value: str) -> Observable | None:
    if "://" not in value:
        return None
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https", "ftp"} or not parts.hostname:
        return None
    host = parts.hostname
    private = is_private_address(host)
    if not private and not _DOMAIN_RE.match(host) and _classify_ip(host) is None:
        return None
    return Observable(value=value, type=ObservableType.URL, is_private=private)


def _classify_domain(value: str) -> Observable | None:
    candidate = value.lower().rstrip(".")
    if _DOMAIN_RE.match(candidate):
        return Observable(value=candidate, type=ObservableType.DOMAIN)
    return None


def classify(raw: str) -> Observable:
    """Classify a raw user input into a typed observable.

    Raises ValidationFailedError when the input is empty, oversized or unusable.
    """
    if raw is None:
        raise ValidationFailedError("An observable is required.")
    value = refang(raw)
    if not value:
        raise ValidationFailedError("An observable is required.")
    if len(value) > MAX_OBSERVABLE_LENGTH:
        raise ValidationFailedError(
            f"The observable exceeds the maximum length of {MAX_OBSERVABLE_LENGTH} characters."
        )
    if any(ord(char) < 32 for char in value):
        raise ValidationFailedError("The observable contains control characters.")

    for classifier in (_classify_ip, _classify_hash, _classify_url, _classify_domain):
        observable = classifier(value)
        if observable is not None:
            return observable

    lowered = value.lower()
    if _EMAIL_RE.match(lowered) or _ASN_RE.match(lowered):
        return Observable(value=lowered, type=ObservableType.GENERIC)
    if len(value) <= 256 and " " not in value:
        return Observable(value=value, type=ObservableType.GENERIC)
    raise ValidationFailedError("The observable type could not be determined.")


def ensure_scannable(observable: Observable, *, allow_private: bool) -> None:
    """Refuse non-routable targets unless the deployment explicitly allows them."""
    if observable.is_private and not allow_private:
        raise ValidationFailedError(
            "Scanning loopback, link-local or RFC1918 targets is disabled on this instance."
        )


def hostname_of(observable: Observable) -> str:
    """Return the hostname an analyzer should query for this observable."""
    if observable.type is ObservableType.URL:
        return urlsplit(observable.value).hostname or observable.value
    return observable.value
