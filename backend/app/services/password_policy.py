"""Password policy following NIST SP 800-63B: length over composition rules."""

from __future__ import annotations

from pathlib import Path

from app.core.errors import ValidationFailedError

MIN_LENGTH = 12
MAX_LENGTH = 128

_BREACHED_LIST = Path(__file__).with_name("breached_passwords.txt")
_cache: frozenset[str] | None = None


def _breached() -> frozenset[str]:
    """Load the bundled list of common and breached passwords."""
    global _cache
    if _cache is None:
        if _BREACHED_LIST.is_file():
            entries = {
                line.strip().lower()
                for line in _BREACHED_LIST.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            }
        else:
            entries = set()
        _cache = frozenset(entries)
    return _cache


def assert_acceptable(password: str, *, username: str | None = None) -> None:
    """Raise ValidationFailedError when a password must be refused."""
    if len(password) < MIN_LENGTH:
        raise ValidationFailedError(f"The password must be at least {MIN_LENGTH} characters long.")
    if len(password) > MAX_LENGTH:
        raise ValidationFailedError(f"The password must be at most {MAX_LENGTH} characters long.")
    lowered = password.lower()
    if lowered in _breached():
        raise ValidationFailedError(
            "This password appears in public breach and common-password lists."
        )
    if username and username.lower() in lowered:
        raise ValidationFailedError("The password must not contain the username.")
    if len(set(password)) < 5:
        raise ValidationFailedError("The password repeats too few distinct characters.")
