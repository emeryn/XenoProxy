"""Structured JSON logging with request correlation and secret redaction."""

from __future__ import annotations

import logging
import re
import sys
from contextvars import ContextVar
from typing import Any

import structlog

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
actor_var: ContextVar[str] = ContextVar("actor", default="-")

_SENSITIVE_KEYS = re.compile(
    r"(password|secret|token|api_key|apikey|authorization|cookie|client_secret|private)",
    re.IGNORECASE,
)
_CONTROL_CHARS = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")
_CREDENTIAL_IN_URL = re.compile(
    r"(?i)\b(key|apikey|api_key|token|access_token|auth|password|secret|signature)"
    r"=[^&\s\"']+"
)
_CREDENTIAL_IN_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")


def _redact(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key, value in list(event_dict.items()):
        if _SENSITIVE_KEYS.search(key):
            event_dict[key] = "[redacted]"
        elif isinstance(value, str):
            event_dict[key] = _CONTROL_CHARS.sub(" ", value)[:2000]
    return event_dict


def _add_context(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    event_dict["request_id"] = request_id_var.get()
    event_dict["actor"] = actor_var.get()
    return event_dict


class _CredentialScrubber(logging.Filter):
    """Strip credentials that third-party libraries put in a logged URL.

    Several providers authenticate with a query parameter, and httpx logs the
    full request URL, so without this filter a key would reach the logs through
    a library we do not control.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        scrubbed = _CREDENTIAL_IN_URL.sub(r"\1=[redacted]", message)
        scrubbed = _CREDENTIAL_IN_USERINFO.sub(r"\1[redacted]@", scrubbed)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    scrubber = _CredentialScrubber()
    for handler in logging.getLogger().handlers:
        handler.addFilter(scrubber)
    # These libraries log full request URLs at INFO, which is noise at best and a
    # credential leak at worst; the scrubber above is the second line of defence.
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _add_context,
            _redact,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
