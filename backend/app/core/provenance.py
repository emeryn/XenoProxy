"""Which entry point the current request came in through.

A job submitted by the assistant or by an agent over MCP is created by the very
same API route as one submitted from the interface, by the very same account.
Nothing in the request distinguishes them, so the history cannot say where a
job came from unless the entry point says so itself.

A header would be the obvious carrier and is the wrong one: any authenticated
client can set a header, so the label would be a claim rather than a fact. A
context variable cannot be set from outside the process. The MCP bridge calls
the application in-process through an ASGI transport, inside the same task, so
what it sets here reaches the route handler and nothing else does.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from fastapi import Request

from app.models.job import JobOrigin

_origin: ContextVar[JobOrigin | None] = ContextVar("request_origin", default=None)


@contextmanager
def entering(origin: JobOrigin) -> Iterator[None]:
    """Mark everything done inside this block as coming from `origin`."""
    token = _origin.set(origin)
    try:
        yield
    finally:
        _origin.reset(token)


def current(default: JobOrigin) -> JobOrigin:
    """The marked origin, or `default` when the request was not marked."""
    return _origin.get() or default


def from_request(request: Request) -> JobOrigin:
    """How this request reached the API, as far as it can be known.

    A bearer token is a personal API token, which is what a script or an
    automation uses; the interface authenticates with its session cookie. The
    MCP bridge holds a token too, so it overrides this with its own mark.
    """
    authorization = request.headers.get("authorization", "")
    default = (
        JobOrigin.API if authorization.lower().startswith("bearer ") else JobOrigin.UI
    )
    return current(default)
