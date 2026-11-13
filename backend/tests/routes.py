"""Enumerate the application's routes, whatever FastAPI does internally.

Since FastAPI 0.16x, `include_router` keeps a wrapper object instead of copying
the routes into `app.routes`, so walking that list alone silently finds almost
nothing. This collector recurses through the wrappers and rebuilds the full
path; the tests assert a plausible route count so the enumeration can never
quietly go empty again.

A route's `path` already carries the prefix of the router it was declared on,
but not the prefixes of the routers that include it, which is what the walk
accumulates.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute


def _included_router(node: Any) -> tuple[Any, str] | None:
    """Return (router, extra prefix) when a node is an include wrapper."""
    router = getattr(node, "original_router", None) or getattr(node, "included_router", None)
    if router is None or not hasattr(router, "routes"):
        return None
    context = getattr(node, "include_context", None)
    return router, str(getattr(context, "prefix", "") or "")


def _walk(router: Any, carried: str, found: dict[tuple[str, str], APIRoute]) -> None:
    """Collect the routes of one router.

    `carried` is the absolute prefix that applies to this router's own routes.
    An include wrapper already stores the including router's prefix in its
    context, so that value is appended rather than recomputed.
    """
    for item in getattr(router, "routes", []):
        if isinstance(item, APIRoute):
            path = carried + item.path
            for method in item.methods - {"HEAD", "OPTIONS"}:
                found[(method, path)] = item
            continue

        included = _included_router(item)
        if included is not None:
            sub_router, context_prefix = included
            _walk(sub_router, carried + context_prefix, found)
        elif hasattr(item, "routes"):
            _walk(item, carried + str(getattr(item, "prefix", "") or ""), found)


def collect_routes(app: FastAPI) -> dict[tuple[str, str], APIRoute]:
    """Every served route, keyed by (method, full path)."""
    found: dict[tuple[str, str], APIRoute] = {}
    _walk(app, "", found)
    return found


def route_pairs(app: FastAPI) -> list[tuple[str, str, APIRoute]]:
    """(method, path, route) for every served route, sorted for stable output."""
    return sorted(
        ((method, path, route) for (method, path), route in collect_routes(app).items()),
        key=lambda entry: (entry[1], entry[0]),
    )


def declared_permission(route: APIRoute) -> str | None:
    """The permission a route declares through `require(...)`, if any."""
    for dependency in route.dependant.dependencies:
        permission = getattr(dependency.call, "__xenoproxy_permission__", None)
        if permission:
            return str(permission)
    return None
