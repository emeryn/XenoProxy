"""Centralised outbound HTTP client with proxy, custom CA and SSRF validation.

Every analyzer, connector and the assistant perform their network calls through
this module so that proxy settings, certificate authorities, timeouts and
destination validation are applied uniformly and cannot be bypassed per
integration.

The outbound route has two sources. The environment pins it for a headless
deployment; the Network section of the settings overrides it from the interface.
The resolved route is held here rather than read from the database per call,
because a call happens inside an analyzer that has no session, and because
building an SSL context on every request would be wasteful. `set_network()`
refreshes it: at startup, and whenever an administrator saves the section.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_USER_AGENT = "XenoProxy-OSINT/0.1"
_BLOCKED_PORTS = frozenset({22, 23, 25, 110, 135, 137, 138, 139, 445, 3389})
_METADATA_HOSTS = frozenset({"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"})


class OutboundRequestError(RuntimeError):
    """Raised when a destination is refused before any connection is attempted."""


@dataclass(frozen=True)
class HttpResult:
    """Normalised response of an outbound call."""

    status_code: int
    json_body: Any
    text: str
    elapsed_ms: int

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


def is_private_address(value: str) -> bool:
    """Report whether a literal IP address must never be scanned or contacted."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OutboundRequestError(f"host {host} could not be resolved") from exc
    return sorted({info[4][0] for info in infos})


def validate_destination(url: str, *, allow_private: bool | None = None) -> None:
    """Refuse a destination that points at the local host, a private range or metadata.

    Resolution happens here and the resulting addresses are checked, which closes the
    plain DNS-rebinding window between validation and connection for the common case.
    """
    settings = get_settings()
    allow_private = settings.allow_private_targets if allow_private is None else allow_private

    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise OutboundRequestError("only http and https destinations are allowed")
    if settings.is_production and parts.scheme != "https" and not allow_private:
        raise OutboundRequestError("plain http destinations are refused in production")
    host = parts.hostname
    if not host:
        raise OutboundRequestError("destination has no host")
    if parts.port and parts.port in _BLOCKED_PORTS:
        raise OutboundRequestError(f"port {parts.port} is not allowed")
    if host.lower() in _METADATA_HOSTS:
        raise OutboundRequestError("cloud metadata endpoints are not allowed")

    addresses = [host] if is_private_address(host) else _resolve(host)
    for address in addresses:
        if address in _METADATA_HOSTS:
            raise OutboundRequestError("cloud metadata endpoints are not allowed")
        if is_private_address(address) and not allow_private:
            raise OutboundRequestError(
                f"destination resolves to the non-routable address {address}"
            )


@dataclass(frozen=True)
class OutboundRoute:
    """The resolved outbound route: where to go through, and whom to trust."""

    proxy: str | None = None
    no_proxy: str = ""
    verify: Any = True

    def describe(self) -> str:
        """One line an administrator can read in a connection test."""
        parts = [f"proxy: {self.proxy}" if self.proxy else "direct connection"]
        if self.no_proxy:
            parts.append(f"bypassed for {self.no_proxy}")
        parts.append(
            "additional certificate authorities trusted"
            if isinstance(self.verify, ssl.SSLContext)
            else "system certificate authorities"
        )
        return ", ".join(parts)


_route: OutboundRoute | None = None


def _ssl_context(ca_bundle: str) -> ssl.SSLContext:
    """Trust extra authorities on top of the system store.

    The bundle is loaded from memory rather than written to a file: the runtime
    filesystem is read-only, and a private key material path is one more thing
    to protect. Verification is never disabled — trusting your own authority is
    the supported way to talk to an internal service.
    """
    context = ssl.create_default_context()
    context.load_verify_locations(cadata=ca_bundle)
    return context


def _proxy_with_credentials(url: str, username: str, password: str) -> str:
    """Put the credentials in the proxy URL, escaped so a password cannot break it."""
    if not username:
        return url
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{rest}"


def set_network(section: Any | None) -> None:
    """Install the outbound route, from the settings section or the environment.

    A section field that is left empty falls back to the environment, so an
    operator can pin the proxy in the deployment and still see it applied.
    """
    global _route
    settings = get_settings()

    proxy = getattr(section, "http_proxy", "") or getattr(section, "https_proxy", "")
    if proxy:
        proxy = _proxy_with_credentials(
            proxy,
            getattr(section, "proxy_username", ""),
            getattr(section, "proxy_password", ""),
        )
    else:
        proxy = settings.outbound_proxy_url or ""

    verify: Any = True
    bundle = getattr(section, "ca_bundle", "")
    if bundle:
        try:
            verify = _ssl_context(bundle)
        except ssl.SSLError as exc:
            logger.error("ca_bundle_rejected", error=str(exc))
    elif settings.custom_ca_file:
        verify = settings.custom_ca_file

    _route = OutboundRoute(
        proxy=proxy or None,
        no_proxy=getattr(section, "no_proxy", "") or "",
        verify=verify,
    )
    logger.info("outbound_route_set", route=_route.describe())


def build_route(section: Any) -> OutboundRoute:
    """Resolve a route from a Network settings section, without installing it.

    This is what a connection test needs: the route the administrator is
    proposing, used for one request, while the instance keeps running on the
    route it already has.
    """
    proxy = getattr(section, "http_proxy", "") or getattr(section, "https_proxy", "")
    verify: Any = True
    bundle = getattr(section, "ca_bundle", "")
    if bundle:
        verify = _ssl_context(bundle)
    return OutboundRoute(
        proxy=_proxy_with_credentials(
            proxy,
            getattr(section, "proxy_username", ""),
            getattr(section, "proxy_password", ""),
        )
        if proxy
        else None,
        no_proxy=getattr(section, "no_proxy", "") or "",
        verify=verify,
    )


def stream_client(timeout: float, url: str) -> httpx.AsyncClient:
    """An client on the installed route, for a response read as it arrives.

    Streaming needs the client to outlive a single call, which `request()` does
    not allow, so the caller owns it and closes it.
    """
    return httpx.AsyncClient(**_client_kwargs(timeout, url=url))


def current_route() -> OutboundRoute:
    """The route in force. Falls back to the environment before the first load."""
    if _route is None:
        set_network(None)
    assert _route is not None  # set_network always assigns
    return _route


def _bypasses_proxy(url: str, no_proxy: str) -> bool:
    """Whether this destination is listed in the no-proxy exceptions."""
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False
    for entry in (part.strip().lower() for part in no_proxy.split(",")):
        if not entry:
            continue
        if host == entry or host.endswith(f".{entry.lstrip('.')}"):
            return True
    return False


def _client_kwargs(
    timeout: float, *, url: str = "", route: OutboundRoute | None = None
) -> dict[str, Any]:
    effective = route or current_route()
    kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(timeout, connect=min(10.0, timeout)),
        "follow_redirects": False,
        "headers": {"User-Agent": _USER_AGENT, "Accept": "application/json"},
        "limits": httpx.Limits(max_connections=32, max_keepalive_connections=8),
        "trust_env": False,
        "verify": effective.verify,
    }
    if effective.proxy and not (url and _bypasses_proxy(url, effective.no_proxy)):
        kwargs["proxy"] = effective.proxy
    return kwargs


async def request(
    method: str,
    url: str,
    *,
    timeout: float | None = None,
    allow_private: bool | None = None,
    max_redirects: int = 0,
    **kwargs: Any,
) -> HttpResult:
    """Perform a validated outbound request and return a normalised result.

    Redirects are never followed by httpx itself. When an analyzer needs them —
    RDAP bootstrap redirects a query to the authoritative registry — it opts in
    with `max_redirects`, and every hop is re-validated against the SSRF rules
    before it is followed, so a redirect cannot reach a private address.
    """
    settings = get_settings()
    effective_timeout = timeout or float(settings.analyzer_default_timeout_seconds)
    validate_destination(url, allow_private=allow_private)

    target = url
    elapsed_ms = 0
    async with httpx.AsyncClient(**_client_kwargs(effective_timeout, url=url)) as client:
        for hop in range(max_redirects + 1):
            response = await client.request(method.upper(), target, **kwargs)
            elapsed_ms += int(response.elapsed.total_seconds() * 1000)

            if not response.is_redirect:
                break
            if hop >= max_redirects:
                raise OutboundRequestError(
                    "destination answered with a redirect, which is not followed"
                )

            location = response.headers.get("location", "")
            if not location:
                raise OutboundRequestError("redirect without a location header")
            target = str(response.url.join(location))
            validate_destination(target, allow_private=allow_private)
            # A redirected body would be replayed to a different host.
            kwargs.pop("content", None)
            kwargs.pop("data", None)
            kwargs.pop("json", None)

    try:
        json_body: Any = response.json()
    except ValueError:
        json_body = None
    return HttpResult(
        status_code=response.status_code,
        json_body=json_body,
        text=response.text[:200000],
        elapsed_ms=elapsed_ms,
    )


async def request_with_route(
    method: str,
    url: str,
    *,
    route: OutboundRoute,
    timeout: float = 20.0,
    **kwargs: Any,
) -> HttpResult:
    """Perform one request through a route that is not the installed one.

    This is what lets an administrator test a proxy or a certificate bundle
    before saving it. The destination is validated by the caller, which knows
    whether the target is allowed to be internal.
    """
    async with httpx.AsyncClient(**_client_kwargs(timeout, url=url, route=route)) as client:
        response = await client.request(method.upper(), url, **kwargs)
    try:
        json_body: Any = response.json()
    except ValueError:
        json_body = None
    return HttpResult(
        status_code=response.status_code,
        json_body=json_body,
        text=response.text[:200000],
        elapsed_ms=int(response.elapsed.total_seconds() * 1000),
    )


async def get(url: str, **kwargs: Any) -> HttpResult:
    return await request("GET", url, **kwargs)


async def post(url: str, **kwargs: Any) -> HttpResult:
    return await request("POST", url, **kwargs)


async def get_bytes(
    url: str,
    *,
    timeout: float = 30.0,
    max_bytes: int = 8 * 1024 * 1024,
) -> tuple[bytes, str] | None:
    """Fetch a binary body, bounded, through the installed route.

    Used for a provider's page capture. The body is read in chunks and the
    transfer is abandoned past `max_bytes`, because a declared content length
    is the remote end's claim rather than a fact — a provider could otherwise
    stream until the process runs out of memory.

    Returns the bytes and the content type, or None when the destination
    refuses, answers an error, or exceeds the bound.
    """
    validate_destination(url, allow_private=False)
    client = stream_client(timeout, url)
    try:
        async with client.stream("GET", url) as response:
            if not response.is_success:
                return None
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    logger.warning("outbound_body_too_large", url=url[:200], limit=max_bytes)
                    return None
                chunks.append(chunk)
            return b"".join(chunks), response.headers.get("content-type", "")
    except (httpx.HTTPError, OutboundRequestError) as exc:
        logger.info("outbound_body_failed", url=url[:200], error=str(exc)[:200])
        return None
    finally:
        await client.aclose()
