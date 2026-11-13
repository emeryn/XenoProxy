"""Authentication against an LDAP directory.

The directory is reached over LDAPS, or over LDAP upgraded with StartTLS.
Certificate verification is always on, and the authorities are the ones the
Network section trusts, so an internal PKI is configured in one place for the
whole application rather than once per subsystem.

Every value substituted into a filter is escaped first. A user name is
attacker-controlled input, and an unescaped one rewrites the filter it appears
in — which is how an LDAP injection turns a login form into a directory dump.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

# RFC 4515: the characters that end a filter assertion or start an escape.
_FILTER_ESCAPES = {
    "\\": r"\5c",
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\0": r"\00",
    "/": r"\2f",
}


class DirectoryError(RuntimeError):
    """The directory refused, failed or answered something unusable."""


def escape_filter(value: str) -> str:
    """Make a value safe to substitute into a search filter."""
    return "".join(_FILTER_ESCAPES.get(char, char) for char in value)


def escape_dn(value: str) -> str:
    """Make a value safe to substitute into a distinguished name."""
    escaped = value.replace("\\", "\\\\")
    for char in (",", "+", '"', "<", ">", ";", "="):
        escaped = escaped.replace(char, f"\\{char}")
    return escaped


def _tls_context(ca_bundle: str) -> ssl.SSLContext:
    """The TLS settings for the directory connection.

    There is no switch to disable verification. An internal certificate
    authority is the supported way to reach a directory with a private PKI, and
    a directory bind sends a password: an unverified peer is the one case where
    that password goes to whoever answered.
    """
    context = ssl.create_default_context()
    if ca_bundle:
        context.load_verify_locations(cadata=ca_bundle)
    return context


def _connect(settings: Any, ca_bundle: str) -> Any:
    """Open the connection. Synchronous, so callers run it in a thread."""
    try:
        import ldap3
        from ldap3.core.tls import Tls
    except ImportError as exc:  # pragma: no cover - the dependency is declared
        raise DirectoryError("LDAP support is not installed in this image") from exc

    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ssl_context=_tls_context(ca_bundle),
    )
    server = ldap3.Server(
        settings.server_url,
        use_ssl=settings.server_url.lower().startswith("ldaps://"),
        get_info=ldap3.NONE,
        connect_timeout=settings.timeout,
        tls=tls,
    )
    connection = ldap3.Connection(
        server,
        user=settings.bind_dn or None,
        password=settings.bind_password or None,
        auto_bind=False,
        receive_timeout=settings.timeout,
        raise_exceptions=False,
    )
    if settings.start_tls and not server.ssl and not connection.start_tls():
        raise DirectoryError(f"StartTLS was refused: {connection.last_error}")
    if not connection.bind():
        raise DirectoryError(f"the bind was refused: {connection.last_error}")
    return connection


def _search_user(connection: Any, settings: Any, username: str) -> dict[str, Any] | None:
    """Find one account, returning its DN and the attributes that matter."""
    search_filter = settings.user_filter.replace("{username}", escape_filter(username))
    attributes = [
        attribute
        for attribute in (
            settings.username_attr,
            settings.display_name_attr,
            settings.email_attr,
            "memberOf" if settings.group_mode == "memberof" else None,
        )
        if attribute
    ]
    connection.search(
        search_base=settings.user_base_dn,
        search_filter=search_filter,
        attributes=attributes,
        size_limit=2,
    )
    entries = list(connection.entries)
    if not entries:
        return None
    if len(entries) > 1:
        # An ambiguous filter must not be resolved by picking one: whichever is
        # picked, somebody authenticates as an account that is not theirs.
        raise DirectoryError("the filter matched more than one account")

    entry = entries[0]
    raw = entry.entry_attributes_as_dict
    return {
        "dn": entry.entry_dn,
        "username": _first(raw.get(settings.username_attr)) or username,
        "display_name": _first(raw.get(settings.display_name_attr)),
        "email": _first(raw.get(settings.email_attr)),
        "member_of": [str(value) for value in (raw.get("memberOf") or [])],
    }


def _groups_of(connection: Any, settings: Any, user: dict[str, Any]) -> list[str]:
    """The group names of an account, however the directory models membership."""
    if settings.group_mode == "none":
        return []
    if settings.group_mode == "memberof":
        return [_rdn_value(entry) for entry in user["member_of"]]

    search_filter = settings.group_filter.replace("{user_dn}", escape_filter(user["dn"]))
    connection.search(
        search_base=settings.group_base_dn or settings.user_base_dn,
        search_filter=search_filter,
        attributes=[settings.group_name_attr],
        size_limit=200,
    )
    names: list[str] = []
    for entry in connection.entries:
        value = _first(entry.entry_attributes_as_dict.get(settings.group_name_attr))
        if value:
            names.append(value)
    return names


def _first(values: Any) -> str:
    if isinstance(values, list):
        return str(values[0]) if values else ""
    return str(values or "")


def _rdn_value(dn: str) -> str:
    """`cn=analysts,ou=groups,dc=example,dc=com` reads as `analysts`."""
    head = dn.split(",", 1)[0]
    return head.split("=", 1)[1] if "=" in head else head


def _authenticate(settings: Any, ca_bundle: str, username: str, password: str) -> dict[str, Any]:
    """Bind as the service account, find the user, then bind as the user."""
    import ldap3

    connection = _connect(settings, ca_bundle)
    try:
        user = _search_user(connection, settings, username)
        if user is None:
            raise DirectoryError("unknown account")
        groups = _groups_of(connection, settings, user)
    finally:
        connection.unbind()

    # The password is checked by binding with it; the directory is the only
    # thing that may decide whether it is right.
    server = ldap3.Server(
        settings.server_url,
        use_ssl=settings.server_url.lower().startswith("ldaps://"),
        get_info=ldap3.NONE,
        connect_timeout=settings.timeout,
    )
    as_user = ldap3.Connection(
        server, user=user["dn"], password=password, auto_bind=False, raise_exceptions=False
    )
    if settings.start_tls and not server.ssl:
        as_user.start_tls()
    if not as_user.bind():
        raise DirectoryError("invalid credentials")
    as_user.unbind()

    user["groups"] = groups
    user["is_admin"] = bool(settings.admin_group) and settings.admin_group in groups
    return user


async def authenticate(
    settings: Any, ca_bundle: str, username: str, password: str
) -> dict[str, Any]:
    """Authenticate one account. ldap3 is synchronous, so it runs in a thread."""
    if not password:
        # An empty password is an unauthenticated bind, which most directories
        # accept and which would let anybody in as anybody.
        raise DirectoryError("invalid credentials")
    return await asyncio.to_thread(_authenticate, settings, ca_bundle, username, password)


def _test(settings: Any, ca_bundle: str, username: str | None) -> tuple[str, dict[str, Any] | None]:
    connection = _connect(settings, ca_bundle)
    try:
        if not username:
            return "the bind succeeded", None
        user = _search_user(connection, settings, username)
        if user is None:
            return f"the bind succeeded, but '{username}' was not found", None
        user["groups"] = _groups_of(connection, settings, user)
        return (
            f"'{username}' found, in {len(user['groups'])} group(s)",
            {
                "dn": user["dn"],
                "display_name": user["display_name"],
                "email": user["email"],
                "groups": user["groups"][:50],
            },
        )
    finally:
        connection.unbind()


async def test_connection(
    settings: Any, *, username: str | None = None, ca_bundle: str = ""
) -> tuple[str, dict[str, Any] | None]:
    """Bind, and optionally look one account up, without authenticating it."""
    return await asyncio.to_thread(_test, settings, ca_bundle, username)
