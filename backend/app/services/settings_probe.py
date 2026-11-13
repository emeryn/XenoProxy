"""Connection tests, environment precedence and configuration transfer.

Three concerns that all sit between a settings section and the world outside,
and that the router would otherwise carry itself:

- **probing**: does the provider answer with these values, before they are
  saved? Finding out after committing a directory the whole instance
  authenticates against is the wrong order;
- **precedence**: a field pinned by an environment variable wins over the
  database and is shown read-only, so a headless deployment stays
  authoritative and nobody can widen it from a browser;
- **transfer**: exporting a configuration to replay on another instance, with
  the sealed fields deliberately left behind.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core import http_client
from app.core.config import get_settings
from app.core.errors import ValidationFailedError
from app.core.logging import get_logger
from app.services import app_settings, settings_store

logger = get_logger(__name__)

# Fields a deployment may pin, per section, mapped to the configuration
# attribute that carries them. A field counts as pinned only when the variable
# is actually present in the environment: a setting that merely has a default
# is still the administrator's to change.
ENVIRONMENT_PINS: dict[str, dict[str, str]] = {
    "network": {
        "http_proxy": "outbound_proxy_url",
        "https_proxy": "outbound_proxy_url",
    },
    "oidc": {
        "enabled": "oidc_enabled",
        "issuer": "oidc_issuer",
        "client_id": "oidc_client_id",
        "client_secret": "oidc_client_secret",
        "scopes": "oidc_scopes",
        "admin_group": "oidc_admin_group",
    },
}


def environment_overrides() -> dict[str, list[str]]:
    """Which fields of which sections the environment currently pins."""
    settings = get_settings()
    pinned: dict[str, list[str]] = {}
    for section, fields in ENVIRONMENT_PINS.items():
        held = [
            field
            for field, attribute in fields.items()
            if settings.managed_by_environment(attribute)
        ]
        if held:
            pinned[section] = sorted(held)
    return pinned


def assert_not_managed(section: str, submitted: dict[str, Any]) -> None:
    """Refuse a change to a field the environment pins.

    Hiding the input in the interface is a courtesy; this is the check that
    makes it true, because a form is not the only way to reach the endpoint.
    """
    pinned = set(environment_overrides().get(section, ()))
    conflicting = sorted(
        pinned & {key for key in submitted if not key.endswith(("_set", "_clear"))}
    )
    if conflicting:
        raise ValidationFailedError(
            f"These fields are pinned by the environment and cannot be changed here: "
            f"{', '.join(conflicting)}."
        )


def default_assistant_prompt() -> str:
    """The prompt shipped with the application, shown beside the editable one."""
    from app.services.assistant.prompts import default_prompt

    return default_prompt()


# --------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------


def _outcome(ok: bool, detail: str, started: float, **extra: Any) -> dict[str, Any]:
    return {
        "ok": ok,
        "detail": detail,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
        **extra,
    }


async def _probe_network(value: Any, target: str | None) -> dict[str, Any]:
    """Fetch a URL through the proposed route, without installing it."""
    url = (target or "https://www.google.com/generate_204").strip()
    started = time.perf_counter()

    # The address comes from a form, so it is validated before it is called:
    # a connection test must not become a way of reaching this host or a cloud
    # metadata service.
    try:
        http_client.validate_destination(url)
    except http_client.OutboundRequestError as exc:
        return _outcome(False, str(exc), started)

    route = http_client.build_route(value)

    try:
        result = await http_client.request_with_route("GET", url, route=route, timeout=20)
    except Exception as exc:
        return _outcome(False, f"{type(exc).__name__}: {exc}", started, route=route.describe())
    return _outcome(
        result.status_code < 400,
        f"HTTP {result.status_code}",
        started,
        status=result.status_code,
        route=route.describe(),
    )


async def _probe_assistant(value: Any, _target: str | None) -> dict[str, Any]:
    """Ask the inference server which models it serves."""
    from app.services.assistant.provider import build_provider

    started = time.perf_counter()
    if not value.base_url:
        return _outcome(False, "the address of the inference server is missing", started)

    provider = build_provider(value)
    try:
        models = await provider.list_models()
    except Exception as exc:
        return _outcome(False, f"{type(exc).__name__}: {exc}", started)

    detail = f"{len(models)} model(s) available"
    if value.model and value.model not in models:
        return _outcome(
            False,
            f"the server answered, but it does not serve '{value.model}'",
            started,
            models=models,
        )
    return _outcome(True, detail, started, models=models)


async def _probe_oidc(value: Any, _target: str | None) -> dict[str, Any]:
    """Fetch the discovery document and the signing keys."""
    started = time.perf_counter()
    if not value.issuer:
        return _outcome(False, "the issuer is missing", started)

    discovery = f"{value.issuer}/.well-known/openid-configuration"
    try:
        result = await http_client.get(discovery, timeout=15)
    except Exception as exc:
        return _outcome(False, f"{type(exc).__name__}: {exc}", started)
    if not result.ok or not isinstance(result.json_body, dict):
        return _outcome(
            False, f"the discovery document answered HTTP {result.status_code}", started
        )

    document = result.json_body
    jwks_uri = str(document.get("jwks_uri") or "")
    if not jwks_uri:
        return _outcome(False, "the discovery document declares no jwks_uri", started)

    try:
        keys = await http_client.get(jwks_uri, timeout=15)
    except Exception as exc:
        return _outcome(
            False, f"the keys could not be fetched: {type(exc).__name__}: {exc}", started
        )
    if not keys.ok:
        return _outcome(False, f"the keys answered HTTP {keys.status_code}", started)

    key_count = len((keys.json_body or {}).get("keys") or [])
    return _outcome(
        True,
        f"discovery and {key_count} signing key(s) fetched",
        started,
        authorization_endpoint=document.get("authorization_endpoint"),
        token_endpoint=document.get("token_endpoint"),
    )


async def _probe_ldap(value: Any, target: str | None, ca_bundle: str = "") -> dict[str, Any]:
    """Bind to the directory, and optionally look one account up."""
    from app.services.directory import test_connection

    started = time.perf_counter()
    if not value.server_url:
        return _outcome(False, "the server address is missing", started)
    try:
        detail, found = await test_connection(value, username=target or None, ca_bundle=ca_bundle)
    except Exception as exc:
        return _outcome(False, f"{type(exc).__name__}: {exc}", started)
    return _outcome(True, detail, started, found=found)


async def _probe_smtp(value: Any, target: str | None, ca_bundle: str = "") -> dict[str, Any]:
    """Send a test message, so the whole path is exercised rather than the socket."""
    from app.services.mailer import send_test

    started = time.perf_counter()
    if not value.host:
        return _outcome(False, "the server host is missing", started)
    if not target:
        return _outcome(False, "a recipient is required for this test", started)
    try:
        await send_test(value, target, ca_bundle=ca_bundle)
    except Exception as exc:
        return _outcome(False, f"{type(exc).__name__}: {exc}", started)
    return _outcome(True, f"a test message was accepted for {target}", started)


async def _probe_notifications(value: Any, _target: str | None) -> dict[str, Any]:
    """Post a sample payload to the configured webhook."""
    from app.plugins.webhook import post_signed

    started = time.perf_counter()
    if not (value.webhook_enabled and value.webhook_url):
        return _outcome(False, "no webhook is configured", started)
    try:
        result = await post_signed(
            value.webhook_url,
            {"event": "test", "source": "xenoproxy"},
            timeout=20,
            allow_private=True,
            signing_key=value.webhook_signing_key or None,
        )
    except Exception as exc:
        return _outcome(False, f"{type(exc).__name__}: {exc}", started)
    return _outcome(result.ok, f"HTTP {result.status_code}", started, status=result.status_code)


_PROBES = {
    "network": _probe_network,
    "assistant": _probe_assistant,
    "oidc": _probe_oidc,
    "ldap": _probe_ldap,
    "smtp": _probe_smtp,
    "notifications": _probe_notifications,
}


async def run(
    name: str, value: Any, *, target: str | None = None, ca_bundle: str = ""
) -> dict[str, Any]:
    """Probe one section, never raising: a failed test is a result, not an error.

    A subsystem that opens its own TLS connection — the directory, the mail
    server — is handed the authorities the Network section trusts, so an
    internal PKI is configured once for the whole application.
    """
    probe = _PROBES.get(name)
    if probe is None:
        raise ValidationFailedError(f"The section '{name}' has no connection test.")
    if name in {"ldap", "smtp"}:
        return await probe(value, target, ca_bundle)
    return await probe(value, target)


# --------------------------------------------------------------------------
# Configuration transfer
# --------------------------------------------------------------------------

EXPORT_VERSION = 1


async def export_configuration(session: AsyncSession) -> dict[str, Any]:
    """The instance configuration, without a single sealed value."""
    sections = {
        name: app_settings.public(name, value)
        for name, value in (await app_settings.load_all(session)).items()
    }
    # `public()` leaves the emptied secret and its `_set` flag; neither belongs
    # in a document meant to be applied somewhere else.
    for name, data in sections.items():
        for field in app_settings.SECRET_FIELDS.get(name, ()):
            data.pop(field, None)
            data.pop(f"{field}_set", None)

    return {
        "version": EXPORT_VERSION,
        "settings": await settings_store.load_all(session),
        "sections": sections,
    }


async def import_configuration(
    session: AsyncSession, document: dict[str, Any], *, actor: str
) -> dict[str, Any]:
    """Validate a whole document, then apply it.

    Everything is validated first. A document that is wrong anywhere changes
    nothing, so a bad file cannot leave the instance half configured.
    """
    if int(document.get("version", 0)) != EXPORT_VERSION:
        raise ValidationFailedError(
            f"This configuration is version {document.get('version')!r}; "
            f"version {EXPORT_VERSION} is expected."
        )

    raw_sections = document.get("sections") or {}
    if not isinstance(raw_sections, dict):
        raise ValidationFailedError("'sections' must be an object.")

    prepared: dict[str, Any] = {}
    for name, data in raw_sections.items():
        if name not in app_settings.SECTIONS:
            raise ValidationFailedError(f"Unknown settings section '{name}'.")
        if not isinstance(data, dict):
            raise ValidationFailedError(f"Section '{name}' must be an object.")
        # Sealed fields are absent from an export, so merging against what is
        # stored is what keeps this instance's own credentials in place.
        current = await app_settings.load(session, name)
        prepared[name] = app_settings.validate(
            name, app_settings.merge_secrets(name, data, current)
        )

    scalars = document.get("settings") or {}
    if not isinstance(scalars, dict):
        raise ValidationFailedError("'settings' must be an object.")
    # Anything the receiving instance pins by environment is skipped rather
    # than refused: a document from another deployment legitimately carries it.
    editable = {
        key: content
        for key, content in scalars.items()
        if key in settings_store.BY_KEY
        and not settings_store.is_managed(settings_store.BY_KEY[key])
    }

    for name, value in prepared.items():
        await app_settings.save(session, name, value, actor=actor)
    applied_scalars = await settings_store.update(session, editable, actor=actor)

    logger.info(
        "configuration_imported",
        sections=sorted(prepared),
        settings=len(applied_scalars),
        actor=actor,
    )
    return {"sections": sorted(prepared), "settings": sorted(applied_scalars)}
