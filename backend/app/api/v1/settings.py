"""Instance settings: the scalar declarations, and the structured sections.

Two shapes live under this router because the configuration has two shapes. The
scalar switches are declared one by one with their bounds and changed
individually; a section is a subsystem saved as a whole, because its fields only
make sense together.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import Field

from app.api.deps import DbSession, client_ip, require
from app.core import http_client
from app.core.errors import ValidationFailedError
from app.models.job import ScanMode, Tlp
from app.models.plugin_config import LlmProfile
from app.models.user import User
from app.schemas.common import MessageResponse, StrictModel
from app.services import app_settings, audit, settings_probe, settings_store
from app.services import tlp as tlp_policy
from app.services.assistant import profiles
from app.services.assistant.provider import ProviderError, build_provider

router = APIRouter(prefix="/admin/settings", tags=["admin"])

SettingsAdmin = Annotated[User, Depends(require("settings:manage"))]


class SettingsUpdate(StrictModel):
    """A batch of scalar setting changes, validated against their declarations."""

    values: dict[str, Any]


class SectionUpdate(StrictModel):
    """One section, as the form submits it.

    A sealed field left empty keeps what is stored, and `<field>_clear: true`
    removes it, so the browser never has to hold a secret to save the rest of
    the form.
    """

    values: dict[str, Any]


class SectionProbe(StrictModel):
    """A connection test, optionally against values that are not saved yet."""

    values: dict[str, Any] | None = None
    # Where the probe should go, for the sections that need a target: a URL to
    # fetch through the proxy, a recipient for a test mail.
    target: str | None = None


@router.get("", response_model=dict, summary="Read the instance settings")
async def read_settings(session: DbSession, _user: SettingsAdmin) -> dict[str, Any]:
    sections = {
        name: app_settings.public(name, value)
        for name, value in (await app_settings.load_all(session)).items()
    }
    return {
        "settings": await settings_store.describe(session),
        "scalar_sections": ["security", "scanning", "retention"],
        "sections": sections,
        "section_schemas": {
            name: app_settings.model_for(name).model_json_schema()
            for name in app_settings.section_names()
        },
        # What the environment pins for the sections that can also be set there,
        # so the interface can show those fields read-only.
        "managed_by_environment": settings_probe.environment_overrides(),
        "outbound_route": http_client.current_route().describe(),
        "assistant_default_prompt": settings_probe.default_assistant_prompt(),
        "tlp_levels": [
            {"value": level.value, "description": tlp_policy.describe(level)} for level in Tlp
        ],
        "scan_modes": [
            {
                "value": ScanMode.REUSE_RECENT.value,
                "description": (
                    "Serve an identical recent lookup from the cache, sparing the quota."
                ),
            },
            {
                "value": ScanMode.FORCE_NEW.value,
                "description": "Always query the provider, whatever is cached.",
            },
        ],
    }


@router.patch("", response_model=dict, summary="Change instance settings")
async def update_settings(
    payload: SettingsUpdate, request: Request, session: DbSession, user: SettingsAdmin
) -> dict[str, Any]:
    applied = await settings_store.update(session, payload.values, actor=user.username)
    await audit.record(
        session,
        action="settings.update",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
        details={"keys": sorted(applied)},
    )
    return {"settings": await settings_store.describe(session), "applied": sorted(applied)}


@router.put("/sections/{name}", response_model=dict, summary="Save a settings section")
async def save_section(
    name: str,
    payload: SectionUpdate,
    request: Request,
    session: DbSession,
    user: SettingsAdmin,
) -> dict[str, Any]:
    """Validate and store one section, then apply it where it takes effect now."""
    current = await app_settings.load(session, name)
    merged = app_settings.merge_secrets(name, payload.values, current)
    value = app_settings.validate(name, merged)

    settings_probe.assert_not_managed(name, payload.values)
    await app_settings.save(session, name, value, actor=user.username)

    # A saved route or a saved assistant has to take effect without a restart.
    if name == "network":
        http_client.set_network(value)

    await audit.record(
        session,
        action=f"settings.{name}",
        actor=user.username,
        actor_id=user.id,
        target=f"section:{name}",
        ip_address=client_ip(request),
        details=app_settings.audit_safe(name, value),
    )
    await session.commit()
    return app_settings.public(name, value)


@router.post("/sections/{name}/test", response_model=dict, summary="Test a settings section")
async def test_section(
    name: str,
    payload: SectionProbe,
    request: Request,
    session: DbSession,
    user: SettingsAdmin,
) -> dict[str, Any]:
    """Try the section against its provider, without saving it.

    Testing unsaved values is the point: an administrator finds out whether the
    directory answers before committing a configuration the whole instance
    authenticates against.
    """
    current = await app_settings.load(session, name)
    if payload.values:
        value = app_settings.validate(
            name, app_settings.merge_secrets(name, payload.values, current)
        )
    else:
        value = current

    network = await app_settings.load(session, "network")
    result = await settings_probe.run(
        name, value, target=payload.target, ca_bundle=network.ca_bundle
    )
    await audit.record(
        session,
        action=f"settings.{name}_test",
        actor=user.username,
        actor_id=user.id,
        target=f"section:{name}",
        ip_address=client_ip(request),
        details={"ok": result.get("ok"), "detail": result.get("detail")},
    )
    await session.commit()
    return result


@router.get("/export", response_model=dict, summary="Export the instance configuration")
async def export_configuration(
    request: Request, session: DbSession, user: SettingsAdmin
) -> dict[str, Any]:
    """Every setting and section, with the sealed fields left out.

    The export carries no secret: moving an API key between instances through a
    browser download is exactly how a key ends up in a ticket. The receiving
    instance keeps whatever it already had for those fields, and the rest is
    applied.
    """
    payload = await settings_probe.export_configuration(session)
    await audit.record(
        session,
        action="settings.export",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
        details={"sections": sorted(payload["sections"]), "settings": len(payload["settings"])},
    )
    await session.commit()
    return payload


@router.post("/import", response_model=dict, summary="Import an instance configuration")
async def import_configuration(
    payload: SectionUpdate,
    request: Request,
    session: DbSession,
    user: SettingsAdmin,
) -> dict[str, Any]:
    """Apply an exported configuration, section by section.

    Nothing is applied unless every part of it validates, so a bad file cannot
    leave the instance half configured.
    """
    document = payload.values
    if not isinstance(document, dict):
        raise ValidationFailedError("A configuration document is expected.")

    applied = await settings_probe.import_configuration(session, document, actor=user.username)
    if "network" in applied["sections"]:
        http_client.set_network(await app_settings.load(session, "network"))

    await audit.record(
        session,
        action="settings.import",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
        details=applied,
    )
    await session.commit()
    return applied


# --- Assistant profiles ------------------------------------------------------
#
# Saved connections to an inference server, separate from the assistant policy.
# The routes live under the settings router because that is where an operator
# configures them, and they take the same permission.


class ProfileWrite(StrictModel):
    """A profile as the form submits it.

    `api_key` left empty keeps the stored one, so the interface can save a
    profile it never held the secret of. `headers` left out keeps the stored
    ones; sending an object replaces them wholesale.
    """

    name: str = Field(min_length=1, max_length=128)
    provider: Literal["ollama", "openai"] = "ollama"
    base_url: str = Field("", max_length=1024)
    model: str = Field("", max_length=256)
    timeout: int = Field(120, ge=5, le=900)
    temperature: float = Field(0.2, ge=0, le=2)
    top_p: float = Field(0.95, ge=0, le=1)
    max_tokens: int = Field(2048, ge=64, le=32768)
    context_tokens: int = Field(0, ge=0, le=1_048_576)
    api_key: str = Field("", max_length=1024)
    headers: dict[str, str] | None = None


def _profile_out(profile: LlmProfile) -> dict[str, Any]:
    """A profile as the interface sees it: never its secrets."""
    secrets = profiles.secrets_of(profile)
    return {
        "id": str(profile.id),
        "name": profile.name,
        "provider": profile.provider,
        "base_url": profile.base_url,
        "model": profile.model,
        "timeout": profile.timeout,
        "temperature": profile.temperature,
        "top_p": profile.top_p,
        "max_tokens": profile.max_tokens,
        "context_tokens": profile.context_tokens,
        "is_active": profile.is_active,
        "api_key_set": bool(secrets.api_key),
        "header_names": list(profile.header_names or []),
        "updated_at": profile.updated_at,
        "updated_by": profile.updated_by,
    }


@router.get("/assistant/profiles", summary="List the saved assistant connections")
async def list_profiles(session: DbSession, _user: SettingsAdmin) -> list[dict[str, Any]]:
    return [_profile_out(profile) for profile in await profiles.list_profiles(session)]


@router.post("/assistant/profiles", summary="Create an assistant connection")
async def create_profile(
    payload: ProfileWrite, request: Request, session: DbSession, user: SettingsAdmin
) -> dict[str, Any]:
    profile = await profiles.save(
        session,
        profile_id=None,
        values=payload.model_dump(exclude={"api_key", "headers"}),
        api_key=payload.api_key,
        headers=payload.headers,
        actor=user.username,
    )
    await audit.record(
        session,
        action="assistant.profile.create",
        actor=user.username,
        actor_id=user.id,
        target=profile.name,
        ip_address=client_ip(request),
        details={"provider": profile.provider, "model": profile.model},
    )
    await session.commit()
    return _profile_out(profile)


@router.put("/assistant/profiles/{profile_id}", summary="Update an assistant connection")
async def update_profile(
    profile_id: uuid.UUID,
    payload: ProfileWrite,
    request: Request,
    session: DbSession,
    user: SettingsAdmin,
) -> dict[str, Any]:
    profile = await profiles.save(
        session,
        profile_id=profile_id,
        values=payload.model_dump(exclude={"api_key", "headers"}),
        api_key=payload.api_key,
        headers=payload.headers,
        actor=user.username,
    )
    await audit.record(
        session,
        action="assistant.profile.update",
        actor=user.username,
        actor_id=user.id,
        target=profile.name,
        ip_address=client_ip(request),
        details={"provider": profile.provider, "model": profile.model},
    )
    await session.commit()
    return _profile_out(profile)


@router.post("/assistant/profiles/{profile_id}/activate", summary="Use this connection")
async def activate_profile(
    profile_id: uuid.UUID, request: Request, session: DbSession, user: SettingsAdmin
) -> dict[str, Any]:
    profile = await profiles.activate(session, profile_id, actor=user.username)
    await audit.record(
        session,
        action="assistant.profile.activate",
        actor=user.username,
        actor_id=user.id,
        target=profile.name,
        ip_address=client_ip(request),
    )
    await session.commit()
    return _profile_out(profile)


@router.delete("/assistant/profiles/{profile_id}", summary="Delete an assistant connection")
async def delete_profile(
    profile_id: uuid.UUID, request: Request, session: DbSession, user: SettingsAdmin
) -> MessageResponse:
    profile = await profiles.delete(session, profile_id)
    await audit.record(
        session,
        action="assistant.profile.delete",
        actor=user.username,
        actor_id=user.id,
        target=profile.name,
        ip_address=client_ip(request),
    )
    await session.commit()
    return MessageResponse(message=f"Deleted the '{profile.name}' connection.")


@router.post("/assistant/profiles/{profile_id}/test", summary="Probe an assistant connection")
async def test_profile(
    profile_id: uuid.UUID, session: DbSession, _user: SettingsAdmin
) -> dict[str, Any]:
    """List the models the server offers, which proves the URL and the key."""
    profile = await profiles.get(session, profile_id)
    settings = profiles.overlay(await app_settings.load(session, "assistant"), profile)
    try:
        models = await build_provider(settings).list_models()
    except ProviderError as exc:
        return {"ok": False, "detail": str(exc)[:400], "models": []}
    return {
        "ok": True,
        "detail": f"{len(models)} model(s) available.",
        "models": models[:50],
        "model_present": settings.model in models if settings.model else False,
    }


class ModelProbe(StrictModel):
    """Values being typed, so the models can be listed before anything is saved."""

    provider: Literal["ollama", "openai"] = "ollama"
    base_url: str = Field("", max_length=1024)
    timeout: int = Field(60, ge=5, le=300)
    # Left empty on an existing connection, the stored key is used: the browser
    # never holds it, so it cannot resend it just to list the models.
    api_key: str = Field("", max_length=1024)
    headers: dict[str, str] | None = None
    profile_id: uuid.UUID | None = None


@router.post("/assistant/models", summary="List the models a server offers")
async def list_models(
    payload: ModelProbe, session: DbSession, _user: SettingsAdmin
) -> dict[str, Any]:
    """Ask the server what it serves, so the model is chosen rather than typed.

    A model identifier is long, exact and unforgiving — `gemma-4-31b-it:free`
    is not `gemma-4-31b:free` — and a typo only shows up as a failed chat much
    later. Listing turns it into a choice.
    """
    base = await app_settings.load(session, "assistant")
    stored = (
        profiles.secrets_of(await profiles.get(session, payload.profile_id))
        if payload.profile_id is not None
        else None
    )
    settings = base.model_copy(
        update={
            "provider": payload.provider,
            "base_url": payload.base_url,
            "timeout": payload.timeout,
            "api_key": payload.api_key or (stored.api_key if stored else ""),
            "headers": payload.headers
            if payload.headers is not None
            else (dict(stored.headers or {}) if stored else {}),
        }
    )
    if not settings.base_url:
        raise ValidationFailedError("Set the base URL before listing the models.")

    try:
        models = await build_provider(settings).list_models()
    except ProviderError as exc:
        return {"ok": False, "detail": str(exc)[:400], "models": []}
    return {
        "ok": True,
        "detail": f"{len(models)} model(s) offered.",
        "models": models,
    }
