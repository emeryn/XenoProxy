"""Administration of installed plugin packages: list, install from a zip, remove, reload.

Installing a plugin runs operator-supplied code inside the backend, so every
route here is admin-only and every action is written to the audit trail with the
archive digest.
"""

from __future__ import annotations

import re
import shutil
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Request, UploadFile, status

from app.api.deps import DbSession, client_ip, require
from app.core.config import get_settings
from app.core.errors import ForbiddenError, NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.models.user import User
from app.plugins import load_all
from app.plugins.custom import (
    ArchiveError,
    ManifestError,
    current_state,
    extract,
    plugins_root,
    sync,
    unload_plugin,
)
from app.plugins.custom.archive import MAX_ARCHIVE_BYTES
from app.repositories import plugin_configs
from app.schemas.common import MessageResponse
from app.services import audit

logger = get_logger(__name__)
router = APIRouter(prefix="/admin/plugin-packages", tags=["admin"])

PluginAdmin = Annotated[User, Depends(require("plugins:manage"))]

_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_]{2,47}$")


def _state_payload() -> dict[str, Any]:
    settings = get_settings()
    state = current_state()
    return {
        "enabled": state.enabled,
        "upload_enabled": settings.plugins_upload_enabled,
        "directory": state.directory,
        "max_archive_bytes": MAX_ARCHIVE_BYTES,
        "plugins": [plugin.as_dict() for plugin in state.plugins],
    }


@router.get("", response_model=dict, summary="List installed plugin packages")
async def list_plugins(_user: PluginAdmin) -> dict[str, Any]:
    sync()
    return _state_payload()


@router.post("/reload", response_model=dict, summary="Rescan the plugins directory")
async def reload_plugins(request: Request, session: DbSession, user: PluginAdmin) -> dict[str, Any]:
    """Pick up a plugin that was dropped straight into the volume."""
    before = {plugin.name for plugin in current_state().plugins}
    state = sync()
    after = {plugin.name for plugin in state.plugins}
    await _ensure_configs(session)
    await audit.record(
        session,
        action="plugin.reload",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
        details={"added": sorted(after - before), "removed": sorted(before - after)},
    )
    return _state_payload()


@router.post(
    "",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Install a plugin package from a zip archive",
)
async def install_plugin(
    request: Request,
    session: DbSession,
    user: PluginAdmin,
    archive: Annotated[UploadFile, File(description="Zip archive holding plugin.json")],
) -> dict[str, Any]:
    settings = get_settings()
    if not settings.plugins_enabled:
        raise ForbiddenError("Installed plugin packages are disabled on this instance.")
    if not settings.plugins_upload_enabled:
        raise ForbiddenError(
            "Plugin upload is disabled; drop the folder into the plugins volume instead."
        )

    payload = await archive.read(MAX_ARCHIVE_BYTES + 1)
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValidationFailedError(
            f"The archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB."
        )

    root = plugins_root()
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValidationFailedError(f"The plugins directory {root} is not writable: {exc}") from exc

    try:
        installed = extract(payload, root)
    except (ArchiveError, ManifestError) as exc:
        await audit.record(
            session,
            action="plugin.install",
            outcome="failure",
            actor=user.username,
            actor_id=user.id,
            target=archive.filename or "archive.zip",
            ip_address=client_ip(request),
            details={"reason": str(exc)[:300]},
        )
        raise ValidationFailedError(str(exc)) from exc

    # Replacing a loaded plugin means the old module is still imported.
    unload_plugin(installed.manifest.name)
    state = sync()
    loaded = next((entry for entry in state.plugins if entry.name == installed.manifest.name), None)

    if loaded is None or not loaded.loaded:
        reason = loaded.error if loaded else "the plugin did not load"
        shutil.rmtree(installed.directory, ignore_errors=True)
        sync()
        await audit.record(
            session,
            action="plugin.install",
            outcome="failure",
            actor=user.username,
            actor_id=user.id,
            target=installed.manifest.name,
            ip_address=client_ip(request),
            details={"reason": str(reason)[:300], "sha256": installed.sha256},
        )
        raise ValidationFailedError(f"The plugin was rejected: {reason}")

    await _ensure_configs(session)
    await audit.record(
        session,
        action="plugin.install",
        actor=user.username,
        actor_id=user.id,
        target=installed.manifest.name,
        ip_address=client_ip(request),
        details={
            "version": installed.manifest.version,
            "sha256": installed.sha256,
            "files": installed.file_count,
            "filename": archive.filename,
        },
    )
    logger.info(
        "plugin_installed",
        plugin=installed.manifest.name,
        version=installed.manifest.version,
        sha256=installed.sha256,
    )
    return _state_payload()


@router.delete(
    "/{name}",
    response_model=MessageResponse,
    summary="Remove an installed plugin package",
)
async def delete_plugin(
    name: str, request: Request, session: DbSession, user: PluginAdmin
) -> MessageResponse:
    if not _SAFE_NAME.match(name):
        raise ValidationFailedError("That is not a valid plugin name.")

    root = plugins_root()
    directory = root / name
    if not directory.is_dir() or not directory.resolve().is_relative_to(root.resolve()):
        raise NotFoundError("The plugin is not installed.")

    unload_plugin(name)
    shutil.rmtree(directory, ignore_errors=True)
    sync()

    await audit.record(
        session,
        action="plugin.delete",
        actor=user.username,
        actor_id=user.id,
        target=name,
        ip_address=client_ip(request),
    )
    return MessageResponse(
        message=f"The plugin '{name}' has been removed.",
        details={"note": "Its stored credentials and configuration are kept."},
    )


async def _ensure_configs(session: DbSession) -> None:
    """Give every freshly loaded custom plugin its default configuration row."""
    for cls in load_all().values():
        if getattr(cls, "is_custom", False):
            await plugin_configs.ensure(session, cls)
