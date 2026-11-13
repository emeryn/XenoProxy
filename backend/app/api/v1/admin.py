"""Administration: plugin configuration, credential vault, playbooks, users, audit.

Every route in this module is guarded by an admin-scoped permission.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select

from app.api.deps import DbSession, client_ip, require
from app.api.v1.catalog import build_plugin_views
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailedError
from app.models.audit import AuditEvent
from app.models.job import PluginKind
from app.models.playbook import Playbook
from app.models.user import User
from app.plugins import load_all
from app.plugins.base.registry import get_plugin
from app.repositories import plugin_configs
from app.schemas.admin import (
    AuditEventOut,
    HealthCheckOut,
    PlaybookOut,
    PlaybookWrite,
    PluginConfigUpdate,
    PluginOut,
    SecretUpdate,
)
from app.schemas.common import MessageResponse, Page
from app.services import audit, plugin_runtime, secrets_vault
from app.services.secrets_vault import SecretTooShortError

router = APIRouter(prefix="/admin", tags=["admin"])

PluginAdmin = Annotated[User, Depends(require("analyzers:manage"))]
SecretAdmin = Annotated[User, Depends(require("secrets:manage"))]
PlaybookAdmin = Annotated[User, Depends(require("playbooks:manage"))]
UserAdmin = Annotated[User, Depends(require("users:manage"))]
AuditReader = Annotated[User, Depends(require("audit:read"))]


@router.get(
    "/plugins",
    response_model=list[PluginOut],
    summary="List plugins with credential hints",
)
async def list_plugins(
    session: DbSession,
    _user: PluginAdmin,
    plugin_type: PluginKind | None = None,
) -> list[PluginOut]:
    return await build_plugin_views(session, include_hints=True, plugin_type=plugin_type)


@router.patch(
    "/plugins/{plugin_name}",
    response_model=PluginOut,
    summary="Update the configuration of one plugin",
)
async def update_plugin(
    plugin_name: str,
    payload: PluginConfigUpdate,
    request: Request,
    session: DbSession,
    user: PluginAdmin,
) -> PluginOut:
    load_all()
    cls = get_plugin(plugin_name)
    config = await plugin_configs.ensure(session, cls)

    changes: dict[str, Any] = {}
    if payload.enabled is not None:
        stored = await secrets_vault.configured_plugins(session)
        missing = set(cls.required_secret_names()) - stored.get(cls.name, set())
        if payload.enabled and missing:
            raise ValidationFailedError(
                "Configure the required credential(s) first: " + ", ".join(sorted(missing))
            )
        config.enabled = payload.enabled
        changes["enabled"] = payload.enabled
    if payload.timeout_seconds is not None:
        config.timeout_seconds = payload.timeout_seconds
        changes["timeout_seconds"] = payload.timeout_seconds
    if payload.cache_ttl_seconds is not None:
        config.cache_ttl_seconds = payload.cache_ttl_seconds
        changes["cache_ttl_seconds"] = payload.cache_ttl_seconds
    if payload.options is not None:
        allowed = set(cls.options_schema or {})
        unknown = set(payload.options) - allowed
        if unknown:
            raise ValidationFailedError(
                f"Unknown option(s) for {cls.name}: {', '.join(sorted(unknown))}"
            )
        config.options = payload.options
        changes["options"] = sorted(payload.options)

    config.updated_by = user.username
    await audit.record(
        session,
        action="plugin.configure",
        actor=user.username,
        actor_id=user.id,
        target=cls.name,
        ip_address=client_ip(request),
        details={**changes, "plugin_type": cls.plugin_type.value},
    )
    views = await build_plugin_views(session, include_hints=True)
    return next(view for view in views if view.name == cls.name)


@router.post(
    "/plugins/{plugin_name}/healthcheck",
    response_model=HealthCheckOut,
    summary="Probe whether a plugin can reach its provider",
)
async def healthcheck_plugin(
    plugin_name: str, session: DbSession, _user: PluginAdmin
) -> HealthCheckOut:
    """Ask the plugin whether its provider answers, and record the outcome.

    The probe runs with the instance credentials, never an analyst's own: it
    reports on what the team shares, which is what the Admin list shows.
    """
    load_all()
    cls = get_plugin(plugin_name)
    built = await plugin_runtime.build(session, cls.name, require_enabled=False)
    if built is None:
        raise NotFoundError("The plugin has no stored configuration yet.")

    check = await built.plugin.health_check()
    config = await plugin_configs.record_health(session, cls.name, check)
    await session.commit()
    if config is None:  # pragma: no cover - ensured by build() above
        raise NotFoundError("The plugin has no stored configuration yet.")

    return HealthCheckOut(
        plugin_name=cls.name,
        healthy=check.healthy,
        detail=check.detail,
        checked_at=config.health_checked_at,
    )


@router.put(
    "/plugins/{plugin_name}/secrets/{secret_name}",
    response_model=MessageResponse,
    summary="Store or replace a plugin credential",
)
async def put_secret(
    plugin_name: str,
    secret_name: str,
    payload: SecretUpdate,
    request: Request,
    session: DbSession,
    user: SecretAdmin,
) -> MessageResponse:
    """The value is sealed immediately and is never returned by the API."""
    load_all()
    cls = get_plugin(plugin_name)
    declared = {spec.name for spec in cls.secrets}
    if secret_name not in declared:
        raise ValidationFailedError(
            f"{cls.label} does not declare a credential named '{secret_name}'."
        )

    try:
        record = await secrets_vault.set_secret(
            session,
            plugin_name=cls.name,
            secret_name=secret_name,
            value=payload.value,
            actor=user.username,
        )
    except SecretTooShortError as exc:
        raise ValidationFailedError(str(exc)) from exc

    await audit.record(
        session,
        action="plugin.secret_set",
        actor=user.username,
        actor_id=user.id,
        target=f"{cls.name}/{secret_name}",
        ip_address=client_ip(request),
        details={"hint": record.hint},
    )
    return MessageResponse(message="The credential has been stored.", details={"hint": record.hint})


@router.delete(
    "/plugins/{plugin_name}/secrets/{secret_name}",
    response_model=MessageResponse,
    summary="Delete a plugin credential",
)
async def delete_secret(
    plugin_name: str,
    secret_name: str,
    request: Request,
    session: DbSession,
    user: SecretAdmin,
) -> MessageResponse:
    load_all()
    cls = get_plugin(plugin_name)
    deleted = await secrets_vault.delete_secret(
        session, plugin_name=cls.name, secret_name=secret_name
    )
    if not deleted:
        raise NotFoundError("The credential is not configured.")

    config = await plugin_configs.get(session, cls.name)
    if config is not None and secret_name in set(cls.required_secret_names()):
        config.enabled = False
        config.updated_by = user.username

    await audit.record(
        session,
        action="plugin.secret_delete",
        actor=user.username,
        actor_id=user.id,
        target=f"{cls.name}/{secret_name}",
        ip_address=client_ip(request),
    )
    return MessageResponse(message="The credential has been deleted.")


@router.post(
    "/playbooks",
    response_model=PlaybookOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a playbook",
)
async def create_playbook(
    payload: PlaybookWrite, request: Request, session: DbSession, user: PlaybookAdmin
) -> PlaybookOut:
    load_all()
    _assert_playbook_plugins(payload)
    existing = (
        await session.execute(select(Playbook).where(Playbook.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("A playbook with this name already exists.")

    playbook = Playbook(
        name=payload.name,
        description=payload.description,
        observable_types=payload.observable_types,
        analyzers=payload.analyzers,
        connectors=payload.connectors,
        pivots=payload.pivots,
        enabled=payload.enabled,
        is_builtin=False,
    )
    session.add(playbook)
    await session.flush()
    await audit.record(
        session,
        action="playbook.create",
        actor=user.username,
        actor_id=user.id,
        target=playbook.name,
        ip_address=client_ip(request),
        details={
            "analyzers": payload.analyzers,
            "connectors": payload.connectors,
            "pivots": payload.pivots,
        },
    )
    return PlaybookOut.model_validate(playbook, from_attributes=True)


@router.put("/playbooks/{playbook_id}", response_model=PlaybookOut, summary="Update a playbook")
async def update_playbook(
    playbook_id: uuid.UUID,
    payload: PlaybookWrite,
    request: Request,
    session: DbSession,
    user: PlaybookAdmin,
) -> PlaybookOut:
    load_all()
    _assert_playbook_plugins(payload)
    playbook = (
        await session.execute(select(Playbook).where(Playbook.id == playbook_id))
    ).scalar_one_or_none()
    if playbook is None:
        raise NotFoundError("The playbook does not exist.")

    playbook.name = payload.name
    playbook.description = payload.description
    playbook.observable_types = payload.observable_types
    playbook.analyzers = payload.analyzers
    playbook.connectors = payload.connectors
    playbook.pivots = payload.pivots
    playbook.enabled = payload.enabled
    await audit.record(
        session,
        action="playbook.update",
        actor=user.username,
        actor_id=user.id,
        target=playbook.name,
        ip_address=client_ip(request),
        details={
            "analyzers": payload.analyzers,
            "connectors": payload.connectors,
            "pivots": payload.pivots,
        },
    )
    return PlaybookOut.model_validate(playbook, from_attributes=True)


@router.delete(
    "/playbooks/{playbook_id}", response_model=MessageResponse, summary="Delete a playbook"
)
async def delete_playbook(
    playbook_id: uuid.UUID, request: Request, session: DbSession, user: PlaybookAdmin
) -> MessageResponse:
    playbook = (
        await session.execute(select(Playbook).where(Playbook.id == playbook_id))
    ).scalar_one_or_none()
    if playbook is None:
        raise NotFoundError("The playbook does not exist.")
    if playbook.is_builtin:
        raise ForbiddenError("Built-in playbooks cannot be deleted; disable them instead.")

    name = playbook.name
    await session.delete(playbook)
    await audit.record(
        session,
        action="playbook.delete",
        actor=user.username,
        actor_id=user.id,
        target=name,
        ip_address=client_ip(request),
    )
    return MessageResponse(message="The playbook has been deleted.")


@router.get("/audit", response_model=Page[AuditEventOut], summary="Read the audit trail")
async def list_audit(
    session: DbSession,
    _user: AuditReader,
    page: Annotated[int, Query(ge=1, le=1000)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    action: Annotated[str | None, Query(max_length=64)] = None,
) -> Page[AuditEventOut]:
    statement = select(AuditEvent)
    if action:
        statement = statement.where(AuditEvent.action == action)
    total = (
        await session.execute(select(func.count()).select_from(statement.subquery()))
    ).scalar_one()
    rows = (
        await session.execute(
            statement.order_by(AuditEvent.seq.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars()
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(row, from_attributes=True) for row in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/audit/verify", response_model=MessageResponse, summary="Verify the audit hash chain")
async def verify_audit(session: DbSession, _user: AuditReader) -> MessageResponse:
    result = await audit.verify_chain(session)
    message = (
        "The audit chain is intact."
        if result["valid"]
        else f"The audit chain is broken at sequence {result['broken_at_seq']}."
    )
    return MessageResponse(message=message, details=result)


def _assert_playbook_plugins(payload: PlaybookWrite) -> None:
    """Refuse a playbook whose lists hold the wrong kind of plugin.

    Catching it here is what stops a playbook from naming a connector in its
    analyzer list, which would otherwise surface as a plugin silently never
    running in the phase the operator expected.
    """
    for names, expected in (
        (payload.analyzers, PluginKind.ANALYZER),
        (payload.connectors, PluginKind.CONNECTOR),
        (payload.pivots, PluginKind.PIVOT),
    ):
        for name in names:
            cls = get_plugin(name)
            if cls.plugin_type is not expected:
                raise ValidationFailedError(
                    f"'{name}' is a {cls.plugin_type.value}; it cannot be listed "
                    f"as a {expected.value} in a playbook."
                )


async def _load_user(session: DbSession, user_id: uuid.UUID) -> User:
    target = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target is None:
        raise NotFoundError("The user does not exist.")
    return target
