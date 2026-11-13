"""Administration of users and groups."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbSession, client_ip, require
from app.core.crypto import hash_password, new_token
from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailedError
from app.models.group import Group
from app.models.user import AuthSource, Role, Session, User
from app.schemas.common import MessageResponse
from app.schemas.identity import (
    GroupMappingProbe,
    GroupOut,
    GroupWrite,
    UserCreate,
    UserCreated,
    UserDetailOut,
    UserGroupsUpdate,
    UserUpdate,
)
from app.services import audit, group_mapping, mfa, settings_store
from app.services.password_policy import assert_acceptable

router = APIRouter(prefix="/admin", tags=["admin"])

UserAdmin = Annotated[User, Depends(require("users:manage"))]
GroupAdmin = Annotated[User, Depends(require("groups:manage"))]


# --- groups -----------------------------------------------------------------


@router.get("/groups", response_model=list[GroupOut], summary="List groups")
async def list_groups(session: DbSession, _user: GroupAdmin) -> list[GroupOut]:
    rows = (
        await session.execute(
            select(Group).options(selectinload(Group.members)).order_by(Group.name)
        )
    ).scalars()
    return [_group_out(group) for group in rows]


@router.post(
    "/groups",
    response_model=GroupOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a group",
)
async def create_group(
    payload: GroupWrite, request: Request, session: DbSession, user: GroupAdmin
) -> GroupOut:
    existing = (
        await session.execute(select(Group).where(Group.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("A group with this name already exists.")

    group = Group(
        name=payload.name,
        description=payload.description,
        is_default=payload.is_default,
        require_mfa=payload.require_mfa,
        external_names=_clean_names(payload.external_names),
        grants_admin=payload.grants_admin,
    )
    session.add(group)
    await session.flush()
    await audit.record(
        session,
        action="group.create",
        actor=user.username,
        actor_id=user.id,
        target=group.name,
        ip_address=client_ip(request),
        details={"is_default": group.is_default, "require_mfa": group.require_mfa},
    )
    await session.refresh(group, ["members"])
    return _group_out(group)


@router.put("/groups/{group_id}", response_model=GroupOut, summary="Update a group")
async def update_group(
    group_id: uuid.UUID,
    payload: GroupWrite,
    request: Request,
    session: DbSession,
    user: GroupAdmin,
) -> GroupOut:
    group = await _load_group(session, group_id)
    clash = (
        await session.execute(select(Group).where(Group.name == payload.name, Group.id != group_id))
    ).scalar_one_or_none()
    if clash is not None:
        raise ConflictError("A group with this name already exists.")

    group.name = payload.name
    group.description = payload.description
    group.is_default = payload.is_default
    group.require_mfa = payload.require_mfa
    group.external_names = _clean_names(payload.external_names)
    group.grants_admin = payload.grants_admin
    await audit.record(
        session,
        action="group.update",
        actor=user.username,
        actor_id=user.id,
        target=group.name,
        ip_address=client_ip(request),
    )
    return _group_out(group)


@router.delete("/groups/{group_id}", response_model=MessageResponse, summary="Delete a group")
async def delete_group(
    group_id: uuid.UUID, request: Request, session: DbSession, user: GroupAdmin
) -> MessageResponse:
    group = await _load_group(session, group_id)
    remaining = (await session.execute(select(func.count()).select_from(Group))).scalar_one()
    if remaining <= 1:
        raise ForbiddenError("The last group cannot be deleted.")
    if group.members:
        raise ConflictError(
            f"The group still has {len(group.members)} member(s); move them out first."
        )

    name = group.name
    await session.delete(group)
    await audit.record(
        session,
        action="group.delete",
        actor=user.username,
        actor_id=user.id,
        target=name,
        ip_address=client_ip(request),
    )
    return MessageResponse(message=f"The group '{name}' has been deleted.")


# --- users ------------------------------------------------------------------


@router.post(
    "/groups/mapping-preview",
    response_model=dict,
    summary="What a sign-in reporting these provider groups would resolve to",
)
async def preview_group_mapping(
    payload: GroupMappingProbe, session: DbSession, _user: UserAdmin
) -> dict[str, object]:
    """Try a mapping without asking anyone to sign in.

    A wrong mapping that grants administration is not something to discover by
    watching who gets in, so the resolution is answerable directly.
    """
    return await group_mapping.preview(session, payload.groups)


def _clean_names(names: list[str]) -> list[str]:
    """Deduplicate the mapped names, keeping what the administrator typed."""
    kept = [name.strip()[:256] for name in names if name.strip()]
    return list(dict.fromkeys(kept))


@router.get("/users", response_model=list[UserDetailOut], summary="List users")
async def list_users(session: DbSession, _user: UserAdmin) -> list[UserDetailOut]:
    rows = (
        await session.execute(
            select(User).options(selectinload(User.groups)).order_by(User.username)
        )
    ).scalars()
    return [_user_out(row) for row in rows]


@router.post(
    "/users",
    response_model=UserCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create a local user",
)
async def create_user(
    payload: UserCreate, request: Request, session: DbSession, user: UserAdmin
) -> UserCreated:
    """Create a local account. The password is shown once and must be changed."""
    username = payload.username.strip().lower()
    existing = (
        await session.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("A user with this username already exists.")

    password = payload.password or new_token(12)
    assert_acceptable(password, username=username)

    groups = await _resolve_groups(session, payload.group_ids, fall_back_to_default=True)
    created = User(
        username=username,
        email=payload.email,
        display_name=payload.display_name or username,
        role=payload.role,
        auth_source=AuthSource.LOCAL,
        password_hash=hash_password(password),
        must_change_password=await settings_store.get(
            session, "force_password_change_at_first_login"
        ),
        is_active=True,
        groups=groups,
    )
    session.add(created)
    await session.flush()

    await audit.record(
        session,
        action="user.create",
        actor=user.username,
        actor_id=user.id,
        target=created.username,
        ip_address=client_ip(request),
        details={"role": created.role.value, "groups": [group.name for group in groups]},
    )
    return UserCreated(
        **_user_out(created).model_dump(),
        initial_password=password,
    )


@router.patch("/users/{user_id}", response_model=UserDetailOut, summary="Update a user")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    request: Request,
    session: DbSession,
    user: UserAdmin,
) -> UserDetailOut:
    target = await _load_user(session, user_id)
    changes: dict[str, object] = {}

    if payload.role is not None:
        if target.id == user.id and payload.role is not Role.ADMIN:
            raise ForbiddenError("You cannot remove your own administrator role.")
        changes["role"] = {"before": target.role.value, "after": payload.role.value}
        target.role = payload.role
    if payload.is_active is not None:
        if target.id == user.id and not payload.is_active:
            raise ForbiddenError("You cannot disable your own account.")
        changes["is_active"] = payload.is_active
        target.is_active = payload.is_active
        if not payload.is_active:
            await _revoke_sessions(session, target)
    if payload.display_name is not None:
        target.display_name = payload.display_name
    if payload.email is not None:
        target.email = payload.email

    await audit.record(
        session,
        action="user.update",
        actor=user.username,
        actor_id=user.id,
        target=target.username,
        ip_address=client_ip(request),
        details=changes,
    )
    await session.refresh(target, ["groups"])
    return _user_out(target)


@router.put(
    "/users/{user_id}/groups",
    response_model=UserDetailOut,
    summary="Replace a user's group membership",
)
async def set_user_groups(
    user_id: uuid.UUID,
    payload: UserGroupsUpdate,
    request: Request,
    session: DbSession,
    user: UserAdmin,
) -> UserDetailOut:
    target = await _load_user(session, user_id)
    groups = await _resolve_groups(session, payload.group_ids, fall_back_to_default=False)
    if not groups:
        raise ValidationFailedError("A user must belong to at least one group.")

    target.groups = groups
    await audit.record(
        session,
        action="user.groups_change",
        actor=user.username,
        actor_id=user.id,
        target=target.username,
        ip_address=client_ip(request),
        details={"groups": [group.name for group in groups]},
    )
    return _user_out(target)


@router.post(
    "/users/{user_id}/reset-password",
    response_model=UserCreated,
    summary="Reset a user's password",
)
async def reset_user_password(
    user_id: uuid.UUID, request: Request, session: DbSession, user: UserAdmin
) -> UserCreated:
    """Issue a new password, revoke the user's sessions and force a change."""
    target = await _load_user(session, user_id)
    if target.auth_source is not AuthSource.LOCAL:
        raise ValidationFailedError("This account is managed by the identity provider.")

    password = new_token(12)
    target.password_hash = hash_password(password)
    target.must_change_password = await settings_store.get(
        session, "force_password_change_at_first_login"
    )
    revoked = await _revoke_sessions(session, target)

    await audit.record(
        session,
        action="user.password_reset",
        actor=user.username,
        actor_id=user.id,
        target=target.username,
        ip_address=client_ip(request),
        details={"sessions_revoked": revoked},
    )
    return UserCreated(**_user_out(target).model_dump(), initial_password=password)


@router.post(
    "/users/{user_id}/reset-mfa",
    response_model=MessageResponse,
    summary="Clear a user's two-factor enrolment",
)
async def reset_user_mfa(
    user_id: uuid.UUID, request: Request, session: DbSession, user: UserAdmin
) -> MessageResponse:
    """Use when an authenticator is lost and the recovery codes are gone too."""
    target = await _load_user(session, user_id)
    await mfa.disable(session, target)
    await _revoke_sessions(session, target)
    await audit.record(
        session,
        action="user.mfa_reset",
        actor=user.username,
        actor_id=user.id,
        target=target.username,
        ip_address=client_ip(request),
    )
    return MessageResponse(
        message=f"Two-factor authentication has been cleared for '{target.username}'.",
        details={"note": "They will be asked to enrol again at the next sign-in."},
    )


@router.delete("/users/{user_id}", response_model=MessageResponse, summary="Delete a user")
async def delete_user(
    user_id: uuid.UUID, request: Request, session: DbSession, user: UserAdmin
) -> MessageResponse:
    target = await _load_user(session, user_id)
    if target.id == user.id:
        raise ForbiddenError("You cannot delete your own account.")

    admins = (
        await session.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.ADMIN, User.is_active.is_(True))
        )
    ).scalar_one()
    if target.role is Role.ADMIN and admins <= 1:
        raise ForbiddenError("The last administrator cannot be deleted.")

    username = target.username
    await session.delete(target)
    await audit.record(
        session,
        action="user.delete",
        actor=user.username,
        actor_id=user.id,
        target=username,
        ip_address=client_ip(request),
    )
    return MessageResponse(
        message=f"The user '{username}' has been deleted.",
        details={"note": "Their jobs are kept and stay attributed to their username."},
    )


# --- helpers ----------------------------------------------------------------


def _group_out(group: Group) -> GroupOut:
    return GroupOut(
        id=group.id,
        name=group.name,
        description=group.description,
        is_default=group.is_default,
        require_mfa=group.require_mfa,
        external_names=list(group.external_names or []),
        grants_admin=group.grants_admin,
        matched_source=group.matched_source,
        matched_at=group.matched_at,
        member_count=len(group.members),
        members=sorted(member.username for member in group.members),
        created_at=group.created_at,
    )


def _user_out(user: User) -> UserDetailOut:
    return UserDetailOut(
        id=user.id,
        username=user.username,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        auth_source=user.auth_source,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        mfa_enabled=user.mfa_enabled,
        groups=sorted(group.name for group in user.groups),
        group_ids=[group.id for group in user.groups],
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


async def _load_group(session: DbSession, group_id: uuid.UUID) -> Group:
    group = (
        await session.execute(
            select(Group).where(Group.id == group_id).options(selectinload(Group.members))
        )
    ).scalar_one_or_none()
    if group is None:
        raise NotFoundError("The group does not exist.")
    return group


async def _load_user(session: DbSession, user_id: uuid.UUID) -> User:
    target = (
        await session.execute(
            select(User).where(User.id == user_id).options(selectinload(User.groups))
        )
    ).scalar_one_or_none()
    if target is None:
        raise NotFoundError("The user does not exist.")
    return target


async def _resolve_groups(
    session: DbSession, group_ids: list[uuid.UUID], *, fall_back_to_default: bool
) -> list[Group]:
    if not group_ids:
        if not fall_back_to_default:
            return []
        rows = (await session.execute(select(Group).where(Group.is_default.is_(True)))).scalars()
        return list(rows)

    rows = list((await session.execute(select(Group).where(Group.id.in_(group_ids)))).scalars())
    missing = set(group_ids) - {group.id for group in rows}
    if missing:
        raise ValidationFailedError(f"Unknown group(s): {', '.join(str(item) for item in missing)}")
    return rows


async def _revoke_sessions(session: DbSession, target: User) -> int:
    rows = (await session.execute(select(Session).where(Session.user_id == target.id))).scalars()
    revoked = 0
    for record in rows:
        if not record.revoked:
            record.revoked = True
            revoked += 1
    await session.flush()
    return revoked
