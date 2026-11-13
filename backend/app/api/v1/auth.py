"""Authentication routes: sign-in, sign-out, profile and personal API keys."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app.api.deps import (
    CurrentUser,
    CurrentUserOptional,
    DbSession,
    client_ip,
    permissions_for,
)
from app.core.config import get_settings
from app.core.crypto import hash_password, verify_password
from app.core.errors import (
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
    ValidationFailedError,
)
from app.models.user import ApiKey, AuthSource
from app.schemas.auth import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyOut,
    AuthMethods,
    LoginRequest,
    LoginResult,
    MfaLoginRequest,
    PasswordChangeRequest,
    PreferencesUpdate,
)
from app.schemas.auth import (
    CurrentUser as CurrentUserOut,
)
from app.schemas.common import MessageResponse
from app.schemas.identity import (
    MfaConfirm,
    MfaDisable,
    MfaEnrolmentOut,
    MfaRecoveryCodesOut,
    MfaStatus,
)
from app.services import audit, auth, mfa, oidc, settings_store
from app.services.password_policy import assert_acceptable

router = APIRouter(prefix="/auth", tags=["auth"])

_PUBLIC = {"login", "methods"}


@router.get("/methods", response_model=AuthMethods, summary="List enabled sign-in methods")
async def methods() -> AuthMethods:
    settings = get_settings()
    return AuthMethods(
        local_enabled=True,
        oidc_enabled=settings.oidc_enabled,
        proxy_enabled=settings.proxy_auth_enabled,
    )


@router.post("/login", response_model=LoginResult, summary="Sign in with a local account")
async def login(
    payload: LoginRequest, request: Request, response: Response, session: DbSession
) -> LoginResult:
    """First step. An account with an authenticator gets a challenge, not a session."""
    ip = client_ip(request)
    user = await auth.authenticate_local(session, payload.username, payload.password)
    if user is None:
        await audit.record(
            session,
            action="auth.login",
            outcome="failure",
            actor=payload.username[:128],
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
        raise UnauthorizedError("The credentials are invalid.")

    if user.mfa_enabled:
        await audit.record(
            session,
            action="auth.mfa_challenge",
            actor=user.username,
            actor_id=user.id,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
        return LoginResult(
            mfa_required=True,
            challenge_token=auth.issue_mfa_challenge(user),
            user=None,
        )

    return LoginResult(
        mfa_required=False,
        challenge_token=None,
        user=await _finish_sign_in(session, user, request, response, method="password"),
    )


@router.post(
    "/login/mfa",
    response_model=LoginResult,
    summary="Complete sign-in with a one-time or recovery code",
)
async def login_mfa(
    payload: MfaLoginRequest, request: Request, response: Response, session: DbSession
) -> LoginResult:
    """Second step. Accepts a six-digit code or a single-use recovery code."""
    ip = client_ip(request)
    user_id = auth.open_mfa_challenge(payload.challenge_token)
    user = await auth.load_user(session, user_id)
    if user is None or not user.is_active or not user.mfa_enabled:
        raise UnauthorizedError("The sign-in attempt is no longer valid; start again.")

    accepted = mfa.verify_code(user, payload.code)
    used_recovery = False
    if not accepted:
        accepted = await mfa.consume_recovery_code(session, user, payload.code)
        used_recovery = accepted

    if not accepted:
        await audit.record(
            session,
            action="auth.mfa_verify",
            outcome="failure",
            actor=user.username,
            actor_id=user.id,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
        )
        raise UnauthorizedError("That code is not valid.")

    current = await _finish_sign_in(
        session,
        user,
        request,
        response,
        method="recovery_code" if used_recovery else "totp",
    )
    return LoginResult(mfa_required=False, challenge_token=None, user=current)


async def _finish_sign_in(
    session: DbSession,
    user: object,
    request: Request,
    response: Response,
    *,
    method: str,
) -> CurrentUserOut:
    """Open the session, set the cookie and record the sign-in."""
    settings = get_settings()
    record, token = await auth.open_session(
        session,
        user,  # type: ignore[arg-type]
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_hours * 3600,
    )
    await audit.record(
        session,
        action="auth.login",
        actor=user.username,  # type: ignore[attr-defined]
        actor_id=user.id,  # type: ignore[attr-defined]
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"session_id": str(record.id), "method": method},
    )
    return await _current_user_payload(session, user)  # type: ignore[arg-type]


@router.post("/logout", response_model=MessageResponse, summary="Sign out")
async def logout(
    request: Request, response: Response, session: DbSession, user: CurrentUserOptional
) -> MessageResponse:
    cookie = request.cookies.get(auth.SESSION_COOKIE)
    if cookie:
        await auth.revoke_session(session, cookie)
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    if user is not None:
        await audit.record(
            session,
            action="auth.logout",
            actor=user.username,
            actor_id=user.id,
            ip_address=client_ip(request),
        )
    return MessageResponse(message="Signed out.")


@router.get("/me", response_model=CurrentUserOut, summary="Describe the current user")
async def me(session: DbSession, user: CurrentUser) -> CurrentUserOut:
    return await _current_user_payload(session, user)


@router.put(
    "/me/preferences",
    response_model=CurrentUserOut,
    summary="Save the current user's own scan preferences",
)
async def save_preferences(
    payload: PreferencesUpdate, request: Request, session: DbSession, user: CurrentUser
) -> CurrentUserOut:
    """One preference so far: the playbook the scan page starts from.

    The playbook is stored by name and is not checked against the catalogue: a
    playbook can be renamed or removed later, and a stale preference should
    degrade to no preselection rather than refuse the save.
    """
    user.default_playbook = payload.default_playbook or None
    await audit.record(
        session,
        action="user.preferences",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
        details={"default_playbook": user.default_playbook},
    )
    await session.commit()
    await session.refresh(user, ["groups"])
    return await _current_user_payload(session, user)


@router.post(
    "/password", response_model=MessageResponse, summary="Change the current user password"
)
async def change_password(
    payload: PasswordChangeRequest, request: Request, session: DbSession, user: CurrentUser
) -> MessageResponse:
    if user.auth_source is not AuthSource.LOCAL or not user.password_hash:
        raise ForbiddenError("This account is managed by the identity provider.")
    if not verify_password(user.password_hash, payload.current_password):
        await audit.record(
            session,
            action="auth.password_change",
            outcome="failure",
            actor=user.username,
            actor_id=user.id,
            ip_address=client_ip(request),
        )
        raise UnauthorizedError("The current password is incorrect.")
    assert_acceptable(payload.new_password, username=user.username)

    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    await audit.record(
        session,
        action="auth.password_change",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
    )
    return MessageResponse(message="The password has been changed.")


@router.get("/api-keys", response_model=list[ApiKeyOut], summary="List personal API keys")
async def list_api_keys(session: DbSession, user: CurrentUser) -> list[ApiKeyOut]:
    rows = (
        await session.execute(
            select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc())
        )
    ).scalars()
    return [ApiKeyOut.model_validate(row, from_attributes=True) for row in rows]


@router.post(
    "/api-keys",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create a personal API key",
)
async def create_api_key(
    payload: ApiKeyCreate, request: Request, session: DbSession, user: CurrentUser
) -> ApiKeyCreated:
    record, token = await auth.create_api_key(
        session, user, name=payload.name, days_valid=payload.days_valid
    )
    await audit.record(
        session,
        action="api_key.create",
        actor=user.username,
        actor_id=user.id,
        target=record.name,
        ip_address=client_ip(request),
        details={"prefix": record.prefix},
    )
    return ApiKeyCreated(
        **ApiKeyOut.model_validate(record, from_attributes=True).model_dump(), token=token
    )


@router.delete(
    "/api-keys/{key_id}", response_model=MessageResponse, summary="Revoke a personal API key"
)
async def revoke_api_key(
    key_id: uuid.UUID, request: Request, session: DbSession, user: CurrentUser
) -> MessageResponse:
    record = (
        await session.execute(select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id))
    ).scalar_one_or_none()
    if record is None:
        raise NotFoundError("The API key does not exist.")
    record.revoked = True
    await audit.record(
        session,
        action="api_key.revoke",
        actor=user.username,
        actor_id=user.id,
        target=record.name,
        ip_address=client_ip(request),
    )
    return MessageResponse(message="The API key has been revoked.")


@router.get(
    "/oidc/start",
    summary="Begin the single sign-on flow",
    response_class=RedirectResponse,
)
async def oidc_start(
    request: Request,
    next_path: Annotated[str | None, Query(alias="next", max_length=512)] = None,
) -> RedirectResponse:
    """Redirect the browser to the identity provider."""
    settings = get_settings()
    redirect_uri = f"{settings.public_url}/api/v1/auth/oidc/callback"
    authorization_url, sealed_state = await oidc.build_authorization_url(redirect_uri)

    response = RedirectResponse(authorization_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        oidc.STATE_COOKIE,
        sealed_state,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=oidc.STATE_TTL_SECONDS,
    )
    response.set_cookie(
        "__Host-oidc-next",
        oidc.safe_next_path(next_path),
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=oidc.STATE_TTL_SECONDS,
    )
    return response


@router.get(
    "/oidc/callback",
    summary="Complete the single sign-on flow",
    response_class=RedirectResponse,
)
async def oidc_callback(
    request: Request,
    session: DbSession,
    code: Annotated[str, Query(max_length=4096)],
    state: Annotated[str, Query(max_length=512)],
) -> RedirectResponse:
    """Verify the provider answer, provision the user and open a session."""
    settings = get_settings()
    state_cookie = request.cookies.get(oidc.STATE_COOKIE)
    if not state_cookie:
        raise UnauthorizedError("The sign-on attempt is unknown; start again.")

    identity = await oidc.exchange_code(
        code=code,
        redirect_uri=f"{settings.public_url}/api/v1/auth/oidc/callback",
        state_token=state_cookie,
        returned_state=state,
    )
    user = await auth.upsert_federated_user(
        session,
        username=identity.username,
        email=identity.email,
        display_name=identity.display_name,
        groups=identity.groups,
        source=AuthSource.OIDC,
    )
    record, token = await auth.open_session(
        session,
        user,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    await audit.record(
        session,
        action="auth.login",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"method": "oidc", "session_id": str(record.id), "subject": identity.subject},
    )

    destination = oidc.safe_next_path(request.cookies.get("__Host-oidc-next"))
    response = RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_hours * 3600,
    )
    response.delete_cookie(oidc.STATE_COOKIE, path="/")
    response.delete_cookie("__Host-oidc-next", path="/")
    return response


@router.get("/mfa", response_model=MfaStatus, summary="Two-factor state of the current user")
async def mfa_status(session: DbSession, user: CurrentUser) -> MfaStatus:
    requirement = await mfa.requirement(session, user)
    return MfaStatus(
        enabled=user.mfa_enabled,
        required=requirement.required,
        requirement_reason=requirement.reason,
        confirmed_at=user.mfa_confirmed_at,
        recovery_codes_remaining=await mfa.remaining_recovery_codes(session, user),
    )


@router.post(
    "/mfa/enrol",
    response_model=MfaEnrolmentOut,
    summary="Start two-factor enrolment",
)
async def mfa_enrol(request: Request, session: DbSession, user: CurrentUser) -> MfaEnrolmentOut:
    """Return a fresh secret. It only becomes active once a code confirms it."""
    if user.auth_source is not AuthSource.LOCAL and not await settings_store.get(
        session, "allow_mfa_for_external_identities"
    ):
        raise ForbiddenError(
            "This account is managed by the identity provider, which is where its second "
            "factor is enrolled. An administrator can allow enrolment here instead."
        )
    enrolment = await mfa.begin_enrolment(session, user)
    await audit.record(
        session,
        action="auth.mfa_enrol_start",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
    )
    return MfaEnrolmentOut(secret=enrolment.secret, otpauth_uri=enrolment.otpauth_uri)


@router.post(
    "/mfa/confirm",
    response_model=MfaRecoveryCodesOut,
    summary="Confirm two-factor enrolment and get the recovery codes",
)
async def mfa_confirm(
    payload: MfaConfirm, request: Request, session: DbSession, user: CurrentUser
) -> MfaRecoveryCodesOut:
    codes = await mfa.confirm_enrolment(session, user, payload.code)
    await audit.record(
        session,
        action="auth.mfa_enabled",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
    )
    return MfaRecoveryCodesOut(codes=codes)


@router.post(
    "/mfa/recovery-codes",
    response_model=MfaRecoveryCodesOut,
    summary="Replace the recovery codes",
)
async def mfa_regenerate_codes(
    payload: MfaConfirm, request: Request, session: DbSession, user: CurrentUser
) -> MfaRecoveryCodesOut:
    """Issuing new codes invalidates the previous set."""
    if not user.mfa_enabled:
        raise ValidationFailedError("Two-factor authentication is not enabled on this account.")
    if not mfa.verify_code(user, payload.code):
        raise UnauthorizedError("That code is not valid.")
    codes = await mfa.generate_recovery_codes(session, user)
    await audit.record(
        session,
        action="auth.mfa_recovery_codes_reissued",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
    )
    return MfaRecoveryCodesOut(codes=codes)


@router.post("/mfa/disable", response_model=MessageResponse, summary="Turn two-factor off")
async def mfa_disable(
    payload: MfaDisable, request: Request, session: DbSession, user: CurrentUser
) -> MessageResponse:
    """Requires the password and a current code, so a borrowed session cannot do it."""
    if not user.mfa_enabled:
        raise ValidationFailedError("Two-factor authentication is not enabled on this account.")
    requirement = await mfa.requirement(session, user)
    if requirement.required:
        raise ForbiddenError(requirement.reason or "Two-factor authentication is required.")
    if not user.password_hash or not verify_password(user.password_hash, payload.password):
        raise UnauthorizedError("The password is incorrect.")
    if not mfa.verify_code(user, payload.code):
        raise UnauthorizedError("That code is not valid.")

    await mfa.disable(session, user)
    await audit.record(
        session,
        action="auth.mfa_disabled",
        actor=user.username,
        actor_id=user.id,
        ip_address=client_ip(request),
    )
    return MessageResponse(message="Two-factor authentication has been turned off.")


async def _current_user_payload(session: DbSession, user: object) -> CurrentUserOut:
    requirement = await mfa.requirement(session, user)  # type: ignore[arg-type]
    return CurrentUserOut(
        id=user.id,  # type: ignore[attr-defined]
        username=user.username,  # type: ignore[attr-defined]
        email=user.email,  # type: ignore[attr-defined]
        display_name=user.display_name,  # type: ignore[attr-defined]
        role=user.role,  # type: ignore[attr-defined]
        auth_source=user.auth_source,  # type: ignore[attr-defined]
        must_change_password=user.must_change_password,  # type: ignore[attr-defined]
        mfa_enabled=user.mfa_enabled,  # type: ignore[attr-defined]
        mfa_required=requirement.required,
        mfa_requirement_reason=requirement.reason,
        groups=sorted(group.name for group in user.groups),  # type: ignore[attr-defined]
        permissions=permissions_for(user.role),  # type: ignore[attr-defined]
        default_playbook=user.default_playbook,  # type: ignore[attr-defined]
    )
