"""Authentication schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.user import AuthSource, Role
from app.schemas.common import StrictModel

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class PreferencesUpdate(StrictModel):
    """An analyst's own defaults for the scan page."""

    default_playbook: str | None = Field(default=None, max_length=128)


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class CurrentUser(BaseModel):
    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    role: Role
    auth_source: AuthSource
    must_change_password: bool
    mfa_enabled: bool
    mfa_required: bool
    mfa_requirement_reason: str | None
    groups: list[str]
    permissions: list[str]
    default_playbook: str | None = None


class LoginResult(BaseModel):
    """Outcome of the first sign-in step.

    When the account has an authenticator, no session is opened: the caller must
    post the challenge token back with a code.
    """

    mfa_required: bool
    challenge_token: str | None
    user: CurrentUser | None


class MfaLoginRequest(StrictModel):
    challenge_token: str = Field(min_length=1, max_length=2048)
    code: str = Field(min_length=6, max_length=32)


class AuthMethods(BaseModel):
    """What the sign-in page should offer."""

    local_enabled: bool
    oidc_enabled: bool
    proxy_enabled: bool


class ApiKeyCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    days_valid: int | None = Field(default=365, ge=1, le=3650)


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked: bool


class ApiKeyCreated(ApiKeyOut):
    """Returned once on creation; the token is never retrievable again."""

    token: str
