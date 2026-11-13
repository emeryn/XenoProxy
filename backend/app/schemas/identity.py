"""User, group and two-factor schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.user import AuthSource, Role
from app.schemas.common import StrictModel


class GroupOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    is_default: bool
    require_mfa: bool
    # The names this group answers to in the identity provider or the directory.
    external_names: list[str]
    grants_admin: bool
    # The provider that last signed somebody in through this group. Absent
    # means local: no directory has ever claimed it.
    matched_source: str | None = None
    matched_at: datetime | None = None
    member_count: int
    members: list[str]
    created_at: datetime


class GroupWrite(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    is_default: bool = False
    require_mfa: bool = False
    # Group names reported by OpenID Connect, LDAP or a trusted reverse proxy
    # that land a user in this group. A full distinguished name is accepted: its
    # first component is what gets compared.
    external_names: list[str] = Field(default_factory=list, max_length=50)
    # Membership grants the administrator role on every sign-in that maps here.
    grants_admin: bool = False


class GroupMappingProbe(StrictModel):
    """What a sign-in reporting these provider groups would resolve to."""

    groups: list[str] = Field(default_factory=list, max_length=100)


class UserDetailOut(BaseModel):
    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    role: Role
    auth_source: AuthSource
    is_active: bool
    must_change_password: bool
    mfa_enabled: bool
    groups: list[str]
    group_ids: list[uuid.UUID]
    created_at: datetime
    last_login_at: datetime | None


class UserCreated(UserDetailOut):
    """Returned once on creation or reset; the password is never retrievable again."""

    initial_password: str


class UserCreate(StrictModel):
    username: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._@+-]+$")
    display_name: str | None = Field(default=None, max_length=256)
    email: EmailStr | None = None
    role: Role = Role.ANALYST
    group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    # Left empty, a strong password is generated and returned once.
    password: str | None = Field(default=None, min_length=12, max_length=128)


class UserUpdate(StrictModel):
    display_name: str | None = Field(default=None, max_length=256)
    email: EmailStr | None = None
    role: Role | None = None
    is_active: bool | None = None


class UserGroupsUpdate(StrictModel):
    group_ids: list[uuid.UUID] = Field(max_length=20)


# --- two-factor -------------------------------------------------------------


class MfaStatus(BaseModel):
    enabled: bool
    required: bool
    requirement_reason: str | None
    confirmed_at: datetime | None
    recovery_codes_remaining: int


class MfaEnrolmentOut(BaseModel):
    """The shared secret, shown once so the authenticator can be set up."""

    secret: str
    otpauth_uri: str


class MfaConfirm(StrictModel):
    code: str = Field(min_length=6, max_length=16)


class MfaRecoveryCodesOut(BaseModel):
    codes: list[str]


class MfaDisable(StrictModel):
    """Disabling two-factor requires proving control of the account again."""

    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=16)
