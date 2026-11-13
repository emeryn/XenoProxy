"""Administration schemas: plugin configuration, credentials, playbooks, users."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.job import PluginKind
from app.models.user import AuthSource, Role
from app.schemas.common import StrictModel


class ProviderInfoOut(BaseModel):
    """Who serves a plugin, and what configuring it requires."""

    name: str
    url: str
    # The endpoint XenoProxy calls. Shown read-only: it is not a setting, and
    # seeing it is how an operator knows what to allow through their egress.
    api_base_url: str
    credential_url: str
    free_tier: str
    rate_limit: str
    notes: str
    self_hosted: bool


class SecretSpecOut(BaseModel):
    name: str
    label: str
    required: bool
    help_text: str
    placeholder: str
    user_overridable: bool


class PluginOut(BaseModel):
    """A plugin as the UI sees it: declaration plus runtime state."""

    name: str
    label: str
    description: str
    plugin_type: PluginKind
    supported_types: list[str]
    secrets: list[SecretSpecOut]
    options_schema: dict[str, Any]
    documentation_url: str
    free_tier: bool
    requires_network: bool
    provider: ProviderInfoOut
    is_custom: bool
    plugin_version: str
    max_tlp: str
    # Connector and pivot declarations. Absent for an analyzer.
    run_on_verdicts: list[str] = Field(default_factory=list)
    run_on_partial_failure: bool | None = None
    child_playbook: str | None = None
    max_children: int | None = None
    # Stored state.
    enabled: bool
    configured: bool
    missing_secrets: list[str]
    secret_hints: dict[str, str]
    options: dict[str, Any]
    timeout_seconds: int
    cache_ttl_seconds: int
    health_ok: bool | None = None
    health_detail: str | None = None
    health_checked_at: datetime | None = None
    updated_at: datetime | None
    updated_by: str | None


class PluginConfigUpdate(StrictModel):
    enabled: bool | None = None
    timeout_seconds: int | None = Field(default=None, ge=5, le=900)
    cache_ttl_seconds: int | None = Field(default=None, ge=0, le=2592000)
    options: dict[str, Any] | None = None


class SecretUpdate(StrictModel):
    """Write-only credential submission. The value is never returned."""

    value: str = Field(min_length=8, max_length=2048)


class HealthCheckOut(BaseModel):
    """Outcome of probing one plugin's provider."""

    plugin_name: str
    healthy: bool
    detail: str
    checked_at: datetime


class PlaybookOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    observable_types: list[str]
    analyzers: list[str]
    connectors: list[str]
    pivots: list[str]
    is_builtin: bool
    enabled: bool
    updated_at: datetime


class PlaybookWrite(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    observable_types: list[str] = Field(default_factory=list, max_length=6)
    analyzers: list[str] = Field(min_length=1, max_length=30)
    connectors: list[str] = Field(default_factory=list, max_length=10)
    pivots: list[str] = Field(default_factory=list, max_length=10)
    enabled: bool = True


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    role: Role
    auth_source: AuthSource
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserRoleUpdate(StrictModel):
    role: Role


class UserActiveUpdate(StrictModel):
    is_active: bool


class AuditEventOut(BaseModel):
    seq: int
    occurred_at: datetime
    action: str
    outcome: str
    actor: str
    target: str | None
    ip_address: str | None
    request_id: str | None
    details: dict[str, Any]
