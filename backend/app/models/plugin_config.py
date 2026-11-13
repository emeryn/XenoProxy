"""Runtime configuration and sealed secrets for plugins.

Configuration resolves over four layers, lowest priority first:

1. the plugin class declaration (`options_schema` defaults, `default_timeout`);
2. the instance configuration an administrator sets, in `PluginConfig`;
3. the analyst's own preferences, in `UserPluginConfig` / `UserPluginSecret`;
4. the `runtime_configuration` carried by a single job.

Layer 3 exists so an analyst can use a personal provider account without
touching the team's shared subscription. Only options and credentials a plugin
marks `user_overridable` may be set there, which keeps a shared enterprise key
out of reach of an individual override.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.job import PluginKind, Tlp


class PluginConfig(Base):
    """Instance-wide activation state and operational limits for one plugin."""

    __tablename__ = "plugin_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plugin_name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    plugin_type: Mapped[PluginKind] = mapped_column(
        Enum(PluginKind, name="plugin_kind"), default=PluginKind.ANALYZER, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=60)
    cache_ttl_seconds: Mapped[int] = mapped_column(Integer, default=86400)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=4)
    # Highest TLP this plugin may be used at, overriding the class default.
    max_tlp: Mapped[Tlp] = mapped_column(Enum(Tlp, name="tlp"), default=Tlp.AMBER, nullable=False)
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # Last health probe, so the Admin list can show a reachability column
    # without probing every provider on page load.
    health_ok: Mapped[bool | None] = mapped_column(Boolean)
    health_detail: Mapped[str | None] = mapped_column(String(512))
    health_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(128))


class PluginSecret(Base):
    """An instance-wide API credential sealed with envelope encryption.

    The plaintext never leaves the backend: the API exposes only the last four
    characters so an administrator can tell which key is configured.
    """

    __tablename__ = "plugin_secrets"
    __table_args__ = (UniqueConstraint("plugin_name", "secret_name", name="uq_plugin_secret"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_name: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[str] = mapped_column(String(4096), nullable=False)
    wrapped_key: Mapped[str] = mapped_column(String(512), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    hint: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(128))


class UserPluginConfig(Base):
    """One analyst's own option defaults for one plugin."""

    __tablename__ = "user_plugin_configs"
    __table_args__ = (UniqueConstraint("user_id", "plugin_name", name="uq_user_plugin_config"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    options: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class UserPluginSecret(Base):
    """One analyst's own credential for one plugin, sealed the same way."""

    __tablename__ = "user_plugin_secrets"
    __table_args__ = (
        UniqueConstraint("user_id", "plugin_name", "secret_name", name="uq_user_plugin_secret"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    plugin_name: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_name: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[str] = mapped_column(String(4096), nullable=False)
    wrapped_key: Mapped[str] = mapped_column(String(512), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    hint: Mapped[str] = mapped_column(String(16), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class LlmProfile(Base):
    """A saved connection to an inference server, one of which is active.

    A profile holds *where the model is and how it answers*: the server, the
    model, the generation parameters and the credentials. The assistant
    settings keep what is *policy* — whether it is on, who may use it, whether
    it may write, how long conversations live. Switching from a local Ollama to
    a hosted gateway then changes nothing about who is allowed to do what.

    The API key and the header values are sealed together in one blob, because
    a gateway key routinely lives in a header rather than in `Authorization`.
    Neither is ever returned: the API answers whether a key is set, and the
    header names.
    """

    __tablename__ = "llm_profiles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(32), default="ollama", nullable=False)
    base_url: Mapped[str] = mapped_column(String(1024), default="")
    model: Mapped[str] = mapped_column(String(256), default="")
    timeout: Mapped[int] = mapped_column(Integer, default=120)
    temperature: Mapped[float] = mapped_column(Float, default=0.2)
    top_p: Mapped[float] = mapped_column(Float, default=0.95)
    max_tokens: Mapped[int] = mapped_column(Integer, default=2048)
    context_tokens: Mapped[int] = mapped_column(Integer, default=0)
    # Only one row carries this. Enforced by the service, which clears the
    # others in the same transaction.
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Sealed {"api_key": str, "headers": {name: value}}.
    secrets_ciphertext: Mapped[str | None] = mapped_column(String(8192))
    secrets_wrapped_key: Mapped[str | None] = mapped_column(String(512))
    secrets_key_version: Mapped[int] = mapped_column(Integer, default=1)
    # Header names, kept in the clear so the interface can show the shape of a
    # profile without opening its secrets.
    header_names: Mapped[list[str]] = mapped_column(ARRAY(String(128)), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[str | None] = mapped_column(String(128))
