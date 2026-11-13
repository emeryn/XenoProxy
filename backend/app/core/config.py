"""Single source of configuration for the backend, loaded from the environment."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        return None
    return candidate.read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    """Backend settings. Every value comes from a BACKEND_ prefixed variable."""

    model_config = SettingsConfigDict(env_prefix="BACKEND_", extra="ignore")

    environment: Literal["development", "production"] = "production"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    public_url: str = "http://localhost:8080"
    docs_enabled: bool = True

    db_host: str = "database"
    db_port: int = 5432
    db_name: str = "xenoproxy"
    db_user: str = "xenoproxy_app"
    db_password: str = ""
    db_password_file: str | None = None

    redis_host: str = "queue"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    redis_password_file: str | None = None

    secret_key: str = ""
    secret_key_file: str | None = None
    master_key: str = ""
    master_key_file: str | None = None

    # Pinnable so a deployment can decide the two-factor policy without the
    # interface, which an account that still owes an enrolment cannot reach.
    require_mfa_for_all: bool = False
    require_mfa_for_admins: bool = True

    session_idle_minutes: int = 60
    session_absolute_hours: int = 12

    bootstrap_admin_username: str = "admin"
    # Generated into the secrets volume on first boot and read through the
    # *_FILE variant, so no credential sits in docker-compose.yml or in an
    # environment variable that `docker inspect` would show. An explicit value
    # wins, which is how an operator chooses their own.
    bootstrap_admin_password: str = ""
    bootstrap_admin_password_file: str | None = None

    trusted_proxy_count: int = 1
    proxy_auth_enabled: bool = False
    proxy_auth_user_header: str = "X-Remote-User"
    proxy_auth_email_header: str = "X-Remote-Email"
    proxy_auth_groups_header: str = "X-Remote-Groups"

    oidc_enabled: bool = False
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str = ""
    oidc_client_secret_file: str | None = None
    oidc_scopes: str = "openid profile email"
    oidc_admin_group: str = "xenoproxy-admins"

    # Analyzer plugins are loaded from this directory, which is a mounted volume.
    # A plugin runs with the backend's privileges, so installing one is an
    # administrator action; set plugins_enabled to false to forbid it entirely.
    plugins_enabled: bool = True
    plugins_dir: str = "/app/plugins"
    # Samples an analyst submitted. Separate from the plugins volume: one
    # holds code the backend imports, the other holds bytes it must never
    # execute, and they should not share a mount.
    uploads_dir: str = "/app/uploads"
    plugins_upload_enabled: bool = True

    cache_default_ttl_seconds: int = 86400
    analyzer_default_timeout_seconds: int = 60
    analyzer_max_concurrency: int = 8
    allow_private_targets: bool = False

    outbound_proxy_url: str | None = None
    custom_ca_file: str | None = None

    cors_origins: str = ""
    max_body_bytes: int = 2097152
    max_upload_bytes: int = 33554432
    max_page_size: int = 100

    @field_validator("public_url")
    @classmethod
    def _strip_slash(cls, value: str) -> str:
        return value.rstrip("/")

    def model_post_init(self, _context: object) -> None:
        pairs = (
            ("db_password", "db_password_file"),
            ("secret_key", "secret_key_file"),
            ("master_key", "master_key_file"),
            ("bootstrap_admin_password", "bootstrap_admin_password_file"),
            ("redis_password", "redis_password_file"),
            ("oidc_client_secret", "oidc_client_secret_file"),
        )
        for field, file_field in pairs:
            if not getattr(self, field):
                value = _read_secret_file(getattr(self, file_field))
                if value:
                    object.__setattr__(self, field, value)

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def redis_url(self) -> str:
        credentials = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{credentials}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def managed_by_environment(self, name: str) -> bool:
        """Report whether an admin-editable setting is pinned by the environment."""
        key = f"BACKEND_{name.upper()}"
        return key in os.environ or f"{key}_FILE" in os.environ


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
