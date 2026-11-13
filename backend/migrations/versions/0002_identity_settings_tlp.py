"""Groups, two-factor, instance settings and TLP.

Adds group membership, TOTP enrolment with recovery codes, the editable
instance settings table, and the TLP and scan-mode columns the engine uses to
decide what may run and what may be reused.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.core import schema_guards as guards

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TLP_VALUES = ("CLEAR", "GREEN", "AMBER", "RED")
SCAN_MODE_VALUES = ("REUSE_RECENT", "FORCE_NEW")


def upgrade() -> None:
    bind = op.get_bind()
    tlp = postgresql.ENUM(*TLP_VALUES, name="tlp")
    tlp.create(bind, checkfirst=True)
    scan_mode = postgresql.ENUM(*SCAN_MODE_VALUES, name="scan_mode")
    scan_mode.create(bind, checkfirst=True)

    guards.create_table(
        "groups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("description", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("require_mfa", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    guards.create_table(
        "user_groups",
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    guards.create_table(
        "mfa_recovery_codes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("used_at", sa.DateTime(timezone=True)),
    )
    guards.create_index("ix_mfa_recovery_user_id", "mfa_recovery_codes", ["user_id"])

    guards.create_table(
        "instance_settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(length=64), nullable=False, unique=True),
        sa.Column("value", postgresql.JSONB(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_by", sa.String(length=128)),
    )

    guards.add_column(
        "users",
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    guards.add_column("users", sa.Column("mfa_secret_ciphertext", sa.String(length=512)))
    guards.add_column("users", sa.Column("mfa_secret_wrapped_key", sa.String(length=512)))
    guards.add_column(
        "users",
        sa.Column("mfa_secret_key_version", sa.Integer(), nullable=False, server_default="1"),
    )
    guards.add_column("users", sa.Column("mfa_confirmed_at", sa.DateTime(timezone=True)))
    guards.add_column("users", sa.Column("mfa_last_counter", sa.BigInteger()))

    guards.add_column(
        "jobs",
        sa.Column("tlp", tlp, nullable=False, server_default="AMBER"),
    )
    guards.add_column(
        "jobs",
        sa.Column("scan_mode", scan_mode, nullable=False, server_default="REUSE_RECENT"),
    )
    guards.add_column("jobs", sa.Column("scan_check_minutes", sa.Integer()))
    guards.add_column(
        "jobs",
        sa.Column(
            "runtime_configuration",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    guards.add_column(
        "jobs",
        sa.Column(
            "visible_to_group_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("'{}'::uuid[]"),
        ),
    )
    guards.create_index("ix_jobs_tlp", "jobs", ["tlp"])

    guards.add_column(
        "analyzer_configs",
        sa.Column("max_tlp", tlp, nullable=False, server_default="AMBER"),
    )


def downgrade() -> None:
    op.drop_column("analyzer_configs", "max_tlp")
    op.drop_index("ix_jobs_tlp", table_name="jobs")
    for column in (
        "visible_to_group_ids",
        "runtime_configuration",
        "scan_check_minutes",
        "scan_mode",
        "tlp",
    ):
        op.drop_column("jobs", column)
    for column in (
        "mfa_last_counter",
        "mfa_confirmed_at",
        "mfa_secret_key_version",
        "mfa_secret_wrapped_key",
        "mfa_secret_ciphertext",
        "mfa_enabled",
    ):
        op.drop_column("users", column)

    op.drop_table("instance_settings")
    op.drop_index("ix_mfa_recovery_user_id", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
    op.drop_table("user_groups")
    op.drop_table("groups")

    bind = op.get_bind()
    postgresql.ENUM(name="scan_mode").drop(bind, checkfirst=True)
    postgresql.ENUM(name="tlp").drop(bind, checkfirst=True)
