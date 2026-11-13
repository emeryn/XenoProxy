"""Typed plugin framework: connectors, pivots and per-user configuration.

Turns the analyzer-only model into the IntelOwl plugin model:

- `analyzer_reports` becomes `plugin_reports`, carrying a `plugin_type` so one
  table holds analyzer, connector and pivot results, plus the observables a
  pivot derived and the child jobs they produced;
- `analyzer_configs` and `analyzer_secrets` become `plugin_configs` and
  `plugin_secrets`, with the plugin's type and its last health probe;
- `user_plugin_configs` and `user_plugin_secrets` add the analyst's own
  configuration layer between the instance settings and the per-job overrides;
- `jobs` gains the connector and pivot selections and its pivot lineage;
- `playbooks` gains a list per plugin type;
- `job_status` and `report_status` gain KILLED, for a stopped job.

Every change goes through `app.core.schema_guards`, so this revision is a no-op
on a database the baseline just created and a real migration on one created by
an earlier release. See that module for why.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.core import schema_guards as guards

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

PLUGIN_KIND_VALUES = ("ANALYZER", "CONNECTOR", "PIVOT")


def upgrade() -> None:
    bind = op.get_bind()

    plugin_kind = postgresql.ENUM(*PLUGIN_KIND_VALUES, name="plugin_kind")
    plugin_kind.create(bind, checkfirst=True)
    # Referenced without re-creating it on the tables below.
    plugin_kind_ref = postgresql.ENUM(*PLUGIN_KIND_VALUES, name="plugin_kind", create_type=False)

    # A stopped job and a stopped report both need a status of their own.
    guards.add_enum_value("job_status", "KILLED")
    guards.add_enum_value("report_status", "KILLED")

    _migrate_reports(plugin_kind_ref)
    _migrate_configs(plugin_kind_ref)
    _migrate_secrets()
    _create_user_layer()
    _extend_jobs()
    _extend_playbooks()


def _migrate_reports(plugin_kind_ref: postgresql.ENUM) -> None:
    """One report table for every plugin type."""
    guards.rename_table("analyzer_reports", "plugin_reports")
    guards.rename_column("plugin_reports", "analyzer_name", "plugin_name")

    guards.add_column(
        "plugin_reports",
        sa.Column(
            "plugin_type",
            plugin_kind_ref,
            nullable=False,
            server_default="ANALYZER",
        ),
    )
    guards.add_column(
        "plugin_reports",
        sa.Column(
            "derived_observables",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    guards.add_column(
        "plugin_reports",
        sa.Column(
            "spawned_job_ids",
            postgresql.ARRAY(postgresql.UUID(as_uuid=True)),
            nullable=False,
            server_default=sa.text("'{}'::uuid[]"),
        ),
    )

    # Postgres carries an index through a table and a column rename, so the
    # two report indexes already exist under their own names by this point.
    # They are only created here for the database the baseline just built.
    guards.create_index("ix_reports_job_id", "plugin_reports", ["job_id"])
    guards.create_index(
        "ix_reports_cache_lookup",
        "plugin_reports",
        ["plugin_name", "observable_value", "status", "created_at"],
    )


def _migrate_configs(plugin_kind_ref: postgresql.ENUM) -> None:
    """Instance configuration, now typed and carrying a health probe."""
    guards.rename_table("analyzer_configs", "plugin_configs")
    guards.rename_column("plugin_configs", "analyzer_name", "plugin_name")

    guards.add_column(
        "plugin_configs",
        sa.Column("plugin_type", plugin_kind_ref, nullable=False, server_default="ANALYZER"),
    )
    guards.add_column("plugin_configs", sa.Column("health_ok", sa.Boolean()))
    guards.add_column("plugin_configs", sa.Column("health_detail", sa.String(length=512)))
    guards.add_column("plugin_configs", sa.Column("health_checked_at", sa.DateTime(timezone=True)))


def _migrate_secrets() -> None:
    """Instance credentials, renamed alongside their plugin."""
    guards.rename_table("analyzer_secrets", "plugin_secrets")
    guards.rename_column("plugin_secrets", "analyzer_name", "plugin_name")

    # The unique constraint is renamed only when the old name survived the
    # table rename, which is the case on a database created by 0001 + 0002.
    if guards.has_constraint("plugin_secrets", "uq_analyzer_secret"):
        op.execute(
            "ALTER TABLE plugin_secrets RENAME CONSTRAINT uq_analyzer_secret TO uq_plugin_secret"
        )


def _create_user_layer() -> None:
    """The analyst's own configuration layer."""
    guards.create_table(
        "user_plugin_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plugin_name", sa.String(length=64), nullable=False),
        sa.Column(
            "options", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "plugin_name", name="uq_user_plugin_config"),
    )

    guards.create_table(
        "user_plugin_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plugin_name", sa.String(length=64), nullable=False),
        sa.Column("secret_name", sa.String(length=64), nullable=False),
        sa.Column("ciphertext", sa.String(length=4096), nullable=False),
        sa.Column("wrapped_key", sa.String(length=512), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("hint", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "plugin_name", "secret_name", name="uq_user_plugin_secret"),
    )


def _extend_jobs() -> None:
    """Per-type plugin selections and the pivot lineage."""
    for column in ("requested_connectors", "requested_pivots"):
        guards.add_column(
            "jobs",
            sa.Column(
                column,
                postgresql.ARRAY(sa.String(length=64)),
                nullable=False,
                server_default=sa.text("'{}'::varchar[]"),
            ),
        )

    guards.add_column(
        "jobs",
        sa.Column(
            "parent_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
        ),
    )
    guards.add_column("jobs", sa.Column("pivot_name", sa.String(length=64)))
    guards.add_column("jobs", sa.Column("depth", sa.Integer(), nullable=False, server_default="0"))
    guards.create_index("ix_jobs_parent", "jobs", ["parent_job_id"])


def _extend_playbooks() -> None:
    """A playbook names the plugins of each phase."""
    for column in ("connectors", "pivots"):
        guards.add_column(
            "playbooks",
            sa.Column(
                column,
                postgresql.ARRAY(sa.String(length=64)),
                nullable=False,
                server_default=sa.text("'{}'::varchar[]"),
            ),
        )


def downgrade() -> None:
    """Reverse the rename and drop what this revision added.

    The KILLED enum members are left in place: Postgres cannot remove a value
    from an enum type, and leaving an unused member is harmless.
    """
    for column in ("connectors", "pivots"):
        guards.drop_column("playbooks", column)

    guards.drop_index("ix_jobs_parent", "jobs")
    for column in (
        "depth",
        "pivot_name",
        "parent_job_id",
        "requested_pivots",
        "requested_connectors",
    ):
        guards.drop_column("jobs", column)

    if guards.has_table("user_plugin_secrets"):
        op.drop_table("user_plugin_secrets")
    if guards.has_table("user_plugin_configs"):
        op.drop_table("user_plugin_configs")

    if guards.has_constraint("plugin_secrets", "uq_plugin_secret"):
        op.execute(
            "ALTER TABLE plugin_secrets RENAME CONSTRAINT uq_plugin_secret TO uq_analyzer_secret"
        )
    guards.rename_column("plugin_secrets", "plugin_name", "analyzer_name")
    guards.rename_table("plugin_secrets", "analyzer_secrets")

    for column in ("health_checked_at", "health_detail", "health_ok", "plugin_type"):
        guards.drop_column("plugin_configs", column)
    guards.rename_column("plugin_configs", "plugin_name", "analyzer_name")
    guards.rename_table("plugin_configs", "analyzer_configs")

    for column in ("spawned_job_ids", "derived_observables", "plugin_type"):
        guards.drop_column("plugin_reports", column)
    guards.rename_column("plugin_reports", "plugin_name", "analyzer_name")
    guards.rename_table("plugin_reports", "analyzer_reports")

    postgresql.ENUM(name="plugin_kind").drop(op.get_bind(), checkfirst=True)
