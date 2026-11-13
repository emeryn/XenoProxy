"""Directory mappings on a group, and the administrator grant.

A group gains the names it answers to in an identity provider or a directory,
and a flag saying membership grants administration. Together they replace the
single configured administrator group name with a mapping a deployment can
express in full.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core import schema_guards as guards

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.add_column(
        "groups",
        sa.Column(
            "external_names",
            postgresql.ARRAY(sa.String(length=256)),
            nullable=False,
            server_default=sa.text("'{}'::varchar[]"),
        ),
    )
    guards.add_column(
        "groups",
        sa.Column("grants_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # Resolving a sign-in reads every mapping, and the lists are short, so the
    # index that pays off is the one over the array's elements.
    if not guards.has_index("groups", "ix_groups_external_names"):
        guards.op.execute(
            "CREATE INDEX ix_groups_external_names ON groups USING gin (external_names)"
        )


def downgrade() -> None:
    guards.drop_index("ix_groups_external_names", "groups")
    guards.drop_column("groups", "grants_admin")
    guards.drop_column("groups", "external_names")
