"""Where a group's membership comes from.

Groups are always local rows: nothing creates one from a directory, and a
sign-in matches the names a provider reports against the mappings a group
carries. So "synchronised" is not a property a group has until a provider has
actually matched it — which is what these two columns record, on the sign-in
that does it.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

import sqlalchemy as sa

from app.core import schema_guards as guards

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.add_column(
        "groups",
        sa.Column("matched_source", sa.String(length=16), nullable=True),
    )
    guards.add_column(
        "groups",
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    guards.drop_column("groups", "matched_at")
    guards.drop_column("groups", "matched_source")
