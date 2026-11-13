"""A user's own scan preferences, and uploaded files as observables.

An analyst who runs the same kind of investigation every day should not pick
the same playbook every time, so the account carries the one to preselect.

A submitted file is stored with the job: the hash alone cannot be sent to a
sandbox, and an analyst who has the sample wants it analysed, not retyped.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

import sqlalchemy as sa

from app.core import schema_guards as guards

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.add_column(
        "users",
        sa.Column("default_playbook", sa.String(length=128), nullable=True),
    )
    # `file_name` and `file_size` are already in the baseline; only the place
    # the bytes were stored is new.
    guards.add_column(
        "jobs",
        sa.Column("file_path", sa.String(length=512), nullable=True),
    )


def downgrade() -> None:
    guards.drop_column("jobs", "file_path")
    guards.drop_column("users", "default_playbook")
