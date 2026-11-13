"""Where a job was submitted from.

The assistant, an MCP agent and the interface all create a job through the same
route, as the same account, so until now the history could not tell them apart.

Existing rows are backfilled from what the data already implies: a job with a
parent was made by a pivot, and the assistant tagged everything it submitted
with `assistant` before this column existed. Everything else predates the
distinction and is left as the interface, which is where it came from.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.core import schema_guards as guards

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

# SQLAlchemy persists an Enum column by member *name*, which is what every
# other enum in this schema already stores.
_ORIGIN = postgresql.ENUM(
    "UI", "API", "ASSISTANT", "MCP", "PIVOT", name="job_origin", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()
    _ORIGIN.create(bind, checkfirst=True)
    if guards.has_column("jobs", "origin"):
        return
    guards.add_column(
        "jobs",
        sa.Column("origin", _ORIGIN, nullable=False, server_default="UI"),
    )
    op.execute("UPDATE jobs SET origin = 'PIVOT' WHERE parent_job_id IS NOT NULL")
    op.execute("UPDATE jobs SET origin = 'ASSISTANT' WHERE 'assistant' = ANY(tags)")


def downgrade() -> None:
    guards.drop_column("jobs", "origin")
    _ORIGIN.drop(op.get_bind(), checkfirst=True)
