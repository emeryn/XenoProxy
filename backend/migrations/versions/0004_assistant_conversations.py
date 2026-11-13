"""Assistant conversations and messages.

Adds the two tables the in-application assistant stores a thread in. A
conversation belongs to one analyst and cascades with the account, because a
thread quotes job content that account was allowed to see.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.core import schema_guards as guards

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

MESSAGE_ROLE_VALUES = ("USER", "ASSISTANT", "TOOL")


def upgrade() -> None:
    role = postgresql.ENUM(*MESSAGE_ROLE_VALUES, name="message_role")
    role.create(guards.op.get_bind(), checkfirst=True)
    role_ref = postgresql.ENUM(*MESSAGE_ROLE_VALUES, name="message_role", create_type=False)

    guards.create_table(
        "assistant_conversations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=200), nullable=False, server_default=""),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    guards.create_index(
        "ix_conversations_user", "assistant_conversations", ["user_id", "updated_at"]
    )

    guards.create_table(
        "assistant_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "conversation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assistant_conversations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", role_ref, nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "tool_calls", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("tool_name", sa.String(length=64)),
        sa.Column(
            "steps", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("tokens", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    guards.create_index(
        "ix_messages_conversation", "assistant_messages", ["conversation_id", "created_at"]
    )


def downgrade() -> None:
    guards.drop_index("ix_messages_conversation", "assistant_messages")
    if guards.has_table("assistant_messages"):
        guards.op.drop_table("assistant_messages")
    guards.drop_index("ix_conversations_user", "assistant_conversations")
    if guards.has_table("assistant_conversations"):
        guards.op.drop_table("assistant_conversations")
    postgresql.ENUM(name="message_role").drop(guards.op.get_bind(), checkfirst=True)
