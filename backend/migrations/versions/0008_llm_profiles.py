"""Saved connections to an inference server, one of them active.

Separates where the model is from what the assistant is allowed to do: a
profile holds the server, the model, the generation parameters and the
credentials, while the assistant settings keep the policy.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

import sqlalchemy as sa

from app.core import schema_guards as guards

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    guards.create_table(
        "llm_profiles",
        sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("provider", sa.String(length=32), nullable=False, server_default="ollama"),
        sa.Column("base_url", sa.String(length=1024), server_default=""),
        sa.Column("model", sa.String(length=256), server_default=""),
        sa.Column("timeout", sa.Integer(), server_default="120"),
        sa.Column("temperature", sa.Float(), server_default="0.2"),
        sa.Column("top_p", sa.Float(), server_default="0.95"),
        sa.Column("max_tokens", sa.Integer(), server_default="2048"),
        sa.Column("context_tokens", sa.Integer(), server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("secrets_ciphertext", sa.String(length=8192)),
        sa.Column("secrets_wrapped_key", sa.String(length=512)),
        sa.Column("secrets_key_version", sa.Integer(), server_default="1"),
        sa.Column("header_names", sa.ARRAY(sa.String(length=128)), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_by", sa.String(length=128)),
    )


def downgrade() -> None:
    guards.op.drop_table("llm_profiles")
