"""An index over the provider payloads, so they can be queried.

A report keeps the provider's answer whole. Asking which jobs ever saw a given
certificate fingerprint, or which VirusTotal engine disagreed, is a question
about the inside of those payloads. `jsonb_path_ops` is the operator class the
`@?` existence test uses, and it is about half the size of the default one
because it indexes paths rather than every key and value separately.

Guarded like every revision after the baseline; see `app.core.schema_guards`.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from app.core import schema_guards as guards

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

INDEX_NAME = "ix_reports_raw_output_path"


def upgrade() -> None:
    if guards.has_index("plugin_reports", INDEX_NAME):
        return
    # Only the rows that have a payload are indexed: a connector report has
    # none, and leaving them out keeps the index to what can be searched.
    guards.op.execute(
        f"CREATE INDEX {INDEX_NAME} ON plugin_reports "
        "USING gin (raw_output jsonb_path_ops) WHERE raw_output IS NOT NULL"
    )


def downgrade() -> None:
    guards.drop_index(INDEX_NAME, "plugin_reports")
