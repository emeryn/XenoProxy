"""Introspection guards for Alembic revisions.

The baseline revision builds the schema from the live declarative metadata, so
on a clean database it already contains everything every later revision adds.
That makes the baseline trivially correct and always in step with the models,
at the price of one rule every later revision must follow: **it must be
idempotent**, because on a fresh database it runs against a schema that already
has its changes.

These helpers are that rule, written once. A revision expresses its change
through them and works both ways: as a no-op on a fresh database, and as a real
migration on a database created by an earlier release.

The alternative is to freeze the baseline as explicit DDL and let later
revisions be strictly linear. That is the more conventional arrangement, and it
is worth moving to once the schema stabilises; until then this keeps the two
paths from drifting.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# Re-exported so a revision can reach the operations module through the same
# import it already uses for the guards.
__all__ = [
    "add_column",
    "add_enum_value",
    "create_index",
    "create_table",
    "drop_column",
    "drop_index",
    "has_column",
    "has_constraint",
    "has_index",
    "has_table",
    "inspector",
    "op",
    "rename_column",
    "rename_table",
]


def inspector() -> sa.Inspector:
    return sa.inspect(op.get_bind())


def has_table(name: str) -> bool:
    return inspector().has_table(name)


def has_column(table: str, column: str) -> bool:
    insp = inspector()
    if not insp.has_table(table):
        return False
    return any(entry["name"] == column for entry in insp.get_columns(table))


def has_index(table: str, name: str) -> bool:
    insp = inspector()
    if not insp.has_table(table):
        return False
    return any(entry["name"] == name for entry in insp.get_indexes(table))


def has_constraint(table: str, name: str) -> bool:
    insp = inspector()
    if not insp.has_table(table):
        return False
    names = {entry["name"] for entry in insp.get_unique_constraints(table)}
    names |= {entry["name"] for entry in insp.get_check_constraints(table)}
    foreign = insp.get_foreign_keys(table)
    names |= {entry.get("name") for entry in foreign}
    return name in names


def create_table(name: str, *columns: sa.schema.SchemaItem) -> None:
    """Create a table unless the baseline already produced it."""
    if not has_table(name):
        op.create_table(name, *columns)


def add_column(table: str, column: sa.Column) -> None:
    """Add a column unless the baseline already produced it."""
    if has_table(table) and not has_column(table, column.name):
        op.add_column(table, column)


def drop_column(table: str, column: str) -> None:
    if has_column(table, column):
        op.drop_column(table, column)


def create_index(name: str, table: str, columns: list[str], *, unique: bool = False) -> None:
    if has_table(table) and not has_index(table, name):
        op.create_index(name, table, columns, unique=unique)


def drop_index(name: str, table: str) -> None:
    if has_index(table, name):
        op.drop_index(name, table_name=table)


def rename_table(old: str, new: str) -> None:
    """Rename a table, unless the new name is already the one in place."""
    if has_table(old) and not has_table(new):
        op.rename_table(old, new)


def rename_column(table: str, old: str, new: str) -> None:
    """Rename a column, unless the new name is already the one in place."""
    if has_column(table, old) and not has_column(table, new):
        op.alter_column(table, old, new_column_name=new)


def add_enum_value(enum_name: str, value: str) -> None:
    """Append a value to a Postgres enum if it is not already a member.

    `ALTER TYPE ... ADD VALUE` cannot run inside a transaction block on older
    servers, and `IF NOT EXISTS` covers the repeat case, so this is the one
    statement that is safe to issue unconditionally.
    """
    op.execute(f"ALTER TYPE {enum_name} ADD VALUE IF NOT EXISTS '{value}'")
