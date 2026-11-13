"""Restore the most recent dump into a scratch database and verify it.

A backup that has never been restored is not a backup. This proves the newest
dump can be read back, then drops the scratch database.

    python scripts/restore_test.py
"""

from __future__ import annotations

import subprocess  # noqa: S404 - this is a developer tool, not the running service
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUPS = ROOT / "backups"
SCRATCH_DB = "xenoproxy_restore_test"
COMPOSE = ["docker", "compose"]
PASSWORD_FILE = "/run/secrets/db_password.postgres"


def compose(*arguments: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [*COMPOSE, *arguments], cwd=ROOT, input=stdin, capture_output=True, check=False
    )


def psql(database: str, statement: str) -> subprocess.CompletedProcess[bytes]:
    inner = (
        f'PGPASSWORD="$(cat {PASSWORD_FILE})" '
        f"psql -U xenoproxy_app -d {database} -v ON_ERROR_STOP=1 -tAc '{statement}'"
    )
    return compose("exec", "-T", "database", "sh", "-c", inner)


def drop_scratch() -> None:
    psql("postgres", f"DROP DATABASE IF EXISTS {SCRATCH_DB}")


def main() -> int:
    dumps = sorted(BACKUPS.glob("*.dump"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not dumps:
        print("No dump found in ./backups. Create one first:", file=sys.stderr)
        print(
            '  docker compose exec -T database sh -c \'PGPASSWORD="$(cat '
            f"{PASSWORD_FILE})\" pg_dump -U xenoproxy_app -d xenoproxy --format=custom' > backups/xenoproxy.dump",
            file=sys.stderr,
        )
        return 1

    latest = dumps[0]
    print(f"Restoring {latest.name} into {SCRATCH_DB}")

    drop_scratch()
    created = psql("postgres", f"CREATE DATABASE {SCRATCH_DB}")
    if created.returncode != 0:
        print(created.stderr.decode(errors="replace"), file=sys.stderr)
        return 1

    try:
        restore = compose(
            "exec",
            "-T",
            "database",
            "sh",
            "-c",
            f'PGPASSWORD="$(cat {PASSWORD_FILE})" '
            f"pg_restore -U xenoproxy_app -d {SCRATCH_DB} --no-owner --exit-on-error",
            stdin=latest.read_bytes(),
        )
        if restore.returncode != 0:
            print(restore.stderr.decode(errors="replace"), file=sys.stderr)
            print("Restore FAILED.", file=sys.stderr)
            return 1

        counted = psql(
            SCRATCH_DB,
            "SELECT (SELECT count(*) FROM jobs) || '/' || "
            "(SELECT count(*) FROM analyzer_reports) || '/' || "
            "(SELECT count(*) FROM audit_events)",
        )
        rows = counted.stdout.decode(errors="replace").strip()
        print(f"Restore succeeded. jobs/reports/audit rows: {rows}")
        print(
            "Note: analyzer credentials in a restored dump are unreadable "
            "without the master key, so back that key up separately."
        )
        return 0
    finally:
        drop_scratch()


if __name__ == "__main__":
    sys.exit(main())
