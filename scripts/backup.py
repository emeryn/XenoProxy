"""Dump the database into ./backups.

    python scripts/backup.py

Encrypt the dump before storing it, and keep the encryption key separate from
the backup itself.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - this is a developer tool, not the running service
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUPS = ROOT / "backups"
PASSWORD_FILE = "/run/secrets/db_password.postgres"


def main() -> int:
    BACKUPS.mkdir(exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = BACKUPS / f"xenoproxy-{stamp}.dump"

    result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "database",
            "sh",
            "-c",
            f'PGPASSWORD="$(cat {PASSWORD_FILE})" '
            "pg_dump -U xenoproxy_app -d xenoproxy --format=custom",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        print(result.stderr.decode(errors="replace"), file=sys.stderr)
        return 1

    target.write_bytes(result.stdout)
    print(f"Wrote {target.relative_to(ROOT)} ({len(result.stdout) // 1024} KiB)")
    print("Encrypt it before storing it, and back up the master key separately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
