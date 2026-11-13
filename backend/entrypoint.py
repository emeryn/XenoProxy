"""Container entrypoint.

Runs the schema migration, then replaces this process with the API server or the
worker. Nothing is spawned as a child process: `os.execv` replaces the image of
the current process, so the container keeps a single PID and no shell is needed.
"""

from __future__ import annotations

import os
import sys
import time

_VENV_BIN = "/opt/venv/bin"


def _wait_for_database(attempts: int = 60, delay: float = 1.0) -> None:
    """Block until the database accepts a connection, so first boot is ordered."""
    import asyncio

    from sqlalchemy import text

    from app.core.db import dispose_engine, get_engine

    last_error: list[str] = []

    async def probe() -> bool:
        try:
            async with get_engine().connect() as connection:
                await connection.execute(text("SELECT 1"))
            return True
        except Exception as exc:
            last_error.clear()
            last_error.append(f"{type(exc).__name__}: {exc}")
            return False

    async def loop() -> None:
        for attempt in range(1, attempts + 1):
            if await probe():
                await dispose_engine()
                return
            await dispose_engine()
            if attempt == attempts:
                reason = last_error[0] if last_error else "no diagnostic available"
                print(
                    f"database did not become reachable in time ({reason})",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            await asyncio.sleep(delay)

    asyncio.run(loop())


def _migrate() -> None:
    from alembic import command
    from alembic.config import Config

    config = Config("/app/alembic.ini")
    config.set_main_option("script_location", "/app/migrations")
    command.upgrade(config, "head")


def _reset_admin(password: str | None) -> None:
    """Reset the first administrator so the configured credential works again."""
    import asyncio

    from app.core.db import dispose_engine, get_session_factory
    from app.services.auth import reset_bootstrap_admin

    async def run() -> None:
        factory = get_session_factory()
        async with factory() as session:
            try:
                outcome = await reset_bootstrap_admin(session, password)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                raise SystemExit(2) from exc
            await session.commit()
        await dispose_engine()
        print(
            f"The password of '{outcome.username}' has been reset to the configured value. "
            f"{outcome.sessions_revoked} session(s) were revoked."
        )
        if outcome.mfa_cleared:
            print("The two-factor enrolment and its recovery codes were removed.")
        if outcome.password_change_required:
            print("A password change is required at the next sign-in.")

    asyncio.run(run())


def _prune_plugins() -> None:
    """Delete stored configuration for plugins that no longer exist.

    Removing a plugin from a release leaves its configuration and its sealed
    credentials in the database. Startup only reports them, because a plugin
    that is merely failing to import would otherwise silently lose its keys.
    This command is the deliberate cleanup.
    """
    import asyncio

    from app.core.db import dispose_engine, get_session_factory
    from app.plugins import load_all
    from app.repositories import plugin_configs

    async def run() -> None:
        known = set(load_all())
        factory = get_session_factory()
        async with factory() as session:
            removed = await plugin_configs.prune(session, known)
            await session.commit()
        await dispose_engine()
        if removed:
            print("Removed the configuration and credentials of: " + ", ".join(sorted(removed)))
        else:
            print("Nothing to remove: every stored configuration matches a known plugin.")

    asyncio.run(run())


def _admin_password() -> None:
    """Print the first administrator's credential, once.

    The password is generated into the secrets volume on first boot, so it is
    never written in docker-compose.yml and never travels in an environment
    variable that `docker inspect` would show.
    """
    from app.core.config import get_settings

    settings = get_settings()
    if not settings.bootstrap_admin_password:
        print(
            "No bootstrap password is configured. Set XENOPROXY_ADMIN_PASSWORD, or let the "
            "stack generate one by starting it once.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    print(f"username: {settings.bootstrap_admin_username}")
    print(f"password: {settings.bootstrap_admin_password}")


def main() -> None:
    role = sys.argv[1] if len(sys.argv) > 1 else "api"

    if role == "admin-password":
        _admin_password()
        return

    if role in {"api", "worker", "reset-admin", "prune-plugins"}:
        _wait_for_database()

    if role == "reset-admin":
        _reset_admin(sys.argv[2] if len(sys.argv) > 2 else None)
        return

    if role == "prune-plugins":
        _prune_plugins()
        return

    if role == "api":
        # Only the API applies migrations, so concurrent workers never race on them.
        _migrate()
        os.execv(
            f"{_VENV_BIN}/uvicorn",
            [
                "uvicorn",
                "app.main:app",
                "--host",
                "0.0.0.0",  # noqa: S104 - published only to the proxy network
                "--port",
                "8000",
                "--proxy-headers",
                "--forwarded-allow-ips",
                "*",
                "--no-server-header",
                "--timeout-keep-alive",
                "20",
            ],
        )

    if role == "worker":
        # Give the API a moment to finish the migration on a cold start.
        time.sleep(3)
        os.execv(f"{_VENV_BIN}/arq", ["arq", "app.worker.WorkerSettings"])

    if role == "migrate":
        _migrate()
        return

    print(
        f"unknown command: {role} (expected api, worker, migrate, reset-admin or prune-plugins)",
        file=sys.stderr,
    )
    raise SystemExit(2)


if __name__ == "__main__":
    main()
