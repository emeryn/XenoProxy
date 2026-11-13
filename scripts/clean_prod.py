"""Pre-production cleanup. Run it only after a human has validated the release.

Removes development artefacts, then fails if a secret is found in the working
tree, in the git history or in a built image. It never pushes anything.

    python scripts/clean_prod.py [--yes]

Written in Python rather than shell so it behaves identically on Windows and
Linux.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess  # noqa: S404 - this is a developer tool, not the running service
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ARTEFACTS = (
    "frontend/dist",
    "frontend/playwright-report",
    "frontend/test-results",
    "backend/.pytest_cache",
    "backend/.ruff_cache",
    "backend/.mypy_cache",
    "backend/htmlcov",
    "backend/.coverage",
)

DEBUG_PATTERN = re.compile(r"(?:^|[^\w])(breakpoint\(\)|pdb\.set_trace\(\)|console\.(log|debug)\()")
DATA_SUFFIXES = {".sqlite", ".db", ".dump"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".ruff_cache"}

failures: list[str] = []


def step(title: str) -> None:
    print(f"\n== {title}")


def note(message: str) -> None:
    print(f"   {message}")


def fail(message: str) -> None:
    failures.append(message)
    print(f"   FAIL: {message}")


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argument list, no shell
        command, cwd=ROOT, capture_output=True, text=True, check=False
    )


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def walk_sources() -> list[Path]:
    files: list[Path] = []
    for base in ("backend/app", "frontend/src", "scripts"):
        root = ROOT / base
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and not SKIP_DIRS.intersection(path.parts):
                files.append(path)
    return files


def remove_artefacts() -> None:
    step("Removing build and test artefacts")
    for relative in ARTEFACTS:
        target = ROOT / relative
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
            note(f"removed {relative}")
        elif target.is_file():
            target.unlink(missing_ok=True)
            note(f"removed {relative}")

    removed = 0
    for cache in ROOT.rglob("__pycache__"):
        if ".git" in cache.parts:
            continue
        shutil.rmtree(cache, ignore_errors=True)
        removed += 1
    if removed:
        note(f"removed {removed} __pycache__ directories")


def check_local_data() -> None:
    step("Checking for local databases and dumps")
    for path in ROOT.rglob("*"):
        if not path.is_file() or SKIP_DIRS.intersection(path.parts):
            continue
        if path.suffix in DATA_SUFFIXES:
            fail(f"local data file present: {path.relative_to(ROOT)}")


def check_debug_statements() -> None:
    step("Checking for debug statements")
    for path in walk_sources():
        if path.suffix not in {".py", ".ts", ".tsx"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(content.splitlines(), start=1):
            if "console.error" in line:
                continue
            if DEBUG_PATTERN.search(line):
                fail(f"debug statement at {path.relative_to(ROOT)}:{number}: {line.strip()[:80]}")


def check_ai_context_untracked() -> None:
    step("Checking that AI context files are not tracked")
    if run(["git", "rev-parse", "--git-dir"]).returncode != 0:
        note("not a git repository, skipping tracked-file checks")
        return
    for candidate in ("CLAUDE.md", ".claude", ".cursor"):
        if run(["git", "ls-files", "--error-unmatch", candidate]).returncode == 0:
            fail(f"{candidate} is tracked by git; it must stay out of the repository")


def check_ignore_files() -> None:
    step("Checking ignore files")
    pairs = (
        (".gitignore", (".env", "CLAUDE.md", "*.key")),
        (".dockerignore", (".env", "CLAUDE.md")),
    )
    for filename, patterns in pairs:
        path = ROOT / filename
        content = path.read_text(encoding="utf-8") if path.is_file() else ""
        for pattern in patterns:
            if pattern not in content:
                fail(f"{filename} does not cover {pattern}")


def scan_secrets() -> None:
    step("Scanning for secrets")
    if not tool_available("gitleaks"):
        fail("gitleaks is not installed; install it before releasing")
        return
    tree = run(["gitleaks", "detect", "--no-git", "--redact", "--exit-code", "1", "--source", "."])
    if tree.returncode != 0:
        fail("gitleaks found secrets in the working tree")
    if run(["git", "rev-parse", "--git-dir"]).returncode == 0:
        history = run(["gitleaks", "detect", "--redact", "--exit-code", "1", "--source", "."])
        if history.returncode != 0:
            fail("gitleaks found secrets in the git history")


def scan_images() -> None:
    step("Checking the built images for secrets")
    if not tool_available("trivy"):
        note("trivy is not installed; image secret scan skipped")
        return
    for image in ("xenoproxy/backend:0.1.0", "xenoproxy/frontend:0.1.0"):
        result = run(
            ["trivy", "image", "--scanners", "secret", "--exit-code", "1", "--quiet", image]
        )
        if result.returncode != 0:
            fail(f"secret found in {image}")


def main() -> int:
    parser = argparse.ArgumentParser(description="XenoProxy pre-production cleanup")
    parser.add_argument(
        "--yes", action="store_true", help="skip the confirmation prompt"
    )
    arguments = parser.parse_args()

    print("XenoProxy pre-production cleanup")
    print(f"Working directory: {ROOT}")

    if not arguments.yes:
        answer = input("\n   This deletes local development artefacts. Continue? [y/N] ")
        if answer.strip().lower() != "y":
            print("   Aborted.")
            return 1

    remove_artefacts()
    check_local_data()
    check_debug_statements()
    check_ai_context_untracked()
    check_ignore_files()
    scan_secrets()
    scan_images()

    print()
    if failures:
        print(f"Cleanup finished with {len(failures)} blocking finding(s). Fix them before releasing.")
        return 1
    print("Cleanup finished with no blocking finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
