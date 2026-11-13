"""In-process execution guard.

The containers ship without a shell, compiler or package manager, so there is
nothing to execute. This guard is the second layer: it refuses process creation
from inside the interpreter after startup, which turns a code-execution finding
in a dependency into a failed call instead of a shell.

A container-wide seccomp deny on `execve` would stop the entrypoint itself, so the
filter is installed here, once the interpreter is already running. `libseccomp` is
used when present; the audit hook is always installed and is what makes the guard
portable.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

_BLOCKED_EVENTS = (
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.fork",
    "os.forkpty",
    "pty.spawn",
)

_installed = False


class ExecutionBlockedError(PermissionError):
    """Raised when code attempts to start a process."""


def _audit(event: str, _args: tuple[Any, ...]) -> None:
    if event.startswith(_BLOCKED_EVENTS):
        raise ExecutionBlockedError(f"process creation is disabled in this service ({event})")


def _load_libseccomp() -> ctypes.CDLL | None:
    """Open libseccomp, by name or by soname.

    `find_library` shells out to `ldconfig`, `gcc` or `objdump`, none of which a
    runtime image has, and it looks for the `libseccomp.so` symlink that only
    the development package ships. Falling back to the versioned soname is what
    makes the filter load on a minimal image rather than silently doing nothing.
    """
    candidates = (ctypes.util.find_library("seccomp"), "libseccomp.so.2", "libseccomp.so")
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return ctypes.CDLL(candidate, use_errno=True)
        except OSError:
            continue
    return None


def _install_seccomp() -> bool:
    """Install a seccomp filter denying execve and execveat, when libseccomp is present."""
    libseccomp = _load_libseccomp()
    if libseccomp is None:
        return False

    scmp_act_allow = 0x7FFF0000
    scmp_act_errno = 0x00050000 | 1  # EPERM

    libseccomp.seccomp_init.restype = ctypes.c_void_p
    context = libseccomp.seccomp_init(ctypes.c_uint32(scmp_act_allow))
    if not context:
        return False
    try:
        libseccomp.seccomp_rule_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        for syscall_name in (b"execve", b"execveat"):
            libseccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
            syscall = libseccomp.seccomp_syscall_resolve_name(syscall_name)
            if syscall < 0:
                continue
            libseccomp.seccomp_rule_add(
                ctypes.c_void_p(context), ctypes.c_uint32(scmp_act_errno), syscall, 0
            )
        return libseccomp.seccomp_load(ctypes.c_void_p(context)) == 0
    finally:
        libseccomp.seccomp_release(ctypes.c_void_p(context))


def install_exec_guard() -> None:
    """Install the execution guard. Safe to call more than once."""
    global _installed
    if _installed:
        return
    sys.addaudithook(_audit)
    seccomp_active = False
    if sys.platform.startswith("linux"):
        try:
            seccomp_active = _install_seccomp()
        except Exception as exc:
            logger.warning("seccomp_unavailable", error=str(exc))
    _installed = True
    logger.info("exec_guard_installed", seccomp=seccomp_active)
