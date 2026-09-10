"""Filesystem checks applied to EVERY mailgate-owned path.

The original design applied ownership/symlink/mode checks to the config file only.
The audit directory, the log file and the SQLite state are all pre-creatable as
symlinks by an agent running as the same user, so they get the same treatment.
"""
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import stat
from pathlib import Path

from ..errors import ConfigError


def check_secure_path(path: Path, *, want_dir: bool = False, mode_max: int = 0o600) -> Path:
    """Refuse a path that another process could have substituted or could write.

    Checks: not a symlink, owned by us, no group/world write, and no
    world-writable-without-sticky parent up to the filesystem root.
    """
    p = Path(path)
    if p.is_symlink():
        raise ConfigError(f"{p} is a symlink; refusing", code="insecure_path")
    if not p.exists():
        raise ConfigError(f"{p} does not exist", code="missing_path")
    st = p.lstat()
    if want_dir and not stat.S_ISDIR(st.st_mode):
        raise ConfigError(f"{p} is not a directory", code="insecure_path")
    if not want_dir and not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"{p} is not a regular file", code="insecure_path")
    if st.st_uid != os.getuid():
        raise ConfigError(f"{p} is not owned by uid {os.getuid()}", code="insecure_path")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigError(
            f"{p} is group- or world-writable (mode {oct(stat.S_IMODE(st.st_mode))})",
            code="insecure_path",
        )
    if not want_dir and stat.S_IMODE(st.st_mode) & ~mode_max:
        raise ConfigError(
            f"{p} mode {oct(stat.S_IMODE(st.st_mode))} exceeds {oct(mode_max)}",
            code="insecure_path",
        )
    for parent in p.resolve().parents:
        pst = parent.stat()
        if pst.st_mode & stat.S_IWOTH and not pst.st_mode & stat.S_ISVTX:
            raise ConfigError(
                f"parent {parent} is world-writable without the sticky bit",
                code="insecure_path",
            )
    return p


def secure_mkdir(path: Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    if p.is_symlink():
        raise ConfigError(f"{p} is a symlink; refusing", code="insecure_path")
    os.chmod(p, 0o700)
    return check_secure_path(p, want_dir=True)


def open_append_nofollow(path: Path) -> int:
    """Open (creating) an 0600 file for append, refusing to follow a symlink."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    st = os.fstat(fd)
    if st.st_uid != os.getuid() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        os.close(fd)
        raise ConfigError(f"{path} has unsafe ownership or mode", code="insecure_path")
    return fd
