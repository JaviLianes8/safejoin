"""Open a file inside a base so that a link swapped in after the check cannot win."""

from __future__ import annotations

import codecs
import errno
import os
import stat
import sys
from pathlib import Path
from typing import IO, Any

from ._errors import InvalidPartError, SymlinkError, TraversalError
from ._join import StrPath, SymlinkPolicy, safe_join
from ._paths import canonical, relative_inside, resolved
from ._rules import plain_text

_LINK_ERRNOS = (errno.ELOOP, errno.EMLINK)


def _flags(mode: str) -> tuple[int, str, bool]:
    """Translate an ``open()`` mode into OS flags, an ``fdopen`` mode and a truncate flag."""
    kinds = [char for char in mode if char in "rwax"]
    if len(kinds) != 1 or len(set(mode)) != len(mode) or set(mode) - set("rwax+bt"):
        raise ValueError(f"invalid mode: {mode!r}")
    if "b" in mode and "t" in mode:
        raise ValueError(f"invalid mode: {mode!r}")
    kind, plus = kinds[0], "+" in mode
    access = os.O_RDWR if plus else (os.O_RDONLY if kind == "r" else os.O_WRONLY)
    extra = {"r": 0, "w": os.O_CREAT, "a": os.O_CREAT | os.O_APPEND, "x": os.O_CREAT | os.O_EXCL}
    view = {"r": "r", "w": "w", "a": "a", "x": "w"}[kind] + ("+" if plus else "")
    return access | extra[kind], view + ("b" if "b" in mode else ""), kind == "w"


def _check_text_args(
    view: str, encoding: str | None, errors: str | None, newline: str | None
) -> None:
    """Fail before any file is touched, so ``fdopen`` cannot fail after taking the fd."""
    if "b" in view and (encoding, errors, newline) != (None, None, None):
        raise ValueError("binary mode does not take encoding, errors or newline")
    if encoding is not None:
        codecs.lookup(encoding)
    if errors is not None:
        codecs.lookup_error(errors)
    if newline not in (None, "", "\n", "\r", "\r\n"):
        raise ValueError(f"illegal newline value: {newline!r}")


def _require_regular(fd: int, path: Path, part: str | None) -> None:
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise InvalidPartError(f"{path} is not a regular file", part=part)


if sys.platform == "win32":
    from ._winfinal import final_path

    def _platform_open(
        safe_base: Path, path: Path, flags: int, perms: int, policy: str, part: str | None
    ) -> int:
        fd = os.open(path, flags | os.O_NOINHERIT | os.O_BINARY, perms)
        try:
            final = Path(final_path(fd))
            if relative_inside(safe_base, final) is None:
                raise TraversalError(f"opened file {final} is outside base {safe_base}", part=part)
            same = os.path.normcase(canonical(final)) == os.path.normcase(canonical(path))
            if policy == "deny" and not same:
                raise SymlinkError(f"{path} was reached through a link", part=part)
            _require_regular(fd, path, part)
        except BaseException:
            os.close(fd)
            raise
        return fd

else:

    def _step(name: str, flags: int, perms: int, dir_fd: int, part: str | None) -> int:
        try:
            return os.open(name, flags, perms, dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                raise InvalidPartError(f"{name!r} is not a regular file", part=part) from exc
            if exc.errno in _LINK_ERRNOS:
                raise SymlinkError(f"{name!r} is a symlink", part=part) from exc
            if exc.errno == errno.ENOTDIR:
                try:
                    is_link = stat.S_ISLNK(os.lstat(name, dir_fd=dir_fd).st_mode)
                except FileNotFoundError:
                    is_link = True  # it changed under us: treat as a swap
                if is_link:
                    raise SymlinkError(f"{name!r} changed while opening", part=part) from exc
            raise

    def _platform_open(
        safe_base: Path, path: Path, flags: int, perms: int, policy: str, part: str | None
    ) -> int:
        names = relative_inside(safe_base, path) or ()
        walk = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(safe_base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in names[:-1]:
                inner = _step(name, walk, 0, fd, part)
                os.close(fd)
                fd = inner
            final = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            opened = _step(names[-1], flags | final, perms, fd, part)
        finally:
            os.close(fd)
        try:
            _require_regular(opened, path, part)
            os.set_blocking(opened, True)
        except BaseException:
            os.close(opened)
            raise
        return opened


def safe_open(
    base: StrPath,
    *parts: StrPath,
    mode: str = "r",
    buffering: int = -1,
    encoding: str | None = None,
    errors: str | None = None,
    newline: str | None = None,
    symlinks: SymlinkPolicy = "allow_inside",
    windows_rules: bool | None = None,
    permissions: int = 0o666,
) -> IO[Any]:
    """Open a regular file inside base, the way ``open()`` would, with no swap window.

    The path is first validated with ``safe_join`` (same ``symlinks`` and
    ``windows_rules``). Then:

    * on POSIX the file is opened by walking from a descriptor of the resolved base
      with ``O_NOFOLLOW`` on every component, so a symlink planted after the check
      makes the call fail with ``SymlinkError`` instead of escaping;
    * on Windows the file is opened and the OS is asked for the final path of the
      handle; a handle outside the base is closed and refused. Truncation for ``"w"``
      happens only after that check. An attacker who swaps a junction in between the
      check and the open can still make the open itself reach the junction's target
      (leave an empty file there, or connect to a named pipe) before it is refused;
      no content outside the base is read, written or truncated through it.

    Only regular files are opened, so a FIFO or device planted in the base is refused
    with ``InvalidPartError``. Write modes refuse a file with more than one hard link,
    because its other names may live outside the base; reads through a hard link are
    not detected. Missing parent directories are not created. ``mode``
    accepts ``r``, ``w``, ``a`` or ``x`` with optional ``+`` and ``b`` or ``t``.
    """
    flags, view, truncate = _flags(mode)
    _check_text_args(view, encoding, errors, newline)
    base_text = plain_text(base, "base")
    texts = [plain_text(item, "parts") for item in parts]
    path = safe_join(base_text, *texts, symlinks=symlinks, windows_rules=windows_rules)
    part = texts[-1] if texts else None
    safe_base = resolved(Path(base_text))
    if not relative_inside(safe_base, path):
        raise InvalidPartError(f"{path} is the base directory itself, not a file", part=part)
    if path.is_dir():
        raise InvalidPartError(f"{path} is a directory, not a file", part=part)
    fd = _platform_open(safe_base, path, flags, permissions, symlinks, part)
    try:
        if flags & (os.O_WRONLY | os.O_RDWR) and os.fstat(fd).st_nlink > 1:
            raise InvalidPartError(f"{path} has other hard links; refusing to write", part=part)
        if truncate:
            os.ftruncate(fd, 0)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, view, buffering, encoding, errors, newline)
