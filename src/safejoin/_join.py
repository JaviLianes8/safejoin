"""Join a trusted base with untrusted parts, refusing any result that escapes it."""

from __future__ import annotations

import os
from pathlib import Path, PurePath
from typing import Union

from ._errors import UnsafePathError

StrPath = Union[str, "os.PathLike[str]"]


def _normalize(path: Path, resolve: bool) -> Path:
    """Return an absolute path: symlink-resolved when resolve, lexical otherwise."""
    if resolve:
        return path.resolve()
    return Path(os.path.abspath(path))


def _is_rooted(part: PurePath) -> bool:
    """True when a part carries its own anchor (absolute, a drive, or a root)."""
    return part.is_absolute() or bool(part.drive) or bool(part.root)


def _contains(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
    except ValueError:
        return False
    return True


def is_within(base: StrPath, target: StrPath, *, resolve: bool = True) -> bool:
    """Report whether target lies inside base once both are normalized.

    With resolve, symlinks are followed before the check; without it, the
    comparison is purely lexical and never touches the filesystem.
    """
    safe_base = _normalize(Path(os.fspath(base)), resolve)
    safe_target = _normalize(Path(os.fspath(target)), resolve)
    return _contains(safe_base, safe_target)


def safe_join(base: StrPath, *parts: StrPath, resolve: bool = True) -> Path:
    """Join untrusted parts onto a trusted base and return the safe absolute path.

    Raises UnsafePathError when a part is absolute or rooted (including a drive
    change on Windows), or when the combined path would escape base through ``..``
    or, with resolve, a symlink that points outside base.
    """
    base_path = Path(os.fspath(base))
    for part in parts:
        if _is_rooted(PurePath(os.fspath(part))):
            raise UnsafePathError(f"untrusted part {part!r} is absolute or rooted")
    candidate = base_path.joinpath(*(os.fspath(part) for part in parts))
    safe_base = _normalize(base_path, resolve)
    safe_candidate = _normalize(candidate, resolve)
    if not _contains(safe_base, safe_candidate):
        raise UnsafePathError(f"joined path {safe_candidate} escapes base {safe_base}")
    return safe_candidate
