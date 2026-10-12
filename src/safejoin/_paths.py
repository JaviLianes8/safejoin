"""Low-level path helpers: canonical comparison, containment and link inspection."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ._errors import InvalidPartError, SymlinkError, TraversalError

# Reparse tags with this bit set are name surrogates: symlinks and junctions (mount
# points). Other reparse points, such as cloud placeholders, are ordinary files.
_NAME_SURROGATE = 0x20000000
# ERROR_INVALID_NAME and ERROR_BAD_PATHNAME: Windows refuses the name itself.
INVALID_NAME_ERRORS = (123, 161)


def canonical(path: Path) -> Path:
    """Drop a Win32 extended-length prefix so the same location compares equal."""
    text = str(path)
    if text.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + text[8:])
    if text.startswith("\\\\?\\") and len(text) >= 6 and text[5] == ":":
        return Path(text[4:])
    return path


def relative_inside(base: Path, target: Path) -> tuple[str, ...] | None:
    """Return target's components below base, or ``None`` when it is not inside.

    The comparison is lexical on already-normalised paths, case-insensitive on
    Windows, and any leftover ``..`` component counts as outside.
    """
    try:
        rel = canonical(target).relative_to(canonical(base))
    except ValueError:
        return None
    if ".." in rel.parts:
        return None
    return rel.parts


def contains(base: Path, target: Path) -> bool:
    """True when target equals base or lies below it."""
    return relative_inside(base, target) is not None


def absolute(path: Path) -> Path:
    """Lexically absolute and normalised: ``..`` collapsed, filesystem untouched."""
    return Path(os.path.abspath(path))


def resolved(path: Path, part: str | None = None) -> Path:
    """``Path.resolve()`` with loops and resolution failures reported as SymlinkError."""
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        raise SymlinkError(f"cannot resolve {path}: {exc}", part=part) from exc


def is_link(info: os.stat_result) -> bool:
    """True for a symlink, or on Windows a junction or other name-surrogate reparse point."""
    if stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, "st_reparse_tag", 0) & _NAME_SURROGATE)


def lstat_or_none(path: Path, part: str | None = None) -> os.stat_result | None:
    """``lstat`` that returns ``None`` for a missing path and raises typed errors.

    A name Windows refuses raises ``InvalidPartError``; any other failure to inspect
    an existing path raises ``SymlinkError``, because the path cannot be verified.
    """
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        if getattr(exc, "winerror", None) in INVALID_NAME_ERRORS:
            raise InvalidPartError(f"{path} is not a valid name", part=part) from exc
        raise SymlinkError(f"cannot inspect {path}: {exc}", part=part) from exc


def first_link_below(base: Path, target: Path, part: str | None = None) -> Path | None:
    """Return the first existing component strictly below base that is a link.

    Components are checked with ``lstat`` from the base down and the walk stops at
    the first one that does not exist.
    """
    parts = relative_inside(base, target)
    if parts is None:
        raise TraversalError(f"path {target} is not inside base {base}", part=part)
    current = canonical(base)
    for name in parts:
        current = current / name
        info = lstat_or_none(current, part)
        if info is None:
            return None
        if is_link(info):
            return current
    return None


def first_link_as_written(base: Path, names: list[str], part: str | None = None) -> Path | None:
    """Like ``first_link_below`` but over components as written, ``..`` included.

    ``lnk/../x`` checks ``lnk`` before stepping back, so a link that is only passed
    through still counts. Missing components are skipped, not a stopping point.
    """
    current = canonical(base)
    for name in names:
        if name in ("", "."):
            continue
        if name == "..":
            current = current.parent
            continue
        current = current / name
        info = lstat_or_none(current, part)
        if info is not None and is_link(info):
            return current
    return None
