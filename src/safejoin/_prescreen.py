"""Follow links below the base without ever opening what they point at.

``Path.resolve()`` on Windows opens each reparse point it meets. A link planted in the
base that points at a named pipe or a remote share would make the resolve itself
connect there, before any containment check runs. This walk reads link targets with
``readlink`` (which opens only the link) and refuses any target outside the base, so
by the time ``resolve()`` runs, every link it can meet stays inside.
"""

from __future__ import annotations

import ntpath
import os
from pathlib import Path

from ._errors import InvalidPartError, SymlinkError, TraversalError
from ._paths import INVALID_NAME_ERRORS, absolute, canonical, is_link, relative_inside

_MAX_HOPS = 40


def _disk_path(target: str) -> str | None:
    """Return a Win32 disk path for a link target, or ``None`` for a device target."""
    if target.startswith("\\??\\"):
        target = "\\\\?\\" + target[4:]
    if target.startswith("\\\\.\\"):
        return None
    if target.startswith("\\\\?\\"):
        rest = target[4:]
        if rest[1:2] == ":":
            return rest
        if rest[:4].upper() == "UNC\\":
            return "\\\\" + rest[4:]
        return None
    return target


def _landing(link: Path, target: str) -> Path | None:
    """Where a link points, lexically, or ``None`` when it names a device."""
    disk = _disk_path(target)
    if disk is None:
        return None
    drive, rest = ntpath.splitdrive(disk)
    if drive or rest.startswith(("\\", "/")):
        return canonical(absolute(Path(disk)))
    return canonical(absolute(link.parent / disk))


def prescreen(base: Path, safe_base: Path, names: tuple[str, ...], part: str | None) -> None:
    """Walk ``names`` from ``base``, replacing each link by its target, all lexically.

    Raises ``TraversalError`` when a link points outside the base (lexical or
    resolved), ``SymlinkError`` for a device target or too many hops, and
    ``InvalidPartError`` for a name Windows refuses.
    """
    root = canonical(absolute(base))
    bases = (root, canonical(safe_base))
    pending, current, hops = list(names), root, 0
    while pending:
        name = pending.pop(0)
        if name in ("", "."):
            continue
        if name == "..":
            if current == root:
                raise TraversalError(f"a link below {root} climbs out of it", part=part)
            current = current.parent
            continue
        step = current / name
        try:
            info = os.lstat(step)
        except (FileNotFoundError, NotADirectoryError):
            current = step
            continue
        except OSError as exc:
            if getattr(exc, "winerror", None) in INVALID_NAME_ERRORS:
                raise InvalidPartError(f"{step} is not a valid name", part=part) from exc
            raise SymlinkError(f"cannot inspect {step}: {exc}", part=part) from exc
        if not is_link(info):
            current = step
            continue
        hops += 1
        if hops > _MAX_HOPS:
            raise SymlinkError(f"too many links below {root} (a loop?)", part=part)
        landing = _landing(step, os.readlink(step))
        if landing is None:
            raise SymlinkError(f"link {step} points at a device, not a file", part=part)
        for anchor in bases:
            inside = relative_inside(anchor, landing)
            if inside is not None:
                pending, current = list(inside) + pending, root
                break
        else:
            raise TraversalError(f"link {step} points outside the base at {landing}", part=part)
