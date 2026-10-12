"""Join a trusted base with untrusted parts, refusing any result that escapes it."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal, Union

from ._errors import InvalidPartError, SymlinkError, TraversalError
from ._paths import (
    absolute,
    contains,
    first_link_as_written,
    first_link_below,
    relative_inside,
    resolved,
)
from ._prescreen import prescreen
from ._rules import check_part, plain_text, split_components, windows_rules_default

StrPath = Union[str, "os.PathLike[str]"]
SymlinkPolicy = Literal["allow_inside", "deny"]
_POLICIES = ("allow_inside", "deny")
# Win32 device namespace: where GetFullPathName sends names such as NUL or CON.
_DEVICE_PREFIX = "\\\\.\\"


def _base_path(base: StrPath) -> Path:
    text = plain_text(base, "base")
    if "\x00" in text:
        raise InvalidPartError(f"base {text!r} holds a NUL byte")
    return Path(text)


def _check_depth(texts: list[str], windows: bool) -> None:
    """Refuse any ``..`` that would step above the base, even on the way back down."""
    depth = 0
    for text in texts:
        for component in split_components(text, windows):
            if component in ("", "."):
                continue
            depth = depth - 1 if component == ".." else depth + 1
            if depth < 0:
                raise TraversalError(f"untrusted part {text!r} climbs above the base", part=text)


def _settle(base: Path, safe_base: Path, path: Path, resolve: bool) -> Path:
    """Normalise one candidate and prove it is inside the base, or raise without a part.

    The lexical check runs in both modes: on Windows ``GetFullPathName`` maps names
    such as ``NUL`` to the device namespace, which ``resolve()`` alone can miss.
    """
    lexical = absolute(path)
    if not contains(absolute(base), lexical):
        raise TraversalError(f"joined path {lexical} escapes base {absolute(base)}")
    if resolve and sys.platform == "win32":
        prescreen(base, safe_base, relative_inside(absolute(base), lexical) or (), None)
    settled = resolved(path) if resolve else lexical
    if not contains(safe_base, settled):
        raise TraversalError(f"joined path {settled} escapes base {safe_base}")
    if resolve:
        left = first_link_below(safe_base, settled)
        if left is not None:
            raise SymlinkError(f"link {left} could not be resolved (a loop or an error)")
    return settled


def _culprit(base: Path, safe_base: Path, texts: list[str], resolve: bool) -> str | None:
    """Return the first part whose prefix fails ``_settle``, for the error report."""
    current = base
    for text in texts:
        current = current / text
        try:
            _settle(base, safe_base, current, resolve)
        except (TraversalError, SymlinkError, InvalidPartError):
            return text
    return texts[-1] if texts else None


def safe_join(
    base: StrPath,
    *parts: StrPath,
    resolve: bool = True,
    symlinks: SymlinkPolicy = "allow_inside",
    windows_rules: bool | None = None,
) -> Path:
    """Join untrusted parts onto a trusted base and return the safe absolute path.

    Every part is first checked with ``check_part`` (NUL bytes, absolute or rooted
    parts, and Windows naming rules when they apply). A ``..`` that would climb above
    the base is refused even if later parts come back down.

    With ``resolve=True`` (default) base and result are resolved with
    ``Path.resolve()``, so symlinks and junctions are followed, and the result is
    refused unless it lies inside the resolved base and no link is left unresolved
    below it. With ``resolve=False`` the check is lexical and never follows links.

    ``symlinks="deny"`` additionally refuses any existing symlink or junction below
    the base, wherever it points. ``windows_rules=None`` applies Windows rules only
    when running on Windows; pass ``True`` to enforce them everywhere.

    Raises ``AbsolutePartError``, ``TraversalError``, ``InvalidPartError`` or
    ``SymlinkError``, all subclasses of ``UnsafePathError``, naming the offending part.
    The result is only as fresh as the call: see ``safe_open`` for race-free opening.
    """
    if symlinks not in _POLICIES:
        raise ValueError(f"symlinks must be one of {_POLICIES}, not {symlinks!r}")
    base_path = _base_path(base)
    windows = windows_rules_default(windows_rules)
    texts = [plain_text(part, "parts") for part in parts]
    for text in texts:
        check_part(text, windows_rules=windows)
    _check_depth(texts, windows)
    candidate = base_path.joinpath(*texts)
    if symlinks == "deny":
        _deny_links(base_path, texts)
    safe_base = resolved(base_path) if resolve else absolute(base_path)
    try:
        return _settle(base_path, safe_base, candidate, resolve)
    except (TraversalError, SymlinkError, InvalidPartError) as exc:
        if exc.part is None:
            exc.part = _culprit(base_path, safe_base, texts, resolve)
        raise


def _deny_links(base: Path, texts: list[str]) -> None:
    """Refuse any existing link met while walking the parts as written, ``..`` included."""
    names: list[str] = []
    for text in texts:
        names += split_components(text, False)
        link = first_link_as_written(absolute(base), names, text)
        if link is not None:
            raise SymlinkError(f"link {link} is refused by symlinks='deny'", part=text)


def is_within(base: StrPath, target: StrPath, *, resolve: bool = True) -> bool:
    """Report whether target lies inside base (or is base) once both are normalised.

    With ``resolve=True`` symlinks and junctions are followed first, and a target
    that cannot be fully resolved (a loop, an unreadable component) is reported as
    outside. With ``resolve=False`` the comparison is lexical and never touches the
    filesystem. A NUL byte in either path makes the answer ``False``.
    """
    base_text, target_text = plain_text(base, "base"), plain_text(target, "target")
    if "\x00" in base_text or "\x00" in target_text:
        return False
    lexical = absolute(Path(target_text))
    if not resolve:
        return contains(absolute(Path(base_text)), lexical)
    if str(lexical).startswith(_DEVICE_PREFIX):
        return False
    try:
        safe_base = resolved(Path(base_text))
        names = relative_inside(absolute(Path(base_text)), lexical)
        if sys.platform == "win32" and names is not None:
            prescreen(Path(base_text), safe_base, names, None)
        safe_target = resolved(Path(target_text))
        if not contains(safe_base, safe_target):
            return False
        return first_link_below(safe_base, safe_target) is None
    except (SymlinkError, TraversalError, InvalidPartError):
        return False
