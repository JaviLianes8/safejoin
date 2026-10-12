"""Validate zip and tar member names and link targets before anything is extracted."""

from __future__ import annotations

from pathlib import Path

from ._errors import AbsolutePartError, InvalidPartError, TraversalError
from ._join import StrPath, SymlinkPolicy, safe_join
from ._paths import contains, first_link_below, resolved
from ._rules import check_part, is_rooted, plain_text


def _screen(value: object, what: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{what} must be str, not {type(value).__name__}")
    text = str.__str__(value)
    if "\x00" in text:
        raise InvalidPartError(f"{what} {text!r} holds a NUL byte", part=text)
    if is_rooted(text, True):
        raise AbsolutePartError(f"{what} {text!r} is absolute or rooted", part=text)
    return text


def _components(text: str) -> list[str]:
    pieces = [piece for piece in text.replace("\\", "/").split("/") if piece not in ("", ".")]
    for piece in pieces:
        if piece != "..":
            check_part(piece, windows_rules=True)
    return pieces


def member_parts(name: str) -> tuple[str, ...]:
    """Validate an archive member name and return its safe relative components.

    The rules are the same on every platform, because an archive made on one system
    is extracted on another: ``\\`` counts as a separator, absolute names, drives,
    UNC and device paths are refused, any ``..`` component is refused, and Windows
    naming rules always apply. Empty and ``.`` components are dropped; a name with no
    components left (``""``, ``"./"``) is refused. Raises ``UnsafePathError``
    subclasses that name the member.
    """
    text = _screen(name, "member name")
    try:
        pieces = _components(text)
    except InvalidPartError as exc:
        raise InvalidPartError(f"member name {text!r}: {exc}", part=text) from exc
    if ".." in pieces:
        raise TraversalError(f"member name {text!r} holds a '..' component", part=text)
    if not pieces:
        raise InvalidPartError(f"member name {text!r} names no file", part=text)
    return tuple(pieces)


def safe_member_path(
    base: StrPath, name: str, *, resolve: bool = True, symlinks: SymlinkPolicy = "allow_inside"
) -> Path:
    """Return where member ``name`` may be extracted under ``base``, or raise.

    ``member_parts(name)`` then ``safe_join`` with Windows rules on, so a link created
    on disk by an earlier member is followed and checked too.
    """
    return safe_join(
        base, *member_parts(name), resolve=resolve, symlinks=symlinks, windows_rules=True
    )


def link_target_parts(member_name: str, target: str, *, hard: bool = False) -> tuple[str, ...]:
    """Validate a tar link target without the filesystem; return it from the archive root.

    A symlink target is relative to the member's directory and a hard link target
    (``hard=True``) is relative to the archive root, as in tar. The target must not be
    absolute, and ``..`` is allowed only as a leading run that stays inside the
    archive: ``a/..`` is refused because if ``a`` is itself a link the OS would climb
    from its target, not from ``a``. An empty result means the archive root and is
    refused for hard links. Use ``safe_link_target`` at extraction time as well.
    """
    member = member_parts(member_name)
    text = _screen(target, "link target")
    try:
        pieces = _components(text)
    except InvalidPartError as exc:
        raise InvalidPartError(f"link target {text!r}: {exc}", part=text) from exc
    stack = [] if hard else list(member[:-1])
    seen_name = False
    for piece in pieces:
        if piece != "..":
            seen_name = True
            stack.append(piece)
        elif seen_name or not stack:
            raise TraversalError(
                f"link target {text!r} of {member_name!r} climbs out of the archive", part=text
            )
        else:
            stack.pop()
    if hard and not stack:
        raise InvalidPartError(f"hard link target {text!r} names no file", part=text)
    return tuple(stack)


def safe_link_target(base: StrPath, member_name: str, target: str, *, hard: bool = False) -> Path:
    """Check a link target against what is already on disk and return where it points.

    Runs ``link_target_parts`` first, then resolves the target from the real,
    resolved location of the member's directory (or of ``base`` for a hard link), the
    way PEP 706's ``data`` filter does, and refuses it unless it lands inside the
    resolved base with no unresolved link left below it.
    """
    member_name, target = _screen(member_name, "member name"), _screen(target, "link target")
    link_target_parts(member_name, target, hard=hard)
    base_text = plain_text(base, "base")
    safe_base = resolved(Path(base_text))
    member = member_parts(member_name)
    if hard or len(member) == 1:
        start = safe_base
    else:
        start = safe_join(base_text, *member[:-1], windows_rules=True)
    landing = resolved(start / target.replace("\\", "/"), target)
    if not contains(safe_base, landing):
        raise TraversalError(
            f"link target {target!r} lands at {landing}, outside base", part=target
        )
    if first_link_below(safe_base, landing, target) is not None:
        raise TraversalError(f"link target {target!r} could not be fully resolved", part=target)
    return landing
