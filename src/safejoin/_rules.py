"""Per-part checks that need no filesystem: NUL bytes, rooted parts and Windows names."""

from __future__ import annotations

import ntpath
import os
import posixpath
import sys
import unicodedata

from ._errors import AbsolutePartError, InvalidPartError

_DEVICE_BASES = ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$")
_DEVICE_NUMBERED = tuple(
    f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "0123456789\u00b9\u00b2\u00b3"
)
RESERVED_NAMES = frozenset(_DEVICE_BASES + _DEVICE_NUMBERED)
"""Names Windows maps to devices, compared case-insensitively after trimming."""

_FORBIDDEN = frozenset('<>:"|?*') | frozenset(chr(code) for code in range(32))
# Characters that Windows best-fit code page conversion (WideCharToMultiByte without
# WC_NO_BEST_FIT_CHARS) turns into "/", "\" or ":" in at least one common ANSI or OEM
# code page, measured against the OS: yen and won signs, acute accent (cp1253),
# Armenian full stop, fraction and division slashes, set minus and ratio. A program
# that later passes the name through a narrow "A" API would see a separator.
_BEST_FIT_SEPARATORS = frozenset("\u00a5\u00b4\u0589\u2044\u20a9\u2215\u2216\u2236")
_NORMALISED_DANGER = frozenset('/\\:<>"|?*')


def windows_rules_default(windows_rules: bool | None) -> bool:
    """Resolve ``None`` to the platform default: on for Windows, off elsewhere."""
    if windows_rules is None:
        return sys.platform == "win32"
    return windows_rules


def split_components(part: str, windows: bool) -> list[str]:
    """Split a part on ``/`` and, under Windows rules or on Windows, on ``\\``."""
    if windows or os.sep == "\\":
        part = part.replace("\\", "/")
    return part.split("/")


def is_rooted(part: str, windows: bool) -> bool:
    """True when the part carries its own anchor on this platform or under Windows rules."""
    if posixpath.isabs(part):
        return True
    if windows or os.sep == "\\":
        drive, rest = ntpath.splitdrive(part)
        return bool(drive) or rest.startswith(("/", "\\"))
    return False


def _reserved(component: str) -> bool:
    stem = component.split(".", 1)[0].rstrip(" ")
    return stem.upper() in RESERVED_NAMES


def _windows_problem(component: str) -> str | None:
    """Return why a single component breaks Windows naming rules, or ``None``."""
    if component in ("", ".", ".."):
        return None
    bad = sorted(set(component) & _FORBIDDEN)
    if bad:
        return f"holds a character Windows forbids in names: {bad[0]!r}"
    if component[-1] in ". ":
        return "ends with a dot or a space, which Windows silently strips"
    if _reserved(component):
        return "is a Windows device name"
    if set(component) & _BEST_FIT_SEPARATORS:
        return "holds a character that code page conversion turns into a separator"
    folded = unicodedata.normalize("NFKC", component)
    if folded == component:
        return None
    if set(folded) & _NORMALISED_DANGER or folded.strip(". ") == "" or _reserved(folded):
        return "holds look-alike characters that normalise to a separator, dot or device name"
    return None


def check_part(part: str | os.PathLike[str], *, windows_rules: bool | None = None) -> None:
    """Validate one untrusted part without touching the filesystem.

    Raises ``InvalidPartError`` for a NUL byte, ``AbsolutePartError`` for a part that
    is absolute or rooted (``/etc``, ``C:\\x``, ``C:x``, ``\\\\host\\share``,
    ``\\\\?\\...``), and, when Windows rules apply, ``InvalidPartError`` for any
    component that is a device name, an alternate data stream, ends in a dot or a
    space, or holds a forbidden or look-alike character. ``..`` is not refused here:
    it is legal inside the base and ``safe_join`` decides where it lands.
    """
    text = os.fspath(part)
    if not isinstance(text, str):
        raise TypeError(f"parts must be str or os.PathLike[str], not {type(text).__name__}")
    if "\x00" in text:
        raise InvalidPartError(f"untrusted part {text!r} holds a NUL byte", part=text)
    windows = windows_rules_default(windows_rules)
    if is_rooted(text, windows):
        raise AbsolutePartError(f"untrusted part {text!r} is absolute or rooted", part=text)
    if not windows:
        return
    for component in split_components(text, True):
        problem = _windows_problem(component)
        if problem is not None:
            raise InvalidPartError(
                f"untrusted part {text!r}: component {component!r} {problem}", part=text
            )
