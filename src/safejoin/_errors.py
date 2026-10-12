"""The exceptions the package raises, all subclasses of ``UnsafePathError``."""

from __future__ import annotations


class UnsafePathError(ValueError):
    """Raised when an untrusted path would be unsafe to use under its trusted base.

    ``part`` is the untrusted input that caused the refusal (``None`` when no single
    part is to blame, for example a NUL byte in the base) and ``reason`` is a short
    machine-readable tag such as ``"absolute"`` or ``"escape"``.
    """

    reason: str = "unsafe"

    def __init__(self, message: str, *, part: str | None = None) -> None:
        super().__init__(message)
        self.part = part


class AbsolutePartError(UnsafePathError):
    """An untrusted part is absolute or rooted: ``/etc``, ``C:\\``, ``C:foo``, ``\\\\host``."""

    reason = "absolute"


class TraversalError(UnsafePathError):
    """The joined path would leave the base, through ``..`` or a link."""

    reason = "escape"


class InvalidPartError(UnsafePathError):
    """A part holds something no safe name may hold.

    Examples are a NUL byte, a Windows device name such as ``CON``, an alternate data
    stream such as ``file.txt:stream``, or a look-alike of a separator.
    """

    reason = "invalid"


class SymlinkError(UnsafePathError):
    """A symlink or junction was refused by policy, could not be verified, or loops."""

    reason = "symlink"
