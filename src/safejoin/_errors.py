"""The single exception the package raises."""

from __future__ import annotations


class UnsafePathError(ValueError):
    """Raised when an untrusted path would resolve outside its trusted base."""
