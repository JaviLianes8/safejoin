"""Path-traversal-safe joining of a trusted base directory with untrusted relative parts."""

from __future__ import annotations

from ._errors import UnsafePathError
from ._join import is_within, safe_join

__version__ = "0.1.0"

__all__ = ["UnsafePathError", "is_within", "safe_join"]
