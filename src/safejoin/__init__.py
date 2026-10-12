"""Path-traversal-safe joining of a trusted base directory with untrusted relative parts."""

from __future__ import annotations

from ._archive import link_target_parts, member_parts, safe_link_target, safe_member_path
from ._errors import (
    AbsolutePartError,
    InvalidPartError,
    SymlinkError,
    TraversalError,
    UnsafePathError,
)
from ._join import SymlinkPolicy, is_within, safe_join
from ._open import safe_open
from ._rules import RESERVED_NAMES, check_part

__version__ = "0.2.0"

__all__ = [
    "RESERVED_NAMES",
    "AbsolutePartError",
    "InvalidPartError",
    "SymlinkError",
    "SymlinkPolicy",
    "TraversalError",
    "UnsafePathError",
    "check_part",
    "is_within",
    "link_target_parts",
    "member_parts",
    "safe_join",
    "safe_link_target",
    "safe_member_path",
    "safe_open",
]
