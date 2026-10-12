"""Contract over the complete promise, on the real filesystem with real links.

For every hostile part in a large corpus and every mode, ``safe_join`` either raises
an ``UnsafePathError`` subclass naming a part, or returns a path that, once the file
is really created there, lands inside the base with nothing written outside. The
modes that promise link safety (resolved, or lexical with ``symlinks="deny"``) are
held to the ground truth; plain lexical mode is held to lexical containment.
"""

from __future__ import annotations

import itertools
import sys

import pytest
from conftest import Tree, assert_lands_inside
from hostile import PAYLOADS, PREFIXES, SUFFIXES

from safejoin import UnsafePathError, is_within, safe_join
from safejoin._paths import contains

MODES = [(True, "allow_inside"), (True, "deny"), (False, "allow_inside"), (False, "deny")]
WINDOWS = [None, True]


def _corpus() -> list[tuple[str, ...]]:
    singles: list[tuple[str, ...]] = [
        (p + x + s,) for p, x, s in itertools.product(PREFIXES, PAYLOADS, SUFFIXES)
    ]
    split = [(p.rstrip("/\\") or ".", x, "n.txt") for p, x in itertools.product(PREFIXES, PAYLOADS)]
    return singles + split


CORPUS = _corpus()


def test_the_corpus_is_large() -> None:
    assert len(CORPUS) > 2000


def _must_fail(parts: tuple[str, ...], windows: bool) -> bool:
    """An independent oracle: NUL, a rooted part, or a climb above the base."""
    depth = 0
    for part in parts:
        text = part.replace("\\", "/") if windows else part
        if "\x00" in part or text.startswith("/") or (windows and text[1:2] == ":"):
            return True
        for piece in text.split("/"):
            if piece == "..":
                depth -= 1
            elif piece not in ("", "."):
                depth += 1
            if depth < 0:
                return True
    return False


@pytest.mark.parametrize(("resolve", "policy"), MODES)
@pytest.mark.parametrize("windows_rules", WINDOWS)
def test_every_accepted_result_is_inside(
    shared_tree: Tree, resolve: bool, policy: str, windows_rules: bool | None
) -> None:
    tree = shared_tree
    truth = resolve or policy == "deny"
    accepted = 0
    for parts in CORPUS:
        try:
            result = safe_join(
                tree.base,
                *parts,
                resolve=resolve,
                symlinks=policy,  # type: ignore[arg-type]
                windows_rules=windows_rules,
            )
        except UnsafePathError as exc:
            assert exc.part is None or exc.part in parts, (parts, exc.part)
            continue
        assert not _must_fail(parts, windows_rules or sys.platform == "win32"), parts
        assert result.is_absolute(), parts
        assert contains(tree.base.resolve() if resolve else tree.base.absolute(), result), parts
        if truth:
            assert is_within(tree.base, result), parts
            assert_lands_inside(tree, result)
        accepted += 1
    assert accepted > 100


@pytest.mark.parametrize(("resolve", "policy"), MODES)
def test_links_that_leave_the_base_are_refused(tree: Tree, resolve: bool, policy: str) -> None:
    outward = [name for name, kind in tree.links.items() if kind in ("out", "loop")]
    if not outward:
        pytest.skip("no links could be created on this OS account")
    if not resolve and policy == "allow_inside":
        pytest.skip("lexical mode without deny documents that it does not follow links")
    for name in outward:
        for parts in [(name,), (name, "n.txt"), (f"{name}/n.txt",), (name, "secret.txt")]:
            with pytest.raises(UnsafePathError):
                safe_join(tree.base, *parts, resolve=resolve, symlinks=policy)  # type: ignore[arg-type]


def test_links_that_stay_inside_follow_the_policy(tree: Tree) -> None:
    inward = [name for name, kind in tree.links.items() if kind == "in"]
    if not inward:
        pytest.skip("no links could be created on this OS account")
    for name in inward:
        assert safe_join(tree.base, name, "deep") == (tree.base / "sub" / "deep").resolve()
        with pytest.raises(UnsafePathError):
            safe_join(tree.base, name, "deep", symlinks="deny")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path semantics")
def test_windows_specific_inputs_are_refused_by_default(tree: Tree) -> None:
    for part in ["CON", "nul.txt", "COM\u00b9", "a.txt:s", "x.", "x ", "C:x", "\uff0e\uff0e"]:
        with pytest.raises(UnsafePathError):
            safe_join(tree.base, part)
