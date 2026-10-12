"""Seeded fuzzing on the real filesystem: every accepted result resolves inside the base.

Parts are random mixes of real names in the tree (including links), ``..``, ``.``
and hostile tokens, joined with either separator. Whatever ``safe_join`` accepts in
resolved mode must really resolve inside the base, and a sample of accepted results
is created on disk and checked to land inside with nothing written outside.
``safe_open`` and ``member_parts`` are fuzzed with the same generator.
"""

from __future__ import annotations

import random
from collections import Counter

import pytest
from conftest import Tree, assert_lands_inside, real_location

from safejoin import UnsafePathError, member_parts, safe_join, safe_open

NAMES = [
    "sub",
    "deep",
    "junc",
    "junc_in",
    "sl",
    "sl_in",
    "dangling",
    "up",
    "loop_a",
    "file.txt",
    "x",
    "out",
    "secret.txt",
    "new.txt",
]
HOSTILE = [
    "/",
    "C:",
    "c:x",
    "//",
    "?",
    "CON",
    "nul.txt",
    "COM1",
    "a:b",
    "::$DATA",
    " ",
    "x.",
    chr(0),
    chr(0xFF0E) * 2,
    chr(0xFF0F),
    chr(0x2215),
    chr(0xA5),
    "%2e%2e",
    "~",
    chr(0xE9),
    "\t",
]
SEEDS = [0, 1, 2, 3, 4, 5, 6, 7]
CASES_PER_SEED = 1500


def _component(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.35:
        return ".."
    if roll < 0.42:
        return "."
    if roll < 0.92:
        return rng.choice(NAMES)
    return rng.choice(HOSTILE)


def _random_part(rng: random.Random) -> str:
    pieces = [_component(rng) for _ in range(rng.randint(1, 5))]
    return "".join(piece + rng.choice("/\\") for piece in pieces)[:-1]


def _random_parts(rng: random.Random) -> tuple[str, ...]:
    return tuple(_random_part(rng) for _ in range(rng.randint(1, 3)))


@pytest.mark.parametrize("seed", SEEDS)
@pytest.mark.parametrize("policy", ["allow_inside", "deny"])
def test_accepted_results_resolve_inside(shared_tree: Tree, seed: int, policy: str) -> None:
    rng = random.Random(seed)
    real_base = real_location(shared_tree.base)
    outcomes: Counter[str] = Counter()
    for index in range(CASES_PER_SEED):
        parts = _random_parts(rng)
        try:
            result = safe_join(shared_tree.base, *parts, symlinks=policy)  # type: ignore[arg-type]
        except UnsafePathError as exc:
            outcomes[exc.reason] += 1
            continue
        outcomes["accepted"] += 1
        where = real_location(result) if result.exists() else result
        assert where == real_base or real_base in where.parents, (seed, parts, where)
        if index % 7 == 0:
            assert_lands_inside(shared_tree, result)
    assert outcomes["accepted"] > 100, outcomes
    assert outcomes["escape"] > 100, outcomes


@pytest.mark.parametrize("seed", SEEDS[:4])
def test_safe_open_never_touches_outside(tree: Tree, seed: int) -> None:
    rng = random.Random(1000 + seed)
    before = tree.outside_snapshot()
    opened = 0
    for _ in range(CASES_PER_SEED // 3):
        parts = _random_parts(rng)
        try:
            with safe_open(tree.base, *parts, mode="a", encoding="utf-8") as handle:
                handle.write("")
        except (UnsafePathError, OSError):
            continue
        opened += 1
    assert opened > 10
    assert tree.outside_snapshot() == before
    assert (tree.out / "secret.txt").read_text(encoding="utf-8") == "secret"


@pytest.mark.parametrize("seed", SEEDS)
def test_member_parts_only_returns_plain_names(seed: int) -> None:
    rng = random.Random(2000 + seed)
    for _ in range(CASES_PER_SEED):
        name = "/".join(_random_parts(rng))
        try:
            pieces = member_parts(name)
        except UnsafePathError:
            continue
        assert pieces
        for piece in pieces:
            assert piece not in ("", ".", "..")
            assert not set(piece) & set('/\\:<>"|?*' + chr(0))
