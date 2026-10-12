"""safe_open on the real filesystem, including links swapped in after the check."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest
from conftest import Tree, make_junction, need_symlinks

from safejoin import InvalidPartError, SymlinkError, TraversalError, UnsafePathError, safe_open
from safejoin._open import _platform_open
from safejoin._paths import resolved


def test_reads_and_writes_inside_the_base(tree: Tree) -> None:
    with safe_open(tree.base, "file.txt", encoding="utf-8") as handle:
        assert handle.read() == "inside"
    with safe_open(tree.base, "sub", "new.txt", mode="w", encoding="utf-8") as handle:
        handle.write("hello")
    assert (tree.base / "sub" / "new.txt").read_text(encoding="utf-8") == "hello"


def test_modes_behave_like_open(tree: Tree) -> None:
    with safe_open(tree.base, "f.bin", mode="xb") as handle:
        handle.write(b"12345")
    with pytest.raises(FileExistsError):
        safe_open(tree.base, "f.bin", mode="x")
    with safe_open(tree.base, "f.bin", mode="ab") as handle:
        handle.write(b"6")
    with safe_open(tree.base, "f.bin", mode="r+b") as handle:
        assert handle.read() == b"123456"
    with safe_open(tree.base, "f.bin", mode="wb") as handle:
        handle.write(b"x")
    assert (tree.base / "f.bin").read_bytes() == b"x"
    with pytest.raises(FileNotFoundError):
        safe_open(tree.base, "missing.txt")


@pytest.mark.parametrize("mode", ["", "rw", "rr", "q", "rbt", "w+-", "+"])
def test_invalid_modes_are_refused_before_touching_anything(tree: Tree, mode: str) -> None:
    with pytest.raises(ValueError, match="mode"):
        safe_open(tree.base, "never.txt", mode=mode)
    assert not (tree.base / "never.txt").exists()


def test_invalid_text_arguments_are_refused_before_creating(tree: Tree) -> None:
    for kwargs in ({"encoding": "nope"}, {"errors": "nope"}, {"newline": "x"}):
        with pytest.raises((LookupError, ValueError)):
            safe_open(tree.base, "never.txt", mode="w", **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        safe_open(tree.base, "never.txt", mode="wb", encoding="utf-8")
    assert not (tree.base / "never.txt").exists()


def test_unsafe_paths_are_refused(tree: Tree) -> None:
    for parts in [("..", "out", "secret.txt"), ("/etc/passwd",), ("a\x00",)]:
        with pytest.raises(UnsafePathError):
            safe_open(tree.base, *parts)


def test_the_base_itself_and_directories_are_not_files(tree: Tree) -> None:
    with pytest.raises(InvalidPartError):
        safe_open(tree.base)
    with pytest.raises(InvalidPartError):
        safe_open(tree.base, ".")
    with pytest.raises((InvalidPartError, IsADirectoryError, PermissionError)):
        safe_open(tree.base, "sub")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX only")
def test_a_planted_fifo_is_refused_without_blocking(tree: Tree) -> None:
    os.mkfifo(tree.base / "pipe")  # type: ignore[attr-defined,unused-ignore]
    with pytest.raises(InvalidPartError):
        safe_open(tree.base, "pipe")
    with pytest.raises(InvalidPartError):
        safe_open(tree.base, "pipe", mode="w")


def _swap_in_link(tree: Tree, name: str, target: Path) -> None:
    """Replace directory base/name with a link to target, as a racing attacker would."""
    victim = tree.base / name
    if victim.exists():
        shutil.rmtree(victim)
    if not make_junction(target, victim):
        need_symlinks(tree)
        os.symlink(target, victim, target_is_directory=True)


@pytest.mark.parametrize("mode", ["r", "w", "a", "r+"])
def test_a_link_swapped_in_after_the_check_never_reaches_outside(tree: Tree, mode: str) -> None:
    (tree.base / "race").mkdir()
    (tree.base / "race" / "secret.txt").write_text("decoy", encoding="utf-8")
    safe_base = resolved(tree.base)
    checked = safe_base / "race" / "secret.txt"
    _swap_in_link(tree, "race", tree.out)
    from safejoin._open import _flags

    flags = _flags(mode)[0]
    with pytest.raises((TraversalError, SymlinkError)):
        _platform_open(safe_base, checked, flags, 0o666, "allow_inside", "race")
    assert (tree.out / "secret.txt").read_text(encoding="utf-8") == "secret"


def test_deny_refuses_a_link_even_when_it_points_inside(tree: Tree) -> None:
    (tree.base / "inner").mkdir()
    (tree.base / "sub" / "target.txt").write_text("t", encoding="utf-8")
    safe_base = resolved(tree.base)
    checked = safe_base / "inner" / "target.txt"
    _swap_in_link(tree, "inner", tree.base / "sub")
    with pytest.raises(SymlinkError):
        _platform_open(safe_base, checked, os.O_RDONLY, 0o666, "deny", "inner")
    with pytest.raises(SymlinkError):
        safe_open(tree.base, "inner", "target.txt", symlinks="deny")


def test_allow_inside_opens_through_an_inside_link(tree: Tree) -> None:
    (tree.base / "sub" / "target.txt").write_text("t", encoding="utf-8")
    _swap_in_link(tree, "inner", tree.base / "sub")
    with safe_open(tree.base, "inner", "target.txt", encoding="utf-8") as handle:
        assert handle.read() == "t"


def test_a_final_symlink_is_never_followed_on_posix(tree: Tree) -> None:
    need_symlinks(tree)
    if sys.platform == "win32":
        pytest.skip("Windows opens through links and checks the final path instead")
    os.symlink(tree.out / "secret.txt", tree.base / "late.txt")
    safe_base = resolved(tree.base)
    with pytest.raises(SymlinkError):
        _platform_open(safe_base, safe_base / "late.txt", os.O_RDONLY, 0o666, "allow_inside", None)
