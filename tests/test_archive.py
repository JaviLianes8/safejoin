"""Archive member names and link targets: platform-independent rules plus disk checks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import Tree, need_symlinks

from safejoin import (
    AbsolutePartError,
    InvalidPartError,
    TraversalError,
    UnsafePathError,
    link_target_parts,
    member_parts,
    safe_link_target,
    safe_member_path,
)

UNSAFE_MEMBERS = [
    "../evil",
    "a/../../evil",
    "a/../b",
    "..",
    "/etc/passwd",
    "\\evil",
    "C:\\evil",
    "C:evil",
    "c:/evil",
    "\\\\host\\share\\evil",
    "//host/share/evil",
    "\\\\?\\C:\\evil",
    "..\\evil",
    "a\\..\\..\\evil",
    "",
    "/",
    "./",
    ".",
    "evil\x00.txt",
    "CON",
    "docs/nul.txt",
    "a:b",
    "x.",
    "dir /x",
    "\uff0e\uff0e/evil",
    "a\u2215..\u2215..\u2215evil",
]
SAFE_MEMBERS = {
    "a.txt": ("a.txt",),
    "docs/readme.md": ("docs", "readme.md"),
    "./docs//readme.md": ("docs", "readme.md"),
    "docs\\win.txt": ("docs", "win.txt"),
    "dir/": ("dir",),
    "\u00e9t\u00e9/\u65e5\u672c.txt": ("\u00e9t\u00e9", "\u65e5\u672c.txt"),
    "a..b/c": ("a..b", "c"),
}


@pytest.mark.parametrize("name", UNSAFE_MEMBERS)
def test_unsafe_member_names_are_refused(name: str) -> None:
    with pytest.raises(UnsafePathError) as info:
        member_parts(name)
    assert info.value.part == name


@pytest.mark.parametrize(("name", "expected"), SAFE_MEMBERS.items())
def test_safe_member_names_give_their_components(name: str, expected: tuple[str, ...]) -> None:
    assert member_parts(name) == expected


def test_member_errors_are_typed() -> None:
    with pytest.raises(AbsolutePartError):
        member_parts("/x")
    with pytest.raises(TraversalError):
        member_parts("a/../b")
    with pytest.raises(InvalidPartError):
        member_parts("CON")
    with pytest.raises(TypeError):
        member_parts(b"x")  # type: ignore[arg-type]


def test_safe_member_path_joins_under_the_base(tmp_path: Path) -> None:
    assert safe_member_path(tmp_path, "docs\\a.txt") == (tmp_path / "docs" / "a.txt").resolve()
    with pytest.raises(UnsafePathError):
        safe_member_path(tmp_path, "../x")


@pytest.mark.parametrize(
    ("member", "target", "hard", "expected"),
    [
        ("a/link", "b.txt", False, ("a", "b.txt")),
        ("a/link", "../b.txt", False, ("b.txt",)),
        ("a/b/link", "../../c", False, ("c",)),
        ("link", ".", False, ()),
        ("a/hard", "a/file", True, ("a", "file")),
    ],
)
def test_link_targets_inside_the_archive(
    member: str, target: str, hard: bool, expected: tuple[str, ...]
) -> None:
    assert link_target_parts(member, target, hard=hard) == expected


@pytest.mark.parametrize(
    ("member", "target", "hard"),
    [
        ("link", "../x", False),
        ("a/link", "../../x", False),
        ("a/link", "b/../../x", False),
        ("a/link", "b/..", False),
        ("link", "/etc/passwd", False),
        ("link", "C:\\x", False),
        ("link", "\\\\host\\s", False),
        ("hard", "../x", True),
        ("hard", ".", True),
        ("link", "CON", False),
        ("link", "x\x00", False),
        ("../link", "x", False),
    ],
)
def test_link_targets_that_escape_are_refused(member: str, target: str, hard: bool) -> None:
    with pytest.raises(UnsafePathError):
        link_target_parts(member, target, hard=hard)


def test_safe_link_target_follows_links_already_on_disk(tree: Tree) -> None:
    need_symlinks(tree)
    # An earlier member made "a" a link to the base itself, so "a/l" really lives in
    # the base and "../x" from there climbs out, although it looks fine lexically.
    os.symlink(".", tree.base / "a", target_is_directory=True)
    assert link_target_parts("a/l", "../x") == ("x",)
    with pytest.raises(TraversalError):
        safe_link_target(tree.base, "a/l", "../x")


def test_safe_link_target_returns_the_landing_place(tree: Tree) -> None:
    landing = safe_link_target(tree.base, "sub/link", "deep")
    assert landing == (tree.base / "sub" / "deep").resolve()
    assert safe_link_target(tree.base, "h", "sub/deep", hard=True) == landing
    assert safe_link_target(tree.base, "top", "file.txt") == (tree.base / "file.txt").resolve()
    with pytest.raises(TraversalError):
        safe_link_target(tree.base, "sub/link", "../../out")
