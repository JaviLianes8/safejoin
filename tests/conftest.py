"""Real filesystem fixtures: a base, an outside directory and real links between them.

Nothing is mocked. Junctions are created with ``_winapi.CreateJunction`` on Windows
(no privilege needed); symlinks with ``os.symlink`` everywhere, and tests that need
them skip with the reason when the OS refuses (Windows without Developer Mode).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from safejoin._paths import canonical


def can_symlink(where: Path) -> bool:
    probe = where / "symlink-probe"
    try:
        os.symlink(where, probe, target_is_directory=True)
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


def make_junction(target: Path, link: Path) -> bool:
    if sys.platform != "win32":
        return False
    import _winapi

    _winapi.CreateJunction(str(target), str(link))
    return True


@dataclass
class Tree:
    """A temp root holding ``base`` (trusted) and ``out`` (must never be reached)."""

    root: Path
    base: Path
    out: Path
    symlinks: bool
    junctions: bool
    links: dict[str, str] = field(default_factory=dict)

    def outside_snapshot(self) -> tuple[list[str], list[str]]:
        return sorted(os.listdir(self.root)), sorted(os.listdir(self.out))


def build_tree(root: Path) -> Tree:
    """Create base/sub, base/file.txt, out/secret.txt and every link kind available."""
    base, out = root / "base", root / "out"
    (base / "sub" / "deep").mkdir(parents=True)
    out.mkdir()
    (base / "file.txt").write_text("inside", encoding="utf-8")
    (out / "secret.txt").write_text("secret", encoding="utf-8")
    tree = Tree(root, base, out, can_symlink(root), False)
    if make_junction(out, base / "junc"):
        tree.junctions = True
        make_junction(base / "sub", base / "junc_in")
        tree.links.update(junc="out", junc_in="in")
    if tree.symlinks:
        os.symlink(out, base / "sl", target_is_directory=True)
        os.symlink(out / "new.txt", base / "dangling")
        os.symlink(base / "sub", base / "sl_in", target_is_directory=True)
        os.symlink(os.path.join("..", ".."), base / "sub" / "up", target_is_directory=True)
        os.symlink(base / "loop_b", base / "loop_a")
        os.symlink(base / "loop_a", base / "loop_b")
        tree.links.update(sl="out", dangling="out", sl_in="in", **{"sub/up": "out"})
        tree.links.update(loop_a="loop", loop_b="loop")
    return tree


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return build_tree(tmp_path)


@pytest.fixture(scope="module")
def shared_tree(tmp_path_factory: pytest.TempPathFactory) -> Tree:
    return build_tree(tmp_path_factory.mktemp("tree"))


def real_location(path: Path) -> Path:
    """Where the OS really put an existing file: the final path of an open handle."""
    if sys.platform == "win32" and path.is_file():
        from safejoin._winfinal import final_path

        fd = os.open(path, os.O_RDONLY)
        try:
            return canonical(Path(final_path(fd)))
        finally:
            os.close(fd)
    return canonical(Path(os.path.realpath(path)))


def assert_lands_inside(tree: Tree, path: Path) -> None:
    """Create the file at an accepted path and prove it really landed inside the base."""
    before = tree.outside_snapshot()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8"):
            pass
    except OSError:
        assert tree.outside_snapshot() == before, path
        return
    real_base = real_location(tree.base)
    where = real_location(path)
    assert where == real_base or real_base in where.parents, (path, where)
    assert tree.outside_snapshot() == before, path
    assert (tree.out / "secret.txt").read_text(encoding="utf-8") == "secret"


def need_symlinks(tree: Tree) -> None:
    if not tree.symlinks:
        pytest.skip("this OS account may not create symlinks (Windows needs Developer Mode)")


def need_junctions(tree: Tree) -> None:
    if not tree.junctions:
        pytest.skip("junctions exist only on Windows")
