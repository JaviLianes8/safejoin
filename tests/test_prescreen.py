"""Links are refused before they are opened; deny walks the path as written; hard links."""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from conftest import Tree, need_symlinks

from safejoin import InvalidPartError, SymlinkError, TraversalError, safe_join, safe_open


@pytest.mark.skipif(sys.platform != "win32", reason="named pipes and readlink prescreen")
def test_a_link_to_a_named_pipe_is_refused_without_connecting(tree: Tree) -> None:
    need_symlinks(tree)
    from multiprocessing.connection import Client, Listener

    address = rf"\\.\pipe\safejoin-test-{uuid.uuid4().hex}"
    connected: list[object] = []
    # Create the link first: os.symlink itself probes its target on Windows.
    os.symlink(address, tree.base / "pipe")
    with Listener(address, family="AF_PIPE") as listener:
        waiter = threading.Thread(target=lambda: connected.append(listener.accept()))
        waiter.start()
        with pytest.raises(SymlinkError, match="device"):
            safe_join(tree.base, "pipe")
        with pytest.raises(SymlinkError):
            safe_join(tree.base, "pipe", "x")
        time.sleep(0.3)
        assert connected == []
        Client(address, family="AF_PIPE").close()
        waiter.join(timeout=10)


@pytest.mark.skipif(sys.platform != "win32", reason="UNC targets are a Windows concern")
def test_a_link_to_a_remote_share_is_refused_lexically(tree: Tree) -> None:
    need_symlinks(tree)
    os.symlink(r"\\192.0.2.1\share\x", tree.base / "unc", target_is_directory=True)
    started = time.monotonic()
    with pytest.raises(TraversalError, match="outside"):
        safe_join(tree.base, "unc", "f.txt")
    assert time.monotonic() - started < 5, "the share must not be contacted"


def test_inside_link_chains_still_resolve(tree: Tree) -> None:
    if not tree.links:
        pytest.skip("no links could be created on this OS account")
    inward = next(name for name, kind in tree.links.items() if kind == "in")
    assert safe_join(tree.base, inward, "deep", "f") == (tree.base / "sub/deep/f").resolve()


def test_deny_checks_a_link_that_is_only_passed_through(tree: Tree) -> None:
    if not tree.links:
        pytest.skip("no links could be created on this OS account")
    inward = next(name for name, kind in tree.links.items() if kind == "in")
    with pytest.raises(SymlinkError) as info:
        safe_join(tree.base, f"{inward}/../file.txt", symlinks="deny")
    assert info.value.part == f"{inward}/../file.txt"
    with pytest.raises(SymlinkError):
        safe_join(tree.base, "nope", "..", inward, "..", "x", symlinks="deny", resolve=False)


def test_write_modes_refuse_a_file_with_other_hard_links(tree: Tree) -> None:
    try:
        os.link(tree.out / "secret.txt", tree.base / "hl.txt")
    except OSError as exc:
        pytest.skip(f"hard links are not available here: {exc}")
    for mode in ("w", "a", "r+"):
        with pytest.raises(InvalidPartError, match="hard links"):
            safe_open(tree.base, "hl.txt", mode=mode)
    assert (tree.out / "secret.txt").read_text(encoding="utf-8") == "secret"


def test_a_directory_is_an_invalid_part_on_every_platform(tree: Tree) -> None:
    for mode in ("r", "w", "a"):
        with pytest.raises(InvalidPartError, match="directory"):
            safe_open(tree.base, "sub", mode=mode)


def test_an_over_long_name_names_the_part(tmp_path: Path) -> None:
    name = "a" * 300
    try:
        safe_join(tmp_path, "ok", name)
    except (InvalidPartError, SymlinkError) as exc:
        assert exc.part == name
