from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from safejoin import UnsafePathError, is_within, safe_join


def test_normal_join_stays_within_base(tmp_path: Path) -> None:
    result = safe_join(tmp_path, "sub", "file.txt")
    assert result == (tmp_path / "sub" / "file.txt").resolve()
    assert is_within(tmp_path, result)


def test_nested_safe_parts_are_joined(tmp_path: Path) -> None:
    result = safe_join(tmp_path, "a", "b", "c.txt")
    assert result.name == "c.txt"
    assert is_within(tmp_path, result)


def test_returns_an_absolute_path(tmp_path: Path) -> None:
    assert safe_join(tmp_path, "sub").is_absolute()


def test_rejects_parent_escape(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, "..", "etc")


def test_rejects_nested_dotdot_escape(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, "sub", "..", "..", "secret")


def test_rejects_absolute_untrusted_part(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, "/etc/passwd")


@pytest.mark.skipif(sys.platform != "win32", reason="drive letters are Windows only")
def test_rejects_drive_change_on_windows(tmp_path: Path) -> None:
    other = "Z:" if tmp_path.drive.upper() != "Z:" else "Y:"
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, f"{other}\\evil")


def test_is_within_true_for_a_child(tmp_path: Path) -> None:
    assert is_within(tmp_path, tmp_path / "child" / "leaf.txt")


def test_is_within_false_for_a_sibling(tmp_path: Path) -> None:
    assert not is_within(tmp_path / "base", tmp_path / "other")


def test_is_within_false_for_a_shared_prefix(tmp_path: Path) -> None:
    assert not is_within(tmp_path / "base", tmp_path / "baseball")


def test_rejects_symlink_that_points_outside_base(tmp_path: Path) -> None:
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this environment does not allow creating symlinks")
    with pytest.raises(UnsafePathError):
        safe_join(base, "link", "secret.txt")


def test_lexical_mode_still_rejects_dotdot_escape(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, "sub", "..", "..", "secret", resolve=False)


def test_lexical_mode_joins_within_base(tmp_path: Path) -> None:
    result = safe_join(tmp_path, "sub", "file.txt", resolve=False)
    assert result == Path(os.path.abspath(tmp_path / "sub" / "file.txt"))
