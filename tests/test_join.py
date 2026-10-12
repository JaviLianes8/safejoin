from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from safejoin import (
    AbsolutePartError,
    InvalidPartError,
    TraversalError,
    UnsafePathError,
    is_within,
    safe_join,
)


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


def test_errors_name_the_offending_part(tmp_path: Path) -> None:
    with pytest.raises(TraversalError) as info:
        safe_join(tmp_path, "ok", "..", "..", "x")
    assert info.value.part == ".."
    with pytest.raises(AbsolutePartError) as rooted:
        safe_join(tmp_path, "ok", "/etc")
    assert rooted.value.part == "/etc"
    with pytest.raises(InvalidPartError) as nul:
        safe_join(tmp_path, "ok", "a\x00b")
    assert nul.value.part == "a\x00b"


@pytest.mark.parametrize("resolve", [True, False])
def test_a_climb_above_the_base_is_refused_even_if_it_comes_back(
    tmp_path: Path, resolve: bool
) -> None:
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(TraversalError):
        safe_join(base, "..", "base", "x", resolve=resolve)
    with pytest.raises(TraversalError):
        safe_join(base, "a/../../base/x", resolve=resolve)


def test_dotdot_that_stays_inside_is_fine(tmp_path: Path) -> None:
    assert safe_join(tmp_path, "a", "..", "b") == (tmp_path / "b").resolve()
    assert safe_join(tmp_path, "a/b/../../c", resolve=False) == Path(
        os.path.abspath(tmp_path / "c")
    )


def test_no_parts_and_empty_parts_give_the_base(tmp_path: Path) -> None:
    assert safe_join(tmp_path) == tmp_path.resolve()
    assert safe_join(tmp_path, "", ".") == tmp_path.resolve()


def test_a_nul_in_the_base_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InvalidPartError) as info:
        safe_join(f"{tmp_path}\x00x", "a")
    assert info.value.part is None


def test_unknown_symlink_policy_is_a_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="symlinks"):
        safe_join(tmp_path, "a", symlinks="maybe")  # type: ignore[arg-type]


def test_bytes_parts_are_a_type_error(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        safe_join(tmp_path, b"a")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        safe_join(os.fsencode(str(tmp_path)), "a")  # type: ignore[arg-type]


def test_is_within_is_false_for_nul_and_true_for_the_base(tmp_path: Path) -> None:
    assert is_within(tmp_path, tmp_path)
    assert not is_within(tmp_path, f"{tmp_path}\x00")
    assert not is_within(f"{tmp_path}\x00", tmp_path, resolve=False)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 extended-length prefix")
def test_extended_length_paths_compare_with_plain_ones(tmp_path: Path) -> None:
    plain = tmp_path.resolve()
    extended = "\\\\?\\" + str(plain)
    assert is_within(plain, extended + "\\a")
    assert is_within(extended, str(plain / "a"), resolve=False)
    assert not is_within(extended, extended + "\\..\\x", resolve=False)
    assert not is_within(extended, extended + "\\..\\x")
    with pytest.raises(TraversalError):
        safe_join(extended, "..", resolve=False)
    assert safe_join(extended, "a", resolve=False).name == "a"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows device namespace")
def test_windows_devices_never_come_back_even_without_windows_rules(tmp_path: Path) -> None:
    for resolve in (True, False):
        with pytest.raises(TraversalError):
            safe_join(tmp_path, "NUL", resolve=resolve, windows_rules=False)
        assert not is_within(tmp_path, tmp_path / "NUL", resolve=resolve)


def test_windows_rules_can_be_forced_anywhere(tmp_path: Path) -> None:
    for part in ["CON", "a:b", "x.", "..\\..\\x"]:
        with pytest.raises(UnsafePathError):
            safe_join(tmp_path, part, windows_rules=True)


class _LyingStr(str):
    """A str subclass whose helpers pretend the text is harmless."""

    def split(self, *args: object, **kwargs: object) -> list[str]:
        return ["harmless"]

    def replace(self, *args: object, **kwargs: object) -> str:
        return "harmless"

    def __contains__(self, item: object) -> bool:
        return False


class _FlipFlop:
    """A path-like object that answers safely once, then with an escape."""

    def __init__(self) -> None:
        self.calls = 0

    def __fspath__(self) -> str:
        self.calls += 1
        return "safe" if self.calls == 1 else "../../escape"


def test_a_lying_str_subclass_cannot_fool_the_checks(tmp_path: Path) -> None:
    for resolve in (True, False):
        with pytest.raises(UnsafePathError):
            safe_join(tmp_path, _LyingStr("../../x"), resolve=resolve)
        with pytest.raises(UnsafePathError):
            safe_join(tmp_path, _LyingStr("a\x00b"), resolve=resolve)


def test_a_path_like_part_is_read_exactly_once(tmp_path: Path) -> None:
    part = _FlipFlop()
    assert safe_join(tmp_path, part) == (tmp_path / "safe").resolve()
    assert part.calls == 1
