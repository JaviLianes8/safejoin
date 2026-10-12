"""check_part: pure, platform-independent rules when ``windows_rules=True``."""

from __future__ import annotations

import sys
from pathlib import PurePosixPath

import pytest

from safejoin import AbsolutePartError, InvalidPartError, check_part

ROOTED = [
    "/etc/passwd",
    "//server/share",
    "\\Windows",
    "\\\\server\\share\\x",
    "C:\\x",
    "C:/x",
    "C:x",
    "c:",
    "a::$DATA",
    "\\\\?\\C:\\x",
    "\\\\.\\COM1",
    "\\\\?\\UNC\\host\\share",
    "//?/C:/x",
]
INVALID = [
    "CON",
    "con",
    "Con.txt",
    "NUL.tar.gz",
    "AUX .txt",
    "PRN..log",
    "COM1",
    "com9.x",
    "LPT0",
    "COM\u00b9",
    "LPT\u00b3.txt",
    "CONIN$",
    "conout$",
    "sub/CON",
    "a\\nul.txt",
    "file.txt:stream",
    "dir::$INDEX_ALLOCATION",
    "ab::$DATA",
    "x.",
    "x ",
    "dir. /x",
    "a<b",
    "a>b",
    'a"b',
    "a|b",
    "a?b",
    "a*b",
    "a\tb",
    "a\x01b",
    "\uff0e\uff0e",
    "\uff0e\uff0e\uff0fx",
    "a\uff0fb",
    "a\uff3cb",
    "a\u2215b",
    "a\uff1ab",
    "a\u2216b",
    "x\u00a5y",
    "x\u20a9y",
    "\uff23\uff2f\uff2e",
    "...",
    "... ",
    ".. ",
    "a\u2044b",
]
FINE = [
    "a",
    "a.txt",
    "sub/deep/file",
    "..",
    "../x",
    ".",
    "",
    "CONSOLE",
    "COM10",
    "LPT",
    "conx",
    "nul_",
    "a.con",
    "my CON",
    "\u00e9t\u00e9.txt",
    "\u65e5\u672c",
    ".hidden",
    "a..b",
    "-rf",
    "~",
    "%2e%2e",
]


@pytest.mark.parametrize("part", ROOTED)
def test_rooted_parts_are_refused_under_windows_rules(part: str) -> None:
    with pytest.raises(AbsolutePartError) as info:
        check_part(part, windows_rules=True)
    assert info.value.part == part


@pytest.mark.parametrize("part", INVALID)
def test_windows_invalid_parts_are_refused(part: str) -> None:
    with pytest.raises(InvalidPartError) as info:
        check_part(part, windows_rules=True)
    assert info.value.part == part


@pytest.mark.parametrize("part", FINE)
def test_ordinary_parts_pass(part: str) -> None:
    check_part(part, windows_rules=True)
    check_part(part, windows_rules=False)


@pytest.mark.parametrize("part", ["a\x00b", "\x00", "sub/\x00"])
def test_nul_is_refused_in_every_mode(part: str) -> None:
    for rules in (None, True, False):
        with pytest.raises(InvalidPartError):
            check_part(part, windows_rules=rules)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX meaning of backslash and colon")
def test_posix_without_windows_rules_keeps_posix_meaning() -> None:
    for part in ["CON", "a:b", "C:x", "..\\..\\x", "\\\\server\\share", "x."]:
        check_part(part, windows_rules=False)
    with pytest.raises(AbsolutePartError):
        check_part("/etc", windows_rules=False)


@pytest.mark.skipif(sys.platform != "win32", reason="the default only turns on under Windows")
def test_windows_rules_are_on_by_default_on_windows() -> None:
    with pytest.raises(InvalidPartError):
        check_part("CON")


def test_path_like_parts_are_accepted() -> None:
    check_part(PurePosixPath("a/b"), windows_rules=True)


def test_bytes_are_a_type_error() -> None:
    with pytest.raises(TypeError):
        check_part(b"a")  # type: ignore[arg-type]


@pytest.mark.skipif(sys.platform != "win32", reason="asks the real Windows converter")
def test_every_best_fit_separator_is_refused() -> None:
    """Ask WideCharToMultiByte itself which characters best-fit to a separator."""
    import ctypes

    convert = ctypes.WinDLL("kernel32").WideCharToMultiByte  # type: ignore[attr-defined,unused-ignore]
    pages = (437, 850, 874, 932, 936, 949, 950, *range(1250, 1259))
    specials = {ord("/"), ord("\\"), ord(":")}
    out = ctypes.create_string_buffer(8)
    missed = []
    hits = 0
    for code in range(0x80, 0x10000):
        if 0xD800 <= code < 0xE000:
            continue
        char = chr(code)
        for page in pages:
            size = convert(page, 0, char, 1, out, 8, None, None)
            if size == 1 and out.raw[0] in specials:
                hits += 1
                try:
                    check_part(f"a{char}b", windows_rules=True)
                except InvalidPartError:
                    break
                missed.append((hex(code), page))
                break
    assert hits >= 8
    assert missed == []
