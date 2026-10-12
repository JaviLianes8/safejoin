"""scan_archive on hostile archives built in the test: chains, header tricks, corruption."""

from __future__ import annotations

import io
import lzma
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from safejoin._scan import scan_archive


def _tar(path: Path, *members: tuple[str, str, str]) -> Path:
    """Write a tar of (kind, name, link) where kind is file, sym, hard or dir."""
    kinds = {"file": tarfile.REGTYPE, "sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE}
    kinds["dir"] = tarfile.DIRTYPE
    with tarfile.open(path, "w") as archive:
        for kind, name, link in members:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kinds[kind], link
            archive.addfile(info, io.BytesIO(b"") if kind == "file" else None)
    return path


def test_a_link_chain_through_an_earlier_symlink_is_reported(tmp_path: Path) -> None:
    archive = _tar(
        tmp_path / "chain.tar", ("sym", "d", "."), ("sym", "d/l", ".."), ("file", "l/x", "")
    )
    count, problems = scan_archive(archive)
    assert count == 3
    assert any("'d'" in line and "archive root" in line for line in problems)
    assert any("'d/l'" in line and "earlier symlink" in line for line in problems)


def test_writing_through_a_symlinked_directory_is_reported(tmp_path: Path) -> None:
    archive = _tar(tmp_path / "w.tar", ("sym", "d", "sub"), ("file", "d/x", ""))
    _, problems = scan_archive(archive)
    assert problems == ["'d/x': its path passes through an earlier symlink member"]


def test_a_link_target_through_an_earlier_symlink_is_reported(tmp_path: Path) -> None:
    archive = _tar(tmp_path / "t.tar", ("sym", "d", "sub"), ("sym", "e", "d/x"))
    _, problems = scan_archive(archive)
    assert problems == ["'e': its link target passes through an earlier symlink member"]


def test_a_clean_tar_with_links_passes(tmp_path: Path) -> None:
    archive = _tar(
        tmp_path / "ok.tar",
        ("dir", "a", ""),
        ("file", "a/f", ""),
        ("sym", "a/l", "f"),
        ("hard", "h", "a/f"),
    )
    assert scan_archive(archive) == (4, [])


def test_a_zip_local_header_that_differs_is_reported(tmp_path: Path) -> None:
    archive = tmp_path / "header.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("goodnam", "x")
    data = archive.read_bytes()
    local = data.index(b"goodnam")  # the first copy is the local header name
    archive.write_bytes(data[:local] + b"../evil" + data[local + 7 :])
    count, problems = scan_archive(archive)
    assert count == 1
    assert len(problems) == 1
    assert "cannot verify member" in problems[0]


def test_an_unsupported_zip_symlink_is_reported_not_crashed(tmp_path: Path) -> None:
    archive = tmp_path / "method.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        info = zipfile.ZipInfo("l")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        handle.writestr(info, "target")
    data = bytearray(archive.read_bytes())
    for offset in (8, data.index(b"PK\x01\x02") + 10):  # compression method fields
        data[offset : offset + 2] = (99).to_bytes(2, "little")
    archive.write_bytes(bytes(data))
    _, problems = scan_archive(archive)
    assert len(problems) == 1


@pytest.mark.parametrize("suffix", [".tar.xz", ".tar.gz", ".zip"])
def test_corrupt_archives_never_raise_anything_but_value_error(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"bad{suffix}"
    if suffix == ".tar.xz":
        path.write_bytes(lzma.compress(b"x" * 100)[:30])
    elif suffix == ".tar.gz":
        path.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    else:
        path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    try:
        count, problems = scan_archive(path)
    except ValueError:
        return
    assert (count, problems) == (0, [])
