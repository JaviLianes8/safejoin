"""The ``safejoin`` command line tool, driven in process through ``main``."""

from __future__ import annotations

import io
import json
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from safejoin._cli import main


def _run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


def test_check_prints_the_safe_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(capsys, "check", str(tmp_path), "a", "b.txt")
    assert (code, err) == (0, "")
    assert Path(out.strip()) == (tmp_path / "a" / "b.txt").resolve()


def test_check_refuses_with_exit_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(capsys, "check", str(tmp_path), "../etc/passwd")
    assert (code, out) == (1, "")
    assert "unsafe (escape)" in err


def test_check_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "check", "--json", str(tmp_path), "a.txt")
    assert code == 0
    assert json.loads(out) == {"safe": True, "path": str((tmp_path / "a.txt").resolve())}
    code, out, err = _run(capsys, "check", "--json", "--lexical", str(tmp_path), "..")
    report = json.loads(out)
    assert (code, report["safe"], report["reason"], report["part"]) == (1, False, "escape", "..")
    assert err


def test_check_windows_rules_switch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = _run(capsys, "check", "--windows-rules", "on", str(tmp_path), "CON.txt")
    assert code == 1
    assert "device name" in err


def test_check_deny_symlinks_flag_is_wired(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(capsys, "check", "--deny-symlinks", str(tmp_path), "plain")
    assert code == 0
    assert out.strip()


def test_within(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(capsys, "within", str(tmp_path), str(tmp_path / "a"))[:2] == (0, "inside\n")
    assert _run(capsys, "within", str(tmp_path / "a"), str(tmp_path))[:2] == (1, "outside\n")


def test_member(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(capsys, "member", "docs\\a.txt", "../evil", "ok")
    assert code == 1
    assert out.splitlines() == ["docs/a.txt", "ok"]
    assert "../evil" in err


def _zip(path: Path, names: list[str], link: tuple[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, "x")
        if link is not None:
            info = zipfile.ZipInfo(link[0])
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, link[1])
    return path


def _tar(path: Path, members: list[tarfile.TarInfo]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for member in members:
            archive.addfile(member, io.BytesIO(b"") if member.isreg() else None)
    return path


def test_scan_a_clean_zip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = _zip(tmp_path / "ok.zip", ["a.txt", "docs/b.txt"], ("docs/l", "b.txt"))
    assert _run(capsys, "scan", str(archive)) == (0, "3 members checked, 0 unsafe\n", "")


def test_scan_a_zip_slip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    archive = _zip(tmp_path / "bad.zip", ["a.txt", "../../evil.sh", "CON"], ("l", "../x"))
    code, out, err = _run(capsys, "scan", str(archive))
    assert (code, out) == (1, "4 members checked, 3 unsafe\n")
    assert all(name in err for name in ("../../evil.sh", "CON", "'l'"))


def test_scan_a_hostile_tar(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    members = [tarfile.TarInfo("ok.txt"), tarfile.TarInfo("/abs.txt")]
    sym = tarfile.TarInfo("sym")
    sym.type, sym.linkname = tarfile.SYMTYPE, "../../etc"
    hard = tarfile.TarInfo("hard")
    hard.type, hard.linkname = tarfile.LNKTYPE, "../x"
    fifo = tarfile.TarInfo("fifo")
    fifo.type = tarfile.FIFOTYPE
    archive = _tar(tmp_path / "bad.tar.gz", [*members, sym, hard, fifo])
    code, out, err = _run(capsys, "scan", str(archive))
    assert (code, out) == (1, "5 members checked, 4 unsafe\n")
    assert "device or FIFO" in err


def test_scan_errors_go_to_stderr(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "junk.bin").write_bytes(b"not an archive")
    code, out, err = _run(capsys, "scan", str(tmp_path / "junk.bin"))
    assert (code, out) == (1, "")
    assert err.startswith("safejoin: error:")
    code, _, err = _run(capsys, "scan", str(tmp_path / "missing.zip"))
    assert code == 1


def test_usage_errors_exit_1(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["check"])
    assert info.value.code == 1
    assert "usage" in capsys.readouterr().err


def test_help_has_runnable_examples(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    assert "examples:" in capsys.readouterr().out
