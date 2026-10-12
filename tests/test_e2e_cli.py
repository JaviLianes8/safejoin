"""Real end to end test: build the wheel, install it, drive the installed console script.

No mocks. The project is built into a wheel, the wheel is pip-installed into a throwaway
virtual environment, and the real ``safejoin`` executable is run over ``subprocess``
against a real directory tree and real archives.
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

import safejoin

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _exe(env_dir: Path, name: str) -> Path:
    scripts = env_dir / ("Scripts" if sys.platform == "win32" else "bin")
    return scripts / (f"{name}.exe" if sys.platform == "win32" else name)


@pytest.fixture(scope="module")
def cli(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build a wheel, install it into a fresh venv and return the console script path."""
    pytest.importorskip("ensurepip", reason="this interpreter cannot create venvs with pip")
    wheel_dir = tmp_path_factory.mktemp("safejoin-wheel")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "-w",
            str(wheel_dir),
            str(PROJECT_ROOT),
        ],
        check=True,
        capture_output=True,
        timeout=600,
    )
    wheels = sorted(wheel_dir.glob("safejoin-*.whl"))
    assert len(wheels) == 1, wheels
    env_dir = tmp_path_factory.mktemp("safejoin-e2e-venv")
    venv.create(env_dir, with_pip=True)
    python = _exe(env_dir, "python")
    subprocess.run(
        [str(python), "-m", "pip", "install", "--quiet", "--no-deps", str(wheels[0])],
        check=True,
        capture_output=True,
        timeout=600,
    )
    script = _exe(env_dir, "safejoin")
    assert script.is_file(), f"console script was not installed at {script}"
    return script


def _run(cli: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(cli), *args], capture_output=True, text=True, timeout=60)


def test_check_accepts_a_safe_part(cli: Path, tmp_path: Path) -> None:
    result = _run(cli, "check", str(tmp_path), "docs", "a.txt")
    assert (result.returncode, result.stderr) == (0, "")
    assert Path(result.stdout.strip()) == (tmp_path / "docs" / "a.txt").resolve()


def test_check_refuses_traversal_on_stderr(cli: Path, tmp_path: Path) -> None:
    result = _run(cli, "check", str(tmp_path), "../../etc/passwd")
    assert (result.returncode, result.stdout) == (1, "")
    assert "unsafe (escape)" in result.stderr


def test_check_json_names_the_part(cli: Path, tmp_path: Path) -> None:
    result = _run(cli, "check", "--json", "--windows-rules", "on", str(tmp_path), "ok", "CON")
    report = json.loads(result.stdout)
    assert (result.returncode, report["reason"], report["part"]) == (1, "invalid", "CON")


def test_check_refuses_a_junction_or_symlink_out(cli: Path, tmp_path: Path) -> None:
    base, out = tmp_path / "base", tmp_path / "out"
    base.mkdir()
    out.mkdir()
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(out), str(base / "door"))
    else:
        (base / "door").symlink_to(out, target_is_directory=True)
    assert _run(cli, "check", str(base), "door", "x").returncode == 1
    assert _run(cli, "check", "--lexical", str(base), "door", "x").returncode == 0
    assert _run(cli, "check", "--lexical", "--deny-symlinks", str(base), "door").returncode == 1


def test_within_and_member(cli: Path, tmp_path: Path) -> None:
    inside = _run(cli, "within", str(tmp_path), str(tmp_path / "a"))
    assert (inside.returncode, inside.stdout.strip()) == (0, "inside")
    member = _run(cli, "member", "a/b.txt", "../evil")
    assert (member.returncode, member.stdout.strip()) == (1, "a/b.txt")
    assert "../evil" in member.stderr


def test_scan_finds_zip_slip(cli: Path, tmp_path: Path) -> None:
    archive = tmp_path / "slip.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("ok.txt", "x")
        handle.writestr("../../evil.sh", "x")
    result = _run(cli, "scan", str(archive))
    assert (result.returncode, result.stdout.strip()) == (1, "2 members checked, 1 unsafe")
    assert "evil.sh" in result.stderr


def test_non_ascii_never_crashes(cli: Path, tmp_path: Path) -> None:
    result = _run(cli, "check", str(tmp_path), "日本", "été.txt")
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""


def test_help_lists_examples_and_usage_errors_exit_1(cli: Path) -> None:
    helped = _run(cli, "--help")
    assert (helped.returncode, "examples:" in helped.stdout) == (0, True)
    assert _run(cli, "check").returncode == 1


def test_installed_library_imports_in_the_venv(cli: Path) -> None:
    python = _exe(cli.parent.parent, "python")
    code = "import safejoin; print(safejoin.__version__)"
    result = subprocess.run([str(python), "-c", code], capture_output=True, text=True, timeout=60)
    assert (result.returncode, result.stdout.strip()) == (0, safejoin.__version__)
