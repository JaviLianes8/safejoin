"""Audit every member name and link of a zip or tar archive without extracting it."""

from __future__ import annotations

import os
import stat
import tarfile
import zipfile

from ._archive import link_target_parts, member_parts
from ._errors import UnsafePathError

_ZIP_LINK_LIMIT = 4096


def _zip_entries(path: str) -> list[tuple[str, str | None, bool, bool]]:
    entries: list[tuple[str, str | None, bool, bool]] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            mode = info.external_attr >> 16
            target = None
            if stat.S_ISLNK(mode):
                if info.file_size > _ZIP_LINK_LIMIT:
                    raise ValueError(f"zip symlink {info.filename!r} has an oversized target")
                target = archive.read(info).decode("utf-8", "surrogateescape")
            entries.append((info.filename, target, False, False))
    return entries


def _tar_entries(path: str) -> list[tuple[str, str | None, bool, bool]]:
    entries: list[tuple[str, str | None, bool, bool]] = []
    with tarfile.open(path, mode="r:*") as archive:
        for info in archive.getmembers():
            special = info.ischr() or info.isblk() or info.isfifo()
            target = info.linkname if (info.issym() or info.islnk()) else None
            entries.append((info.name, target, info.islnk(), special))
    return entries


def scan_archive(path: str | os.PathLike[str]) -> tuple[int, list[str]]:
    """Return the member count and a list of problems, one line per unsafe member.

    Raises ``ValueError`` when the file is not a readable zip or tar archive.

    Member names go through ``member_parts`` and link targets through
    ``link_target_parts``; device and FIFO members are reported too, as PEP 706's
    ``data`` filter refuses them. Nothing is extracted or written.
    """
    text = os.fspath(path)
    try:
        entries = _zip_entries(text) if zipfile.is_zipfile(text) else _tar_entries(text)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError) as exc:
        raise ValueError(f"cannot read {text!r} as a zip or tar archive: {exc}") from exc
    problems: list[str] = []
    for name, target, hard, special in entries:
        try:
            member_parts(name)
            if special:
                problems.append(f"{name!r}: device or FIFO member")
                continue
            if target is not None:
                link_target_parts(name, target, hard=hard)
        except UnsafePathError as exc:
            problems.append(f"{name!r}: {exc}")
    return len(entries), problems
