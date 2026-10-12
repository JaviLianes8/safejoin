"""Audit every member name and link of a zip or tar archive without extracting it."""

from __future__ import annotations

import lzma
import os
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass

from ._archive import link_target_parts, member_parts
from ._errors import UnsafePathError

_ZIP_LINK_LIMIT = 4096
_READ_ERRORS = (
    tarfile.TarError,
    zipfile.BadZipFile,
    EOFError,
    NotImplementedError,
    RuntimeError,
    zlib.error,
    lzma.LZMAError,
)


@dataclass
class _Entry:
    name: str
    target: str | None = None
    hard: bool = False
    special: bool = False
    problem: str | None = None


def _zip_entries(path: str) -> list[_Entry]:
    entries: list[_Entry] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            entry = _Entry(info.filename)
            try:
                # Opening a member compares its local header name with the central
                # directory name; streaming unzip tools trust the local one.
                with archive.open(info) as member:
                    if stat.S_ISLNK(info.external_attr >> 16):
                        raw = member.read(_ZIP_LINK_LIMIT + 1)
                        if len(raw) > _ZIP_LINK_LIMIT:
                            raise zipfile.BadZipFile("oversized symlink target")
                        entry.target = raw.decode("utf-8", "surrogateescape")
            except _READ_ERRORS as exc:
                entry.problem = f"cannot verify member: {exc}"
            entries.append(entry)
    return entries


def _tar_entries(path: str) -> list[_Entry]:
    entries: list[_Entry] = []
    with tarfile.open(path, mode="r:*") as archive:
        for info in archive.getmembers():
            link = info.linkname if (info.issym() or info.islnk()) else None
            special = info.ischr() or info.isblk() or info.isfifo()
            entries.append(_Entry(info.name, link, info.islnk(), special))
    return entries


def _through_link(pieces: tuple[str, ...], links: set[tuple[str, ...]]) -> bool:
    return any(pieces[:size] in links for size in range(1, len(pieces)))


def _check(entry: _Entry, links: set[tuple[str, ...]]) -> str | None:
    if entry.problem is not None:
        return entry.problem
    pieces = member_parts(entry.name)
    if entry.special:
        return "device or FIFO member"
    if _through_link(pieces, links):
        return "its path passes through an earlier symlink member"
    if entry.target is None:
        return None
    landing = link_target_parts(entry.name, entry.target, hard=entry.hard)
    if not entry.hard:
        links.add(pieces)
        if not landing:
            return "symlink to the archive root"
    if _through_link((*landing, ""), links):
        return "its link target passes through an earlier symlink member"
    return None


def scan_archive(path: str | os.PathLike[str]) -> tuple[int, list[str]]:
    """Return the member count and a list of problems, one line per unsafe member.

    Member names go through ``member_parts`` and link targets through
    ``link_target_parts``. Also reported: device and FIFO members (PEP 706's ``data``
    filter refuses them), symlinks to the archive root, members or link targets whose
    path passes through an earlier symlink member, and zip members whose local header
    does not match the central directory. Nothing is extracted or written. Raises
    ``ValueError`` when the file is not a readable zip or tar archive.
    """
    text = os.fspath(path)
    try:
        entries = _zip_entries(text) if zipfile.is_zipfile(text) else _tar_entries(text)
    except _READ_ERRORS as exc:
        raise ValueError(f"cannot read {text!r} as a zip or tar archive: {exc}") from exc
    links: set[tuple[str, ...]] = set()
    problems: list[str] = []
    for entry in entries:
        try:
            problem = _check(entry, links)
        except UnsafePathError as exc:
            problem = str(exc)
        if problem is not None:
            problems.append(f"{entry.name!r}: {problem}")
    return len(entries), problems
