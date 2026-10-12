# safejoin

Path-traversal-safe joining of a trusted base directory with untrusted relative parts.
Typed, zero dependencies, tested on the real filesystem with real symlinks and
Windows junctions.

## Install

```
pip install safejoin
```

## Usage

```python
from pathlib import Path

from safejoin import UnsafePathError, safe_join, safe_open

base = Path("/srv/uploads")

# A normal request resolves to a path inside the base.
path = safe_join(base, "images", "avatar.png")

# Anything that would escape the base is refused, and the error names the part.
try:
    safe_join(base, "images", "../../etc/passwd")
except UnsafePathError as exc:
    print(exc.reason, exc.part)  # escape ../../etc/passwd

# Open without a window for a symlink swapped in after the check.
with safe_open(base, "images", "avatar.png", mode="rb") as handle:
    data = handle.read()
```

Archives:

```python
import zipfile

from safejoin import safe_member_path

with zipfile.ZipFile("upload.zip") as archive:
    for info in archive.infolist():
        target = safe_member_path("/srv/extract", info.filename)  # raises on zip slip
```

Command line:

```
safejoin check /srv/uploads images/cat.png   # prints the safe path, exit 0
safejoin check /srv/uploads ../etc/passwd    # message on stderr, exit 1
safejoin scan upload.zip                     # audits every member and link
safejoin --help                              # every option, with examples
```

## API

| Name | What it does |
| --- | --- |
| `safe_join(base, *parts, resolve=True, symlinks="allow_inside", windows_rules=None)` | Join and return the safe absolute path, or raise |
| `is_within(base, target, *, resolve=True)` | `True` when target is base or lies below it |
| `check_part(part, *, windows_rules=None)` | Validate one untrusted part without the filesystem |
| `safe_open(base, *parts, mode="r", ...)` | Open a regular file inside base with no link swap window |
| `member_parts(name)` | Validate a zip or tar member name, return its components |
| `safe_member_path(base, name)` | Where a member may be extracted, or raise |
| `link_target_parts(member, target, *, hard=False)` | Validate a tar link target inside the archive |
| `safe_link_target(base, member, target, *, hard=False)` | Check a link target against what is on disk |
| `UnsafePathError` | Base error (a `ValueError`) with `.part` and `.reason` |
| `AbsolutePartError`, `TraversalError`, `InvalidPartError`, `SymlinkError` | Its typed subclasses |
| `RESERVED_NAMES` | The Windows device names that are refused |

## Threat model in one page

`safejoin` guards code that takes a trusted base directory and a path fragment from
an untrusted source (a URL, a form field, a member name inside a zip or tar archive)
and joins them. The full statement, per mode, is in [GUIDE.md](GUIDE.md).

Refused, with the test that pins it:

- `..` that climbs above the base, even if later parts come back down
  (`tests/test_join.py`, `tests/test_corpus.py`).
- Absolute and rooted parts: `/etc`, `\Windows`, `C:\x`, drive-relative `C:x`,
  UNC `\\host\share` and `//host/share`, device paths `\\?\` and `\\.\`
  (`tests/test_rules.py`).
- NUL bytes, in every mode and on every platform.
- On Windows by default, and anywhere with `windows_rules=True`: device names
  (`CON`, `nul.txt`, `COM1`, `COM` with a superscript digit, `CONIN$`), alternate data
  streams (`file.txt:stream`, `dir::$INDEX_ALLOCATION`), names ending in a dot or space,
  characters Windows forbids, and look-alikes that compatibility normalisation or
  best-fit code page conversion turn into `/`, `\` or `:`. The best-fit list is checked
  against the real `WideCharToMultiByte` across 16 code pages
  (`test_every_best_fit_separator_is_refused`).
- Symlinks and junctions that lead outside the base (resolved mode), and every link
  below the base with `symlinks="deny"`. Real links are created in a temp directory;
  junctions with `_winapi.CreateJunction`, symlinks with `os.symlink` (skipped with a
  reason where the OS forbids them).
- A resolution that stops half way (a loop, a component that cannot be inspected):
  the resolved result is walked again and any link still present is refused.

Every accepted result in the contract corpus (over 2,000 hostile inputs, four modes)
and in seeded fuzzing is created on disk and checked to land inside the base with
nothing written outside.

Not covered, by design:

- **URL decoding.** `safejoin` never decodes `%2e%2e/`. Decode exactly once, then call
  it. A double-encoded input decoded twice is a caller bug.
- **Races between the check and later use** of a returned path (TOCTOU). Use
  `safe_open`, which closes that window on POSIX with `O_NOFOLLOW` and on Windows by
  checking the final path of the opened handle. See the guide for what remains.
- **Hard links.** A hard link is indistinguishable from an ordinary file by path.

## Background

- Zip Slip, the archive form of this bug:
  https://security.snyk.io/research/zip-slip-vulnerability
- CVE-2007-4559, path traversal in Python's `tarfile`:
  https://nvd.nist.gov/vuln/detail/CVE-2007-4559
- PEP 706, the `tarfile` extraction filters:
  https://peps.python.org/pep-0706/
- CVE-2025-4517, a `tarfile` filter bypass where `os.path.realpath()` stopped resolving
  without an error (the reason resolved mode verifies its own result):
  https://nvd.nist.gov/vuln/detail/CVE-2025-4517
- CVE-2024-49766, a safe join that missed UNC paths on Windows with Python before 3.11:
  https://nvd.nist.gov/vuln/detail/CVE-2024-49766
- WorstFit, best-fit code page conversion attacks on Windows: https://worst.fit/
- Windows naming rules: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
