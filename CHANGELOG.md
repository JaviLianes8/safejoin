# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

### Security

- NUL bytes in a part or in the base are refused with `InvalidPartError`; 0.1
  accepted them and could return a path containing NUL.
- A `..` that climbs above the base is refused even when later parts come back down
  (`../base/x`), which could leave the base when the base itself is a symlink.
- On Windows (or anywhere with `windows_rules=True`), device names such as `CON`,
  `nul.txt` and `COM1`, alternate data streams (`file.txt:stream`), names ending in a
  dot or a space, forbidden characters and look-alike or best-fit characters that
  become separators are refused. 0.1 accepted them.
- Resolved mode now verifies its own result: a link left unresolved below the base
  (a loop, an over-long path, an unreadable component) is refused with `SymlinkError`
  instead of being trusted or surfacing as `RuntimeError` or `OSError`.
- Resolved mode also applies the lexical check, so a name Windows maps to the device
  namespace (`NUL`) is refused even with Windows rules off; `is_within` reports such a
  target as outside.
- Containment ignores the Win32 `\\?\` prefix on either side and treats any leftover
  `..` as outside, which removes a false rejection and a lexical blind spot.

### Added

- Typed errors `AbsolutePartError`, `TraversalError`, `InvalidPartError` and
  `SymlinkError`, all subclasses of `UnsafePathError`, with `.part` naming the
  offending input and `.reason`.
- `safe_join(..., symlinks="deny")` refuses any symlink or junction below the base;
  `windows_rules=` turns Windows naming rules on or off explicitly.
- `check_part` validates one untrusted part without the filesystem.
- `safe_open` opens a regular file inside the base with `O_NOFOLLOW` descriptor walks
  on POSIX and a final-path check on Windows, truncating only after the check.
- `member_parts`, `safe_member_path`, `link_target_parts` and `safe_link_target` for
  zip and tar extraction.
- `RESERVED_NAMES`, the Windows device names that are refused.
- A `safejoin` command with `check`, `within`, `member` and `scan`.
- `GUIDE.md` with the threat model and the guarantee of each mode.

## [0.1.0]

- First release.
- `safe_join(base, *parts)` joins untrusted parts onto a trusted base and
  returns an absolute path, raising `UnsafePathError` on any attempt to escape
  the base through `..`, an absolute or rooted part, a Windows drive change, or
  a symlink that points outside the base.
- `is_within(base, target)` reports whether a path stays inside a base.
- Both accept `resolve=False` for a purely lexical check that never touches the
  filesystem. Guards the path traversal / zip slip threat model. Zero runtime
  dependencies, fully typed, ships `py.typed`.
