# safejoin guide

This guide states what each function promises, in which mode, and what it does not.

## Words

- **base**: the directory you trust. It is never validated as untrusted input, but a
  NUL byte in it is refused.
- **part**: an untrusted string (or `os.PathLike[str]`). Bytes are a `TypeError`.
- **inside**: equal to the base or below it, after normalisation. Comparison is
  case-insensitive on Windows and case-sensitive elsewhere.

## Order of checks in `safe_join`

1. `symlinks` must be `"allow_inside"` or `"deny"`, otherwise `ValueError`.
2. Each part goes through `check_part`:
   - a NUL byte raises `InvalidPartError`;
   - an absolute or rooted part raises `AbsolutePartError`. On POSIX without Windows
     rules that means a leading `/`. On Windows, or with `windows_rules=True`, it also
     means a drive (`C:`, `C:x`), a leading `\`, UNC (`\\host\share`, `//host/share`)
     and device paths (`\\?\`, `\\.\`);
   - under Windows rules each component is checked for device names, forbidden
     characters (including `:`, so alternate data streams), a trailing dot or space,
     and look-alike characters (see below), raising `InvalidPartError`.
3. Components are counted lexically. A `..` that would climb above the base raises
   `TraversalError`, even if later parts come back down (`../base/x`). This matters
   when the base itself is a symlink: the OS would climb from the link's target.
4. The joined path is normalised lexically (`os.path.abspath`) and must be inside the
   lexical base. On Windows this also catches names that `GetFullPathName` sends to the
   device namespace, such as `NUL`.
5. **Resolved mode** (`resolve=True`, default): base and joined path are resolved with
   `Path.resolve()`, which follows symlinks and junctions, including dangling ones. The
   result must be inside the resolved base, and every existing component below the base
   is checked again with `lstat`: if one is still a link, or cannot be inspected, the
   resolution did not finish (a loop, a permission error, an over-long path) and
   `SymlinkError` is raised. A link that leads outside raises `TraversalError`.
6. **`symlinks="deny"`**: every existing component below the base, in the path as
   written, is checked with `lstat`; a symlink or a junction raises `SymlinkError`,
   even when it points inside. Other Windows reparse points (cloud placeholders) are
   treated as ordinary files.

The returned path is absolute: resolved in resolved mode, lexical otherwise.

## Guarantees per mode

| Mode | At the moment of the call, the returned path... |
| --- | --- |
| `resolve=True` | resolves inside the base through any links that exist |
| `resolve=True, symlinks="deny"` | is inside and reaches no symlink or junction |
| `resolve=False, symlinks="deny"` | is inside lexically and reaches no link |
| `resolve=False` | is inside **lexically only**; a link below the base is not followed |

Plain lexical mode never touches the filesystem. Use it for paths that are not on
this machine (for example, a remote store) or when you control every link below the
base.

## Windows rules

`windows_rules=None` (default) means on when running on Windows and off elsewhere.
Pass `True` to apply them on any platform, for example when the files may later be
copied to Windows. They refuse:

- device names in `RESERVED_NAMES` (`CON`, `PRN`, `AUX`, `NUL`, `COM0` to `COM9`,
  `LPT0` to `LPT9`, the superscript digit variants and `CONIN$`, `CONOUT$`), in any
  case, with any extension, and with spaces before the extension (`CON .txt`);
- `< > : " | ? *` and control characters, so `file.txt:stream` and
  `dir::$INDEX_ALLOCATION` are refused;
- a name ending in a dot or a space, which Windows strips (`secret.txt.` would alias
  `secret.txt`);
- characters whose NFKC form contains a separator, a colon or a forbidden character,
  or is a dot-only or device name (full-width `．．`, `／`, `ＣＯＮ`);
- characters that best-fit code page conversion turns into `/`, `\` or `:` (for
  example the yen sign in cp932 and the division slash in cp1252). A program that later
  passes the name through a narrow ("A") Windows API would otherwise see a separator.

## `safe_open`

`safe_open` runs `safe_join` (resolved mode, with the `symlinks` and `windows_rules`
you pass), then:

- **POSIX**: opens the resolved base, then each directory with
  `O_DIRECTORY | O_NOFOLLOW` relative to the previous descriptor, then the file with
  `O_NOFOLLOW | O_NONBLOCK`. A symlink planted after the check makes it fail with
  `SymlinkError`; nothing outside is opened.
- **Windows**: opens the path, asks the OS for the final path of the handle with
  `GetFinalPathNameByHandleW`, and closes and refuses the handle unless that path is
  inside the resolved base (and, with `"deny"`, equal to the checked path).
  Truncation for `"w"` happens only after the check. What remains: a racing attacker
  who can swap a junction in the base between the check and the open can make a
  create (`"w"`, `"a"`, `"x"`) leave an empty file at the junction's target. No
  content outside the base is ever read, written or truncated.

On both, only regular files are returned: a FIFO or device in the base raises
`InvalidPartError` instead of blocking. Parent directories are not created.

## Archives

`member_parts(name)` applies the same rules on every platform, because archives
travel: `\` is a separator, absolute and drive names are refused, any `..` component
is refused, Windows rules always apply, empty and `.` components are dropped, and a
name with nothing left is refused.

`link_target_parts(member, target, hard=False)` validates a tar link target without
the filesystem. Symlink targets are relative to the member's directory; hard link
targets are relative to the archive root. `..` is allowed only as a leading run that
stays inside the archive: `a/..` is refused, because if `a` is a link the OS climbs
from its target, not from `a`.

That lexical view cannot see links created by earlier members, so at extraction time
use `safe_member_path` for every write and `safe_link_target` for every link. Both
resolve against what is already on disk, the way PEP 706's `data` filter does.
`safejoin scan` runs the lexical checks over a whole zip or tar file and also reports
device and FIFO members.

## What safejoin does not do

- It does not URL-decode. Decode once, then validate the decoded string.
- It cannot protect a path you use later with plain `open()`: the filesystem may
  change in between. Use `safe_open`, or open relative to directory descriptors
  yourself.
- It cannot detect hard links: they are ordinary directory entries.
- Case-insensitive or normalising filesystems (macOS, Windows) may map two different
  names to one file. That never moves a file outside the base, but deny lists keyed on
  names are not reliable there.
