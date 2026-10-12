# safejoin improvement round

A ranked list of substantial, coherent improvements for this round. The API stays
additive: `safe_join`, `is_within` and `UnsafePathError` keep their signatures, and
every new error is a subclass of `UnsafePathError` (itself a `ValueError`). Where the
round rejects input that 0.1 accepted, the input was unsafe and the change is listed
under Security in the changelog.

## Starting point

0.1 joined parts onto a base and checked containment either lexically or after
`Path.resolve()`. Probing it on a real Windows filesystem with real junctions and
symlinks showed it blocked `..`, absolute parts, drive changes and links that point
outside, but also that:

- a part with a NUL byte was accepted and returned a path containing NUL;
- Windows device names (`CON`, `COM1`, `CONOUT$`, `COM` plus a superscript digit),
  alternate data streams (`file.txt:stream`, `dir::$INDEX_ALLOCATION`) and names with
  trailing dots or spaces were accepted, although Windows aliases or redirects them;
- `Path.resolve()` can return a `\\?\`-prefixed path for some inputs, which made the
  containment check reject safe input with a confusing message;
- a base written with the `\\?\` prefix compared lexically with a remainder that
  could still hold `..`;
- `resolve()` failures (symlink loops, over-long paths) surfaced as `RuntimeError` or
  `OSError`, and a non-strict resolve that silently stops following links (the
  CVE-2025-4517 class in `tarfile`) would have been trusted;
- the error never said which part was at fault.

## Ranked improvements

1. **Resolved mode that verifies itself.** After `resolve()`, walk every existing
   component below the base and refuse the result if any is still a symlink or
   junction, or cannot be inspected. A resolve that gave up half way can no longer
   produce a false "inside". Loops and resolution errors become `SymlinkError`.

2. **Symlink policy.** `symlinks="allow_inside"` (default, the 0.1 behaviour) or
   `symlinks="deny"`, which refuses any symlink or junction below the base, even one
   that points inside it. Works in both resolved and lexical modes.

3. **Windows rules.** `windows_rules=None` (on when running on Windows), `True` or
   `False`. Rejects reserved device names with any extension or trailing dots and
   spaces, alternate data streams and every other character Windows forbids in a name,
   names ending in a dot or space, and look-alike characters that compatibility
   normalisation or common code page best-fit mappings turn into a separator, a colon
   or a dot-only name.

4. **Typed errors that name the part.** `AbsolutePartError`, `TraversalError`,
   `InvalidPartError` and `SymlinkError`, each carrying `.part` (the offending
   untrusted input) and `.reason`.

5. **`safe_open`.** Opens a file inside the base without a window for link swaps:
   on POSIX it walks from a descriptor of the base with `O_NOFOLLOW` on every step;
   on Windows it opens, asks the OS for the final path of the handle and refuses it if
   it is outside the base, truncating only after that check. Only regular files are
   opened, so a planted FIFO or device cannot block or hijack the caller.

6. **Archive member validation.** `member_parts(name)` validates a zip or tar member
   name with platform-independent rules (backslash is a separator, drives, UNC and
   absolute names refused, `..` refused, Windows rules always on) and returns its safe
   components. `safe_member_path(base, name)` joins it, and `link_target_parts`
   checks tar symlink and hard link targets the way PEP 706's data filter does.

7. **`check_part`.** Validate one untrusted part without touching the filesystem,
   useful at the edge of an API before a path is ever built.

8. **A command line tool.** `safejoin check`, `within`, `member` and `scan` (audit
   every member and link of a zip or tar file), runnable examples in `--help`, results
   on stdout, problems on stderr and exit code 1 for anything unsafe.

9. **Documentation of the threat model.** Docstrings on every public name, a
   `GUIDE.md` that states each guarantee per mode, the TOCTOU and hard link limits
   honestly, and references to zip slip, the `tarfile` CVEs and PEP 706.

10. **Contracts on the real filesystem.** A large corpus of hostile parts run against
    a real directory tree with real junctions and symlinks, where every accepted result
    is created on disk and checked to land inside the base with nothing written
    outside; seeded fuzzing of the same property; and a real end to end test that
    builds the wheel, installs it into a throwaway virtual environment and drives the
    installed `safejoin` script.

## Out of scope

URL decoding: `safejoin` never decodes `%2e%2e` or similar. Callers must decode
exactly once before calling it, and a decoded string is then checked like any other.
Hard links cannot be told apart from ordinary files by path, so they are documented as
a limit rather than half handled.
