# safejoin

Path-traversal-safe joining of a trusted base directory with untrusted relative parts.

## Install

```
pip install safejoin
```

## Usage

```python
from pathlib import Path

from safejoin import UnsafePathError, is_within, safe_join

base = Path("/srv/uploads")

# A normal request resolves to a path inside the base.
path = safe_join(base, "images", "avatar.png")

# Anything that would escape the base is refused.
try:
    safe_join(base, "..", "..", "etc", "passwd")
except UnsafePathError:
    reject_request()

# safe_join also refuses absolute parts and, on Windows, a drive change.
safe_join(base, "/etc/passwd")   # raises UnsafePathError
safe_join(base, r"D:\secrets")   # raises UnsafePathError on Windows

# Check containment without joining.
is_within(base, "/srv/uploads/images/avatar.png")  # True
is_within(base, "/etc/passwd")                      # False
```

By default `safe_join` and `is_within` call `Path.resolve()`, so symlinks are
followed before the containment check: a symlink inside the base that points
outside it is rejected. Pass `resolve=False` for a purely lexical comparison
that collapses `..` without touching the filesystem (faster, but blind to
symlinks). The returned path is always absolute.

## Threat model

`safejoin` guards the classic **path traversal / zip slip** problem: code that
takes a trusted base directory and a path fragment from an untrusted source (a
URL, a form field, a filename inside a zip or tar archive) and joins them. An
attacker tries to break out of the base with `../` sequences, an absolute path,
a Windows drive letter, or a symlink that points elsewhere. `safe_join` returns
a path only when it provably stays inside the base, and raises `UnsafePathError`
otherwise. It validates paths; it does not open, read or write files.

## Why

The standard library has no safe join: `os.path.join` and `pathlib` happily
let `..` and absolute parts escape the base. The well-known helper is
`werkzeug.utils.safe_join`, but reaching for it pulls in a web framework, it
returns `None` on failure rather than raising, and it does not resolve
symlinks. `safejoin` is a single, standalone, fully typed primitive with zero
dependencies that raises on the failure path and is explicit about symlink
handling.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
