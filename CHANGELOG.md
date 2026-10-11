# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
