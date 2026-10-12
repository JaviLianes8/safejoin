"""The ``safejoin`` command line tool."""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections.abc import Sequence
from typing import NoReturn

from ._errors import UnsafePathError
from ._join import is_within, safe_join
from ._scan import scan_archive

EXAMPLES = """\
examples:
  safejoin check /srv/uploads images/cat.png      # prints the safe absolute path
  safejoin check /srv/uploads ../etc/passwd       # unsafe: message on stderr, exit 1
  safejoin check --deny-symlinks /srv/data a/b    # also refuse any link below the base
  safejoin check --lexical --windows-rules on base "CON.txt"   # exit 1: device name
  safejoin check --json /srv/uploads a.txt        # {"safe": true, "path": ...}
  safejoin within /srv/uploads /srv/uploads/a     # prints inside, exit 0
  safejoin member "docs/readme.txt" "../evil"     # checks archive member names
  safejoin scan upload.zip                        # audits every member and link

exit status: 0 when everything is safe, 1 when anything is unsafe or on error.
"""


class _Parser(argparse.ArgumentParser):
    """Argument parser whose usage errors exit with status 1 like every other error."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser for the ``safejoin`` command."""
    parser = _Parser(
        prog="safejoin",
        description="Check untrusted paths against a trusted base directory.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    check = sub.add_parser("check", help="join parts onto a base and print the safe path")
    check.add_argument("base", help="trusted base directory")
    check.add_argument("parts", nargs="+", help="untrusted relative parts")
    check.add_argument("--lexical", action="store_true", help="do not follow links")
    check.add_argument("--deny-symlinks", action="store_true", help="refuse any link")
    check.add_argument(
        "--windows-rules",
        choices=("auto", "on", "off"),
        default="auto",
        help="Windows naming rules (auto: only on Windows)",
    )
    check.add_argument("--json", action="store_true", help="print a JSON object")
    within = sub.add_parser("within", help="print whether a path lies inside a base")
    within.add_argument("base")
    within.add_argument("target")
    within.add_argument("--lexical", action="store_true", help="do not follow links")
    member = sub.add_parser("member", help="validate zip or tar member names")
    member.add_argument("names", nargs="+")
    scan = sub.add_parser("scan", help="audit every member and link of a zip or tar file")
    scan.add_argument("archive")
    return parser


def _check(args: argparse.Namespace) -> int:
    rules = {"auto": None, "on": True, "off": False}[args.windows_rules]
    try:
        path = safe_join(
            args.base,
            *args.parts,
            resolve=not args.lexical,
            symlinks="deny" if args.deny_symlinks else "allow_inside",
            windows_rules=rules,
        )
    except UnsafePathError as exc:
        if args.json:
            report = {"safe": False, "reason": exc.reason, "part": exc.part, "message": str(exc)}
            print(json.dumps(report))
        print(f"safejoin: unsafe ({exc.reason}): {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"safe": True, "path": str(path)}) if args.json else path)
    return 0


def _within(args: argparse.Namespace) -> int:
    inside = is_within(args.base, args.target, resolve=not args.lexical)
    print("inside" if inside else "outside")
    return 0 if inside else 1


def _member(args: argparse.Namespace) -> int:
    from ._archive import member_parts

    status = 0
    for name in args.names:
        try:
            print("/".join(member_parts(name)))
        except UnsafePathError as exc:
            print(f"safejoin: unsafe ({exc.reason}): {exc}", file=sys.stderr)
            status = 1
    return status


def _scan(args: argparse.Namespace) -> int:
    count, problems = scan_archive(args.archive)
    for problem in problems:
        print(f"safejoin: unsafe: {problem}", file=sys.stderr)
    print(f"{count} members checked, {len(problems)} unsafe")
    return 1 if problems else 0


def _tolerant_streams() -> None:
    """Never crash on a path the console encoding cannot show."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line tool and return its exit status."""
    _tolerant_streams()
    args = build_parser().parse_args(argv)
    handlers = {"check": _check, "within": _within, "member": _member, "scan": _scan}
    try:
        return handlers[args.command](args)
    except (OSError, ValueError) as exc:
        print(f"safejoin: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
