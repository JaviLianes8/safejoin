import importlib.resources

import pytest

import safejoin

# The public API. Add every exported name here as the library grows; this list is the
# contract and the test below fails if the module and this list disagree.
PUBLIC_API: list[str] = [
    "RESERVED_NAMES",
    "AbsolutePartError",
    "InvalidPartError",
    "SymlinkError",
    "SymlinkPolicy",
    "TraversalError",
    "UnsafePathError",
    "check_part",
    "is_within",
    "link_target_parts",
    "member_parts",
    "safe_join",
    "safe_link_target",
    "safe_member_path",
    "safe_open",
]


def test_all_lists_exactly_the_public_api() -> None:
    assert sorted(safejoin.__all__) == sorted(PUBLIC_API)


def test_every_exported_name_resolves() -> None:
    for name in safejoin.__all__:
        assert hasattr(safejoin, name)


def test_version_is_a_three_part_string() -> None:
    parts = safejoin.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)


def test_the_package_ships_type_information() -> None:
    assert importlib.resources.files("safejoin").joinpath("py.typed").is_file()


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (safejoin.AbsolutePartError, "absolute"),
        (safejoin.TraversalError, "escape"),
        (safejoin.InvalidPartError, "invalid"),
        (safejoin.SymlinkError, "symlink"),
    ],
)
def test_every_error_is_an_unsafe_path_error_and_a_value_error(
    error: type[safejoin.UnsafePathError], reason: str
) -> None:
    instance = error("message", part="p")
    assert isinstance(instance, safejoin.UnsafePathError)
    assert isinstance(instance, ValueError)
    assert (instance.reason, instance.part, str(instance)) == (reason, "p", "message")


def test_the_base_error_keeps_its_0_1_constructor() -> None:
    error = safejoin.UnsafePathError("message")
    assert (error.part, error.reason, str(error)) == (None, "unsafe", "message")


def test_reserved_names_cover_every_windows_device() -> None:
    expected = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    expected |= {
        f"{p}{d}" for p in ("COM", "LPT") for d in "0123456789" + chr(0xB9) + chr(0xB2) + chr(0xB3)
    }
    assert expected == safejoin.RESERVED_NAMES
