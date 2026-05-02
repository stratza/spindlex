#!/usr/bin/env python3
"""Keep runtime version metadata derived from pyproject.toml."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.9/3.10 in CI
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
VERSION_FILE = ROOT / "spindlex" / "_version.py"
VERSION_PATTERN = re.compile(r'(?m)^(version\s*=\s*)"([^"]+)"')
SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def read_pyproject_version(pyproject: Path = PYPROJECT) -> str:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    version = data.get("project", {}).get("version")
    if not isinstance(version, str):
        raise ValueError("pyproject.toml does not define project.version")
    validate_version(version)
    return version


def validate_version(version: str) -> None:
    if not SEMVER_PATTERN.fullmatch(version):
        raise ValueError(f"Unsupported version format: {version!r}")


def version_info(version: str) -> tuple[int, int, int]:
    validate_version(version)
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def write_pyproject_version(version: str, pyproject: Path = PYPROJECT) -> None:
    validate_version(version)
    content = pyproject.read_text(encoding="utf-8")
    updated, count = VERSION_PATTERN.subn(rf'\g<1>"{version}"', content, count=1)
    if count != 1:
        raise ValueError("Could not update project.version in pyproject.toml")
    pyproject.write_text(updated, encoding="utf-8")


def render_version_file(version: str) -> str:
    major, minor, patch = version_info(version)
    return (
        "# spindlex/_version.py\n\n"
        f'__version__ = "{version}"\n'
        f"__version_info__ = ({major}, {minor}, {patch})\n\n\n"
        "def get_version() -> str:\n"
        '    """Return the current version as a string."""\n'
        "    return __version__\n\n\n"
        "def get_version_info() -> tuple[int, int, int]:\n"
        '    """Return the current version as a tuple of integers."""\n'
        "    return __version_info__\n"
    )


def write_version_file(version: str, version_file: Path = VERSION_FILE) -> None:
    version_file.write_text(render_version_file(version), encoding="utf-8")


def sync_version(version: str | None = None) -> str:
    target_version = version or read_pyproject_version()
    validate_version(target_version)
    if version is not None:
        write_pyproject_version(target_version)
    write_version_file(target_version)
    return target_version


def check_synced() -> bool:
    version = read_pyproject_version()
    expected = render_version_file(version)
    return VERSION_FILE.read_text(encoding="utf-8") == expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="Optional version to write to pyproject.toml.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate that spindlex/_version.py is derived from pyproject.toml.",
    )
    args = parser.parse_args(argv)

    if args.check:
        if check_synced():
            print("Version metadata is synced.")
            return 0
        print(
            "spindlex/_version.py is not derived from pyproject.toml.",
            file=sys.stderr,
        )
        return 1

    version = sync_version(args.version)
    print(f"Synced project version metadata to {version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
