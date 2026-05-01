#!/usr/bin/env python3
"""Export runtime dependencies from pyproject.toml as requirements text."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def runtime_dependencies(pyproject_path: Path) -> list[str]:
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    dependencies = data.get("project", {}).get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("project.dependencies must be a list.")

    return [dependency for dependency in dependencies if isinstance(dependency, str)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    dependencies = runtime_dependencies(args.pyproject)
    args.output.write_text("\n".join(dependencies) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
