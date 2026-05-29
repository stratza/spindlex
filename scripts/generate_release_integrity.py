#!/usr/bin/env python3
"""Generate release artifact hashes and a minimal SBOM artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate(dist: Path, output_dir: Path) -> list[dict[str, str]]:
    artifacts = sorted(path for path in dist.iterdir() if path.is_file())
    output_dir.mkdir(parents=True, exist_ok=True)

    records = [
        {
            "file": artifact.name,
            "sha256": sha256(artifact),
            "size_bytes": str(artifact.stat().st_size),
        }
        for artifact in artifacts
    ]

    sums = "\n".join(f"{record['sha256']}  {record['file']}" for record in records)
    (output_dir / "SHA256SUMS").write_text(sums + "\n", encoding="utf-8")

    sbom = {
        "schema": "spindlex-release-sbom-v1",
        "tool": "scripts/generate_release_integrity.py",
        "python": platform.python_version(),
        "artifacts": records,
    }
    (output_dir / "sbom.spindlex.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist-integrity"))
    args = parser.parse_args(argv)

    records = generate(args.dist, args.output_dir)
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
