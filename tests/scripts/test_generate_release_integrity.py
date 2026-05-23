from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[2] / "scripts"


def load_script(name: str):
    path = SCRIPT_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


generate_release_integrity = load_script("generate_release_integrity")


def test_generate_release_integrity_writes_hashes_and_sbom(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    output = tmp_path / "integrity"
    dist.mkdir()
    (dist / "example.whl").write_bytes(b"wheel")
    (dist / "example.tar.gz").write_bytes(b"sdist")

    records = generate_release_integrity.generate(dist, output)

    assert [record["file"] for record in records] == [
        "example.tar.gz",
        "example.whl",
    ]
    assert (output / "SHA256SUMS").exists()
    assert (output / "sbom.spindlex.json").exists()
