from __future__ import annotations

import importlib.util
import sys
from email.message import Message
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


check_dependency_licenses = load_script("check_dependency_licenses")


class FakeDistribution:
    def __init__(
        self,
        name: str,
        version: str = "1.0.0",
        license_expression: str = "",
        license_text: str = "",
        classifiers: list[str] | None = None,
    ) -> None:
        self.metadata = Message()
        self.metadata["Name"] = name
        self.metadata["Version"] = version
        if license_expression:
            self.metadata["License-Expression"] = license_expression
        if license_text:
            self.metadata["License"] = license_text
        for classifier in classifiers or []:
            self.metadata["Classifier"] = classifier

    @property
    def name(self) -> str:
        return self.metadata["Name"]

    @property
    def version(self) -> str:
        return self.metadata["Version"]


def test_permissive_license_expression_passes():
    finding = check_dependency_licenses.distribution_finding(
        FakeDistribution(
            "cryptography", license_expression="Apache-2.0 OR BSD-3-Clause"
        ),
        check_dependency_licenses.DEFAULT_DENIED_LICENSES,
    )

    assert finding.denied_matches == []
    assert finding.unknown_license is False


def test_denied_license_classifier_fails():
    finding = check_dependency_licenses.distribution_finding(
        FakeDistribution(
            "copyleft-package",
            classifiers=[
                "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
            ],
        ),
        check_dependency_licenses.DEFAULT_DENIED_LICENSES,
    )

    assert finding.denied_matches == ["GPL"]


def test_lgpl_does_not_report_plain_gpl_match():
    finding = check_dependency_licenses.distribution_finding(
        FakeDistribution("weak-copyleft", license_expression="LGPL-3.0-only"),
        check_dependency_licenses.DEFAULT_DENIED_LICENSES,
    )

    assert finding.denied_matches == ["LGPL"]


def test_missing_license_metadata_is_unknown():
    finding = check_dependency_licenses.distribution_finding(
        FakeDistribution("unknown-package"),
        check_dependency_licenses.DEFAULT_DENIED_LICENSES,
    )

    assert finding.denied_matches == []
    assert finding.unknown_license is True


def test_scan_excludes_bootstrap_packages(monkeypatch):
    distributions = [
        FakeDistribution("pip", license_expression="MIT"),
        FakeDistribution("Runtime_Dep", license_expression="MIT"),
    ]
    monkeypatch.setattr(
        check_dependency_licenses.metadata,
        "distributions",
        lambda: distributions,
    )

    findings = check_dependency_licenses.scan_installed_distributions(
        check_dependency_licenses.DEFAULT_DENIED_LICENSES,
        ["PIP"],
    )

    assert [finding.name for finding in findings] == ["Runtime_Dep"]
