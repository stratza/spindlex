#!/usr/bin/env python3
"""Fail when installed dependency licenses match the project deny policy."""

from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_DENIED_LICENSES = (
    "AGPL",
    "BUSL",
    "CDDL",
    "COMMERCIAL",
    "CPL",
    "EPL",
    "EUPL",
    "GPL",
    "LGPL",
    "OSL",
    "PROPRIETARY",
    "SSPL",
)


@dataclass(frozen=True)
class LicenseFinding:
    name: str
    version: str
    license_expression: str
    license_text: str
    classifiers: list[str]
    denied_matches: list[str]
    unknown_license: bool


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def denied_matches(evidence: Iterable[str], denied: Iterable[str]) -> list[str]:
    matches: set[str] = set()
    evidence_text = "\n".join(value for value in evidence if value).upper()

    for license_name in denied:
        token = re.escape(license_name.upper())
        pattern = re.compile(rf"(?<![A-Z0-9]){token}(?=$|[^A-Z0-9]|V[0-9])")
        if pattern.search(evidence_text):
            matches.add(license_name.upper())

    return sorted(matches)


def distribution_finding(
    distribution: metadata.Distribution,
    denied: Iterable[str],
) -> LicenseFinding:
    package_metadata = distribution.metadata
    name = package_metadata.get("Name", distribution.name)
    version = package_metadata.get("Version", distribution.version)
    license_expression = package_metadata.get("License-Expression", "")
    license_text = package_metadata.get("License", "")
    classifiers = package_metadata.get_all("Classifier") or []
    license_classifiers = [
        classifier for classifier in classifiers if classifier.startswith("License ::")
    ]
    evidence = [license_expression, license_text, *license_classifiers]
    unknown_license = not any(value.strip() for value in evidence)

    return LicenseFinding(
        name=name,
        version=version,
        license_expression=license_expression,
        license_text=license_text,
        classifiers=license_classifiers,
        denied_matches=denied_matches(evidence, denied),
        unknown_license=unknown_license,
    )


def scan_installed_distributions(
    denied: Iterable[str],
    excluded_packages: Iterable[str],
) -> list[LicenseFinding]:
    excluded = {canonical_name(name) for name in excluded_packages}
    findings = []

    for distribution in metadata.distributions():
        finding = distribution_finding(distribution, denied)
        if canonical_name(finding.name) in excluded:
            continue
        findings.append(finding)

    return sorted(findings, key=lambda finding: canonical_name(finding.name))


def write_report(path: Path, findings: list[LicenseFinding]) -> None:
    payload = {
        "dependencies": [asdict(finding) for finding in findings],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--deny",
        action="append",
        default=[],
        help="Denied license token. Defaults to the project deny policy.",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Installed package name to exclude from evaluation.",
    )
    parser.add_argument(
        "--fail-on-unknown",
        action="store_true",
        help="Fail dependencies that do not expose license metadata.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    args = parser.parse_args(argv)

    denied = args.deny or list(DEFAULT_DENIED_LICENSES)
    findings = scan_installed_distributions(denied, args.exclude)
    failing = [
        finding
        for finding in findings
        if finding.denied_matches or (args.fail_on_unknown and finding.unknown_license)
    ]

    if args.output:
        write_report(args.output, findings)

    if failing:
        print("Dependency license policy violations detected:")
        for finding in failing:
            reason = (
                ", ".join(finding.denied_matches)
                if finding.denied_matches
                else "missing license metadata"
            )
            print(f"- {finding.name} {finding.version}: {reason}")
        return 1

    print(f"Checked {len(findings)} installed distributions; no denied licenses found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
