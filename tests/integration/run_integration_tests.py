#!/usr/bin/env python3
"""
Integration Test Runner for SSH Library

This script runs comprehensive integration tests including:
- End-to-end client-server tests
- OpenSSH interoperability tests
- Performance benchmarks
- Stress tests

Usage:
    python run_integration_tests.py [options]

Options:
    --quick         Run only quick tests (skip slow benchmarks)
    --openssh       Include OpenSSH interoperability tests
    --performance   Run performance benchmarks
    --stress        Run stress tests
    --report        Generate detailed HTML report
    --output DIR    Output directory for reports (default: test_reports)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class IntegrationTestRunner:
    """Manages execution of integration tests."""

    def __init__(self, output_dir: str = "test_reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}
        self.start_time = None

    def run_test_suite(
        self,
        quick: bool = False,
        openssh: bool = False,
        performance: bool = False,
        stress: bool = False,
        generate_report: bool = False,
    ) -> Dict:
        """Run the integration test suite."""

        self.start_time = time.time()
        print("=" * 60)
        print("SSH LIBRARY INTEGRATION TEST SUITE")
        print("=" * 60)
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Output directory: {self.output_dir}")
        print()

        # Test categories to run
        test_categories = []

        # Always run basic integration tests
        test_categories.append(
            {
                "name": "Basic Integration Tests",
                "module": "tests/test_integration.py",
                "markers": "not slow",
                "required": True,
            }
        )

        if not quick:
            test_categories.append(
                {
                    "name": "Extended Integration Tests",
                    "module": "tests/test_integration.py",
                    "markers": "slow",
                    "required": False,
                }
            )

        if openssh:
            test_categories.append(
                {
                    "name": "OpenSSH Interoperability Tests",
                    "module": "tests/test_interoperability.py",
                    "markers": None,
                    "required": False,
                }
            )

        if performance:
            test_categories.extend(
                [
                    {
                        "name": "Performance Tests",
                        "module": "tests/test_performance.py",
                        "markers": None,
                        "required": False,
                    },
                    {
                        "name": "Benchmark Suite",
                        "module": "tests/test_benchmarks.py",
                        "markers": None,
                        "required": False,
                    },
                    {
                        "name": "Comprehensive Benchmarks",
                        "module": "tests/test_comprehensive_benchmarks.py",
                        "markers": "not stress" if not stress else None,
                        "required": False,
                    },
                ]
            )

        if stress:
            test_categories.append(
                {
                    "name": "Stress Tests",
                    "module": "tests/test_comprehensive_benchmarks.py",
                    "markers": "stress",
                    "required": False,
                }
            )

        # Run each test category
        overall_success = True

        for category in test_categories:
            success = self._run_test_category(category)
            if not success and category["required"]:
                overall_success = False

        # Generate summary
        self._generate_summary()

        if generate_report:
            self._generate_html_report()

        return {
            "success": overall_success,
            "results": self.results,
            "duration": time.time() - self.start_time,
        }

    def _run_test_category(self, category: Dict) -> bool:
        """Run a specific test category."""
        print(f"\n{'='*20} {category['name']} {'='*20}")

        # Build pytest command
        cmd = ["python", "-m", "pytest", category["module"], "-v"]

        if category["markers"]:
            cmd.extend(["-m", category["markers"]])

        # Add output options
        junit_file = (
            self.output_dir / f"{category['name'].lower().replace(' ', '_')}_junit.xml"
        )
        cmd.extend(["--junit-xml", str(junit_file)])

        # Add coverage if available
        try:
            import coverage

            cov_file = (
                self.output_dir
                / f"{category['name'].lower().replace(' ', '_')}_coverage.xml"
            )
            cmd.extend(["--cov=ssh_library", f"--cov-report=xml:{cov_file}"])
        except ImportError:
            pass

        # Run tests
        start_time = time.time()

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800
            )  # 30 min timeout
            duration = time.time() - start_time

            success = result.returncode == 0

            # Store results
            self.results[category["name"]] = {
                "success": success,
                "duration": duration,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": " ".join(cmd),
            }

            # Print summary
            status = "PASSED" if success else "FAILED"
            print(f"\n{category['name']}: {status} ({duration:.1f}s)")

            if not success:
                print("STDERR:")
                print(result.stderr)
                print("\nSTDOUT:")
                print(result.stdout[-1000:])  # Last 1000 chars

            return success

        except subprocess.TimeoutExpired:
            print(f"\n{category['name']}: TIMEOUT (30 minutes)")
            self.results[category["name"]] = {
                "success": False,
                "duration": 1800,
                "error": "Timeout after 30 minutes",
                "command": " ".join(cmd),
            }
            return False

        except Exception as e:
            print(f"\n{category['name']}: ERROR - {e}")
            self.results[category["name"]] = {
                "success": False,
                "duration": time.time() - start_time,
                "error": str(e),
                "command": " ".join(cmd),
            }
            return False

    def _generate_summary(self):
        """Generate test summary."""
        total_duration = time.time() - self.start_time

        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)

        passed = sum(1 for r in self.results.values() if r["success"])
        total = len(self.results)

        print(f"Total test categories: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Total duration: {total_duration:.1f}s")
        print()

        for name, result in self.results.items():
            status = "PASS" if result["success"] else "FAIL"
            duration = result.get("duration", 0)
            print(f"  {name:<40} {status:<6} ({duration:.1f}s)")

        # Save summary to JSON
        summary_file = self.output_dir / "test_summary.json"
        summary_data = {
            "timestamp": datetime.now().isoformat(),
            "total_duration": total_duration,
            "categories": self.results,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": total - passed,
                "success_rate": passed / total if total > 0 else 0,
            },
        }

        with open(summary_file, "w") as f:
            json.dump(summary_data, f, indent=2)

        print(f"\nDetailed results saved to: {summary_file}")

    def _generate_html_report(self):
        """Generate HTML test report."""
        html_file = self.output_dir / "integration_test_report.html"

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSH Library Integration Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .category {{ margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }}
        .category-header {{ background-color: #f8f8f8; padding: 10px; font-weight: bold; }}
        .category-content {{ padding: 10px; }}
        .pass {{ color: green; }}
        .fail {{ color: red; }}
        .command {{ font-family: monospace; background-color: #f5f5f5; padding: 5px; }}
        .output {{ font-family: monospace; background-color: #f9f9f9; padding: 10px; 
                   max-height: 300px; overflow-y: auto; white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SSH Library Integration Test Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Duration: {time.time() - self.start_time:.1f} seconds</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <ul>
"""

        passed = sum(1 for r in self.results.values() if r["success"])
        total = len(self.results)

        html_content += f"""
            <li>Total Categories: {total}</li>
            <li>Passed: <span class="pass">{passed}</span></li>
            <li>Failed: <span class="fail">{total - passed}</span></li>
            <li>Success Rate: {passed/total*100:.1f}%</li>
        </ul>
    </div>
    
    <h2>Test Categories</h2>
"""

        for name, result in self.results.items():
            status_class = "pass" if result["success"] else "fail"
            status_text = "PASSED" if result["success"] else "FAILED"
            duration = result.get("duration", 0)

            html_content += f"""
    <div class="category">
        <div class="category-header">
            {name} - <span class="{status_class}">{status_text}</span> ({duration:.1f}s)
        </div>
        <div class="category-content">
            <p><strong>Command:</strong></p>
            <div class="command">{result.get('command', 'N/A')}</div>
"""

            if not result["success"]:
                if "error" in result:
                    html_content += f"""
            <p><strong>Error:</strong></p>
            <div class="output">{result['error']}</div>
"""

                if "stderr" in result and result["stderr"]:
                    html_content += f"""
            <p><strong>Error Output:</strong></p>
            <div class="output">{result['stderr']}</div>
"""

            if "stdout" in result and result["stdout"]:
                html_content += f"""
            <p><strong>Output:</strong></p>
            <div class="output">{result['stdout'][-2000:]}</div>
"""

            html_content += """
        </div>
    </div>
"""

        html_content += """
</body>
</html>
"""

        with open(html_file, "w") as f:
            f.write(html_content)

        print(f"HTML report generated: {html_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run SSH Library Integration Tests")

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run only quick tests (skip slow benchmarks)",
    )
    parser.add_argument(
        "--openssh", action="store_true", help="Include OpenSSH interoperability tests"
    )
    parser.add_argument(
        "--performance", action="store_true", help="Run performance benchmarks"
    )
    parser.add_argument("--stress", action="store_true", help="Run stress tests")
    parser.add_argument(
        "--report", action="store_true", help="Generate detailed HTML report"
    )
    parser.add_argument(
        "--output",
        default="test_reports",
        help="Output directory for reports (default: test_reports)",
    )

    args = parser.parse_args()

    # Check if SSH library is available
    try:
        import ssh_library
    except ImportError:
        print("ERROR: ssh_library not found. Please install the library first.")
        sys.exit(1)

    # Create test runner
    runner = IntegrationTestRunner(args.output)

    # Run tests
    try:
        result = runner.run_test_suite(
            quick=args.quick,
            openssh=args.openssh,
            performance=args.performance,
            stress=args.stress,
            generate_report=args.report,
        )

        # Exit with appropriate code
        sys.exit(0 if result["success"] else 1)

    except KeyboardInterrupt:
        print("\n\nTest run interrupted by user.")
        sys.exit(130)

    except Exception as e:
        print(f"\nERROR: Test run failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
