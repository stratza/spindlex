#!/usr/bin/env python3
"""
SSH performance benchmark tool.

A tool for benchmarking SSH operations and comparing performance (part of Spindle).
"""

import argparse
import statistics
import time
from typing import Any, Optional

from ..client.ssh_client import SSHClient
from ..crypto.backend import get_crypto_backend


def benchmark_connection(
    hostname: str,
    username: str,
    password: Optional[str] = None,
    key_filename: Optional[str] = None,
    iterations: int = 10,
) -> dict[str, Any]:
    """Benchmark SSH connection establishment."""
    times = []

    for _i in range(iterations):
        start_time = time.time()

        client = SSHClient()
        try:
            client.connect(
                hostname=hostname,
                username=username,
                password=password,
                key_filename=key_filename,
                timeout=30,
            )
            connect_time = time.time() - start_time
            times.append(connect_time)
        finally:
            client.close()

    return {
        "operation": "connection",
        "iterations": iterations,
        "times": times,
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0,
        "min": min(times),
        "max": max(times),
    }


def benchmark_command_execution(
    client: SSHClient, command: str, iterations: int = 10
) -> dict[str, Any]:
    """Benchmark command execution."""
    times = []

    for _i in range(iterations):
        start_time = time.time()

        stdin, stdout, stderr = client.exec_command(command)
        stdout.read()  # Read all output
        stderr.read()  # Read all errors

        exec_time = time.time() - start_time
        times.append(exec_time)

    return {
        "operation": f"exec_command: {command}",
        "iterations": iterations,
        "times": times,
        "mean": statistics.mean(times),
        "median": statistics.median(times),
        "stdev": statistics.stdev(times) if len(times) > 1 else 0,
        "min": min(times),
        "max": max(times),
    }


def benchmark_crypto_operations(iterations: int = 1000) -> list[dict[str, Any]]:
    """Benchmark cryptographic operations."""
    get_crypto_backend()
    results = []

    # Benchmark key generation
    for key_type in ["ed25519", "ecdsa", "rsa"]:
        times = []

        for _i in range(min(iterations, 10)):  # Limit key gen iterations
            start_time = time.time()

            if key_type == "ed25519":
                from ..crypto.pkey import Ed25519Key

                Ed25519Key.generate()
            elif key_type == "ecdsa":
                from ..crypto.pkey import ECDSAKey

                ECDSAKey.generate()
            elif key_type == "rsa":
                from ..crypto.pkey import RSAKey

                RSAKey.generate(bits=2048)

            gen_time = time.time() - start_time
            times.append(gen_time)

        results.append(
            {
                "operation": f"{key_type}_key_generation",
                "iterations": len(times),
                "times": times,
                "mean": statistics.mean(times),
                "median": statistics.median(times),
                "stdev": statistics.stdev(times) if len(times) > 1 else 0,
                "min": min(times),
                "max": max(times),
            }
        )

    return results


def print_benchmark_results(results: list[dict[str, Any]]) -> None:
    """Print benchmark results in a formatted table."""
    print("\nBenchmark Results")
    print("=" * 80)
    print(
        f"{'Operation':<30} {'Iterations':<10} {'Mean (s)':<12} {'Median (s)':<12} {'StdDev (s)':<12}"
    )
    print("-" * 80)

    for result in results:
        print(
            f"{result['operation']:<30} {result['iterations']:<10} "
            f"{result['mean']:<12.4f} {result['median']:<12.4f} {result['stdev']:<12.4f}"
        )


def main() -> int:
    """Main entry point for ssh-benchmark tool."""
    parser = argparse.ArgumentParser(
        description="Benchmark SSH operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  spindle-benchmark --crypto-only
  spindle-benchmark -H example.com -u user -p password
  spindle-benchmark -H example.com -u user -k ~/.ssh/id_rsa --iterations 20
        """,
    )

    parser.add_argument("-H", "--hostname", help="SSH server hostname")

    parser.add_argument("-u", "--username", help="SSH username")

    parser.add_argument("-p", "--password", help="SSH password")

    parser.add_argument("-k", "--key-filename", help="SSH private key file")

    parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=10,
        help="Number of iterations for each benchmark (default: 10)",
    )

    parser.add_argument(
        "--crypto-only", action="store_true", help="Only run cryptographic benchmarks"
    )

    parser.add_argument(
        "--commands",
        nargs="+",
        default=["echo hello", "ls -la", "uname -a"],
        help="Commands to benchmark (default: echo hello, ls -la, uname -a)",
    )

    args = parser.parse_args()

    results = []

    # Always run crypto benchmarks
    print("Running cryptographic benchmarks...")
    crypto_results = benchmark_crypto_operations(args.iterations)
    results.extend(crypto_results)

    if not args.crypto_only:
        if not args.hostname or not args.username:
            print("Error: hostname and username required for SSH benchmarks")
            parser.print_help()
            return 1

        if not args.password and not args.key_filename:
            print("Error: either password or key filename required")
            parser.print_help()
            return 1

        # Benchmark connection
        print(f"Benchmarking connections to {args.hostname}...")
        conn_result = benchmark_connection(
            args.hostname,
            args.username,
            args.password,
            args.key_filename,
            args.iterations,
        )
        results.append(conn_result)

        # Benchmark commands
        client = SSHClient()
        try:
            client.connect(
                hostname=args.hostname,
                username=args.username,
                password=args.password,
                key_filename=args.key_filename,
            )

            for command in args.commands:
                print(f"Benchmarking command: {command}")
                cmd_result = benchmark_command_execution(
                    client, command, args.iterations
                )
                results.append(cmd_result)

        finally:
            client.close()

    # Print results
    print_benchmark_results(results)

    return 0


if __name__ == "__main__":
    exit(main())
