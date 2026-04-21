"""
SpindleX Performance Benchmark
Benchmarking connection times and performance metrics.
"""

import os
import statistics
import sys
import time

# Ensure local 'spindlex' module is used instead of any installed package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from spindlex import SSHClient

# --- CONFIGURATION ---
SSH_HOST = "my.server.com"
SSH_USER = "user"
SSH_PASS = "my-password"  # Leave as None if using key
SSH_KEY = None  # Path to private key file if needed
# ---------------------


def benchmark_spindlex(host, user, password, key_file, iterations=5):
    print(f"⏱️  Benchmarking SpindleX ({iterations} iterations)...")
    times = []
    for i in range(iterations):
        start = time.time()
        client = SSHClient()
        try:
            client.connect(
                hostname=host, username=user, password=password, key_filename=key_file
            )
            client.close()
            times.append(time.time() - start)
            print(f"   Run {i + 1}: {times[-1]:.4f}s")
        except Exception as e:
            print(f"   Run {i + 1} FAILED: {e}")

    if not times:
        return 0.0
    return statistics.mean(times)


def main():
    print("=" * 50)
    print("🚀 SPINDLEX: CONNECTION BENCHMARK")
    print("=" * 50)
    print(f"Target: {SSH_USER}@{SSH_HOST}")

    spindle_avg = benchmark_spindlex(SSH_HOST, SSH_USER, SSH_PASS, SSH_KEY)

    print("\n" + "=" * 50)
    print("📊 RESULTS (Average Connection Time):")
    print(f"   SpindleX: {spindle_avg:.4f}s")
    print("=" * 50)


if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"\n✨ Total execution time: {time.time() - start_time:.2f} seconds")
