"""
SpindleX vs Paramiko Benchmark
Compare the performance of connection times and SFTP transfers.
"""

import statistics
import time

from spindlex import SSHClient

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# --- CONFIGURATION ---
SSH_HOST = "my.server.com"
SSH_USER = "user"
SSH_PASS = "my-password"  # Leave as None if using key

SSH_KEY  = None        # Path to private key file if needed
# ---------------------

def benchmark_spindlex(host, user, password, key_file, iterations=5):
    print(f"⏱️  Benchmarking SpindleX ({iterations} iterations)...")
    times = []
    for i in range(iterations):
        start = time.time()
        client = SSHClient()
        client.connect(hostname=host, username=user, password=password, key_filename=key_file)
        client.close()
        times.append(time.time() - start)
        print(f"   Run {i+1}: {times[-1]:.4f}s")
    return statistics.mean(times)

def benchmark_paramiko(host, user, password, key_file, iterations=5):
    if not PARAMIKO_AVAILABLE:
        return None
    print(f"⏱️  Benchmarking Paramiko ({iterations} iterations)...")
    times = []
    for i in range(iterations):
        start = time.time()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507

        client.connect(hostname=host, username=user, password=password, key_filename=key_file)
        client.close()
        times.append(time.time() - start)
        print(f"   Run {i+1}: {times[-1]:.4f}s")
    return statistics.mean(times)

def main():
    print("="*50)
    print("🚀 SPINDLEX VS PARAMIKO: CONNECTION BENCHMARK")
    print("="*50)
    print(f"Target: {SSH_USER}@{SSH_HOST}")
    
    if not PARAMIKO_AVAILABLE:
        print("💡 Paramiko is not installed. Run 'pip install paramiko' to compare.")
        
    spindle_avg = benchmark_spindlex(SSH_HOST, SSH_USER, SSH_PASS, SSH_KEY)
    paramiko_avg = benchmark_paramiko(SSH_HOST, SSH_USER, SSH_PASS, SSH_KEY)
    
    print("\n" + "="*50)
    print("📊 RESULTS (Average Connection Time):")
    print(f"   SpindleX: {spindle_avg:.4f}s")
    if paramiko_avg:
        print(f"   Paramiko: {paramiko_avg:.4f}s")
        diff = ((paramiko_avg - spindle_avg) / paramiko_avg) * 100
        if diff > 0:
            print(f"\n✨ SpindleX is {diff:.1f}% FASTER than Paramiko!")
        else:
            print(f"\nParamiko is {-diff:.1f}% faster on this host.")
    print("="*50)

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"\n✨ Total execution time: {time.time() - start_time:.2f} seconds")
