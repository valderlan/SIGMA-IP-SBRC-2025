import os
import platform
import sys
import time

import numpy as np
import pandas as pd
import psutil
from scipy import stats

from src.dataset_classifier import WeightedVotingClassifier

sys.path.append(os.path.join(os.getcwd(), "src"))


def get_system_specs():
    """
    Retrieves system hardware and software specifications.
    Tries to use 'psutil' for memory and core count if available.
    """
    specs = []
    specs.append(f"OS: {platform.system()} {platform.release()} ({platform.version()})")
    specs.append(f"Architecture: {platform.machine()}")
    specs.append(f"Processor: {platform.processor()}")
    specs.append(f"Python Version: {platform.python_version()}")

    mem = psutil.virtual_memory()
    total_ram_gb = mem.total / (1024**3)
    specs.append(f"RAM: {total_ram_gb:.2f} GB")
    specs.append(f"Physical Cores: {psutil.cpu_count(logical=False)}")
    specs.append(f"Logical CPUs: {psutil.cpu_count(logical=True)}")
    return "\n".join(specs)


def benchmark_ips():
    input_file = "datasets/dataset_ipt.csv"

    print(f"--- Starting Benchmark on {input_file} ---")

    df_full = pd.read_csv(input_file)
    if len(df_full) < 100:
        print(
            f"Warning: Dataset has only {len(df_full)} rows. Using all available data."
        )
        df_sample = df_full
    else:
        df_sample = df_full.head(100).copy()

    classifier = WeightedVotingClassifier()

    print("Calculating initial model weights (Setup)...")
    df_proc_all = classifier.preprocess_data(df_sample)
    df_norm_all = classifier.normalize_features(df_proc_all)
    gt_all = classifier.create_ground_truth(df_proc_all)
    weights = classifier.determine_optimal_weights(df_norm_all, gt_all)

    print(
        f"\nStarting measurement (100 repetitions per IP for {len(df_sample)} IPs)..."
    )

    avg_times_per_ip = []

    for i in range(len(df_sample)):
        single_row_df = df_sample.iloc[[i]]

        measurements = []

        for _ in range(100):
            start_time = time.perf_counter()

            row_proc = classifier.preprocess_data(single_row_df)
            row_norm = classifier.normalize_features(row_proc)
            classifier.classify_with_weighted_voting(row_norm, weights)

            end_time = time.perf_counter()
            measurements.append(end_time - start_time)

        avg_times_per_ip.append(np.mean(measurements))

        if (i + 1) % 10 == 0:
            print(f"Processed {i + 1}/{len(df_sample)} IPs...")

    total_mean = np.mean(avg_times_per_ip)
    std_dev = np.std(avg_times_per_ip, ddof=1)
    n = len(avg_times_per_ip)

    conf_interval = stats.t.interval(
        0.95, df=n - 1, loc=total_mean, scale=std_dev / np.sqrt(n)
    )

    mean_ms = total_mean * 1000
    ci_low_ms = conf_interval[0] * 1000
    ci_high_ms = conf_interval[1] * 1000

    system_info = get_system_specs()

    print("\n" + "=" * 50)
    print("BENCHMARK RESULTS")
    os.makedirs("benchmark", exist_ok=True)

    log_path = os.path.join("benchmark", "benchmark_results.log")

    with open(log_path, "a", encoding="utf-8") as f:
        f.write("\n============================================\n")
        f.write(f"BENCHMARK EXECUTED: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("============================================\n")
        f.write("SYSTEM CONFIGURATION:\n")
        f.write(f"{system_info}\n")
        f.write("--------------------------------------------\n")
        f.write(f"IPs tested: {n}\n")
        f.write(f"Repetitions per IP: 100\n")
        f.write(f"Average Time per Classification: {mean_ms:.4f} ms\n")
        f.write(
            f"95% Confidence Interval:       [{ci_low_ms:.4f} ms, {ci_high_ms:.4f} ms]\n"
        )
        f.write("--------------------------------------------\n")

    print(f"\nLog saved to: {log_path}")
    print("=" * 50)
    print("SYSTEM CONFIGURATION:")
    print(system_info)
    print("-" * 30)
    print(f"IPs tested: {n}")
    print(f"Repetitions per IP: 100")
    print("-" * 30)
    print(f"Average Time per Classification: {mean_ms:.4f} ms")
    print(f"95% Confidence Interval:       [{ci_low_ms:.4f} ms, {ci_high_ms:.4f} ms]")
    print("=" * 50)


if __name__ == "__main__":
    benchmark_ips()
