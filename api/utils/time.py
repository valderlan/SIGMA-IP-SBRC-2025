import time
import os
import csv

CSV_PATH = "ip_reputation_timings.csv"


def timed_call(name, func, *args, timings: dict):
    start = time.perf_counter()
    result = None
    try:
        result = func(*args)
        return result
    finally:
        if result is not None:
            timings[name] = round((time.perf_counter() - start) * 1000, 3)


def write_timing_csv(ip, timings):
    file_exists = os.path.isfile(CSV_PATH)

    with open(CSV_PATH, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=["ip", "abuse", "virustotal", "apivoid", "pulsedive", "total"],
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(
            {
                "ip": ip,
                "abuse": timings.get("abuse", ""),
                "virustotal": timings.get("virustotal", ""),
                "apivoid": timings.get("apivoid", ""),
                "pulsedive": timings.get("pulsedive", ""),
                "total": timings.get("total"),
            }
        )
