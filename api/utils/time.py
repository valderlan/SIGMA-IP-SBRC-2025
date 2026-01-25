import time
import os
import csv

CSV_PATH = "ip_reputation_timings.csv"
CSV_FIELDS = [
    "ip",
    "total_api",
    "service_total",
    "external_apis_total",
    "internal_api_total",
    "abuse",
    "virustotal",
    "apivoid",
    "pulsedive",
]


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
        writer = csv.DictWriter(file, fieldnames=CSV_FIELDS)

        if not file_exists:
            writer.writeheader()

        row = {"ip": ip}

        for field in CSV_FIELDS:
            if field != "ip":
                row[field] = timings.get(field, "")
        
        writer.writerow(row)
