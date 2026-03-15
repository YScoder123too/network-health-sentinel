# import pandas as pd
# import random

# data = []

# for i in range(100):

#     log = {
#         "src_ip": f"192.168.1.{random.randint(1,255)}",
#         "port": random.choice([22,80,443,21,25]),
#         "packet_rate": random.randint(1,1000),
#         "packet_size": random.randint(40,1500)
#     }

#     data.append(log)

# df = pd.DataFrame(data)

# df.to_csv("network_logs.csv",index=False)

# print("Mock logs created")


"""
mock_log_generator.py
─────────────────────
Generates realistic network log CSVs for testing Network Health Sentinel.

Usage:
    python mock_log_generator.py              # creates network_logs.csv (200 rows)
    python mock_log_generator.py --rows 500   # custom row count
    python mock_log_generator.py --out demo.csv
"""

import argparse
import random
import csv
import os

random.seed(42)

# ── Traffic profiles ──────────────────────────────────────────────────────────

def normal_traffic():
    return {
        "src_ip":      f"192.168.1.{random.randint(1,254)}",
        "port":        random.choice([80, 443, 8080, 3306, 5432, 25, 587]),
        "packet_rate": random.randint(50, 400),
        "packet_size": random.randint(200, 1200),
        "label":       "Normal",
    }

def dos_attack():
    return {
        "src_ip":      f"10.0.{random.randint(0,5)}.{random.randint(1,254)}",
        "port":        random.choice([80, 443, 53]),
        "packet_rate": random.randint(800, 2000),   # flood
        "packet_size": random.randint(40, 120),     # tiny packets
        "label":       "DoS Attack",
    }

def port_scan():
    return {
        "src_ip":      f"172.16.{random.randint(0,3)}.{random.randint(1,100)}",
        "port":        random.randint(1, 1023),     # sweeping low ports
        "packet_rate": random.randint(150, 500),
        "packet_size": random.randint(40, 80),      # tiny probe packets
        "label":       "Port Scan",
    }

def brute_force():
    return {
        "src_ip":      f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "port":        random.choice([22, 23, 3389, 445, 1433]),  # SSH/RDP/SMB
        "packet_rate": random.randint(120, 600),
        "packet_size": random.randint(80, 300),
        "label":       "Brute-Force Attempt",
    }

def data_exfiltration():
    return {
        "src_ip":      f"192.168.1.{random.randint(1,254)}",
        "port":        random.choice([4444, 6666, 8888, 9999, 31337]),  # non-standard
        "packet_rate": random.randint(80, 350),
        "packet_size": random.randint(1300, 1500),  # large payloads
        "label":       "Data Exfiltration",
    }

# ── Generator ─────────────────────────────────────────────────────────────────

PROFILES = [
    (normal_traffic,      0.55),   # 55% normal  — realistic ratio
    (dos_attack,          0.12),
    (port_scan,           0.13),
    (brute_force,         0.12),
    (data_exfiltration,   0.08),
]

def generate(rows: int = 200) -> list[dict]:
    profiles, weights = zip(*PROFILES)
    records = []
    for _ in range(rows):
        fn = random.choices(profiles, weights=weights, k=1)[0]
        records.append(fn())
    return records


def main():
    parser = argparse.ArgumentParser(description="Generate mock network logs")
    parser.add_argument("--rows", type=int, default=200, help="Number of log rows")
    parser.add_argument("--out",  type=str, default="network_logs.csv", help="Output filename")
    args = parser.parse_args()

    records = generate(args.rows)
    fieldnames = ["src_ip", "port", "packet_rate", "packet_size", "label"]

    out_path = os.path.join(os.path.dirname(__file__), args.out)
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    # Summary
    from collections import Counter
    counts = Counter(r["label"] for r in records)
    print(f"\n✅  Generated {args.rows} rows → {out_path}\n")
    for label, count in counts.most_common():
        bar = "█" * (count // 3)
        print(f"  {label:<25} {count:>4}  {bar}")
    print()


if __name__ == "__main__":
    main()