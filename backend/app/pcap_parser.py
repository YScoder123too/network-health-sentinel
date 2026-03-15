"""
pcap_parser.py
──────────────
Parses real .pcap / .pcapng files using Scapy and extracts the same
feature set that model.py expects:
    src_ip, port, packet_rate, packet_size

How it works
────────────
1. Load all packets from the capture file
2. Group by source IP  (each unique src_ip = one "log entry")
3. Per group compute:
     - packet_rate  = packets sent per second over the capture window
     - packet_size  = mean payload size in bytes
     - port         = most-targeted destination port (mode)
4. Return a DataFrame ready for predict_batch()

Why group by src_ip?
────────────────────
A port scan or DoS comes from one source hitting many targets fast.
Grouping lets the model see the *behaviour* of each host, not just
individual packets — which is how real IDS systems work (Snort,
Suricata both use flow-based analysis).
"""

from __future__ import annotations
import tempfile
import os
from collections import defaultdict
from statistics import mean, mode
from typing import BinaryIO

import pandas as pd

# Scapy import — lazy so the app still starts if scapy isn't installed
try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PCAPParseError(Exception):
    pass


def _require_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise PCAPParseError(
            "scapy is not installed. Run: pip install scapy"
        )


# ── Core parser ───────────────────────────────────────────────────────────────

def parse_pcap(file_bytes: bytes) -> pd.DataFrame:
    """
    Accept raw bytes of a .pcap or .pcapng file.
    Returns a DataFrame with columns: src_ip, port, packet_rate, packet_size
    Raises PCAPParseError on failure.
    """
    _require_scapy()

    # Write to a temp file — scapy needs a filepath
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    except Exception as e:
        raise PCAPParseError(f"Could not read pcap: {e}")
    finally:
        os.unlink(tmp_path)

    if len(packets) == 0:
        raise PCAPParseError("PCAP file contains no packets.")

    # ── Build per-source-IP flow records ─────────────────────────────────────
    # flows[src_ip] = {"times": [...], "sizes": [...], "ports": [...]}
    flows: dict[str, dict] = defaultdict(lambda: {
        "times": [], "sizes": [], "ports": []
    })

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue  # skip non-IP (ARP, etc.)

        src_ip = pkt[IP].src
        ts     = float(pkt.time)
        size   = len(pkt)  # total packet length in bytes

        # Extract destination port (TCP or UDP)
        dst_port = None
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        if dst_port is None:
            continue  # skip non-TCP/UDP (ICMP etc.)

        flows[src_ip]["times"].append(ts)
        flows[src_ip]["sizes"].append(size)
        flows[src_ip]["ports"].append(dst_port)

    if not flows:
        raise PCAPParseError(
            "No TCP/UDP packets with IP layer found in capture."
        )

    # ── Compute per-flow features ─────────────────────────────────────────────
    records = []
    for src_ip, data in flows.items():
        times = data["times"]
        sizes = data["sizes"]
        ports = data["ports"]

        # Time window of this flow in seconds (min 1s to avoid div/0)
        duration    = max(max(times) - min(times), 1.0)
        packet_rate = round(len(times) / duration, 2)   # packets per second
        packet_size = round(mean(sizes), 2)              # avg bytes

        # Most-targeted port (mode)
        try:
            dominant_port = mode(ports)
        except Exception:
            dominant_port = ports[0]

        records.append({
            "src_ip":      src_ip,
            "port":        dominant_port,
            "packet_rate": packet_rate,
            "packet_size": packet_size,
            # Extra metadata — shown in UI but not used as ML features
            "_packet_count": len(times),
            "_unique_ports":  len(set(ports)),
            "_duration_sec":  round(duration, 2),
        })

    df = pd.DataFrame(records)

    # Sort by packet_rate descending — most suspicious hosts first
    df = df.sort_values("packet_rate", ascending=False).reset_index(drop=True)
    return df


def pcap_df_to_model_input(df: pd.DataFrame) -> pd.DataFrame:
    """
    Strip PCAP-only metadata columns before passing to predict_batch().
    Returns only the columns model.py needs.
    """
    return df[["src_ip", "port", "packet_rate", "packet_size"]].copy()


# ── Rich log dict for Gemini ──────────────────────────────────────────────────

def enrich_result_with_pcap_meta(result: dict, pcap_row: pd.Series) -> dict:
    """
    Adds PCAP-specific context to a result dict before sending to Gemini,
    so the SOC report mentions packet counts, unique ports scanned etc.
    """
    return {
        **result,
        "packet_count":  int(pcap_row.get("_packet_count", 0)),
        "unique_ports":  int(pcap_row.get("_unique_ports",  0)),
        "duration_sec":  float(pcap_row.get("_duration_sec", 0)),
        "data_source":   "pcap",
    }