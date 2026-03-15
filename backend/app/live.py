# """
# live.py  —  Real-time threat streaming via Server-Sent Events (SSE)
# ─────────────────────────────────────────────────────────────────────
# Mount this router in main.py with:
#     from app.live import router as live_router
#     app.include_router(live_router)

# Frontend connects to:
#     GET /live/stream          — SSE stream of simulated live logs
#     POST /live/analyze-stream — SSE stream while analyzing an uploaded CSV
# """

# import asyncio
# import json
# import random
# from collections import Counter
# from typing import AsyncGenerator

# from fastapi import APIRouter, UploadFile, File, HTTPException
# from fastapi.responses import StreamingResponse
# import pandas as pd
# import io

# from app.model import predict_row, predict_batch
# from app.gemini_client import explain_attack, generate_threat_summary

# router = APIRouter(prefix="/live", tags=["live"])

# # ── Simulated traffic generator ───────────────────────────────────────────────

# ATTACK_PROFILES = [
#     # (weight, profile_fn)
#     (0.55, lambda: {"src_ip": f"192.168.1.{random.randint(1,254)}", "port": random.choice([80,443,8080,3306]),  "packet_rate": random.randint(50,400),   "packet_size": random.randint(200,1200)}),
#     (0.12, lambda: {"src_ip": f"10.0.0.{random.randint(1,50)}",     "port": random.choice([80,443,53]),         "packet_rate": random.randint(900,2000),  "packet_size": random.randint(40,100)}),   # DoS
#     (0.13, lambda: {"src_ip": f"172.16.{random.randint(0,3)}.{random.randint(1,100)}", "port": random.randint(1,1023), "packet_rate": random.randint(150,500), "packet_size": random.randint(40,80)}),   # Scan
#     (0.12, lambda: {"src_ip": f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}", "port": random.choice([22,23,3389,445,1433]), "packet_rate": random.randint(120,600), "packet_size": random.randint(80,300)}),  # Brute
#     (0.08, lambda: {"src_ip": f"192.168.1.{random.randint(1,254)}", "port": random.choice([4444,6666,31337]),   "packet_rate": random.randint(80,350),   "packet_size": random.randint(1300,1500)}),  # Exfil
# ]

# def _random_log() -> dict:
#     weights   = [p[0] for p in ATTACK_PROFILES]
#     profile   = random.choices(ATTACK_PROFILES, weights=weights, k=1)[0][1]
#     return profile()


# # ── SSE helpers ───────────────────────────────────────────────────────────────

# def _sse(event: str, data: dict) -> str:
#     return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# async def _stream_log(log: dict) -> dict:
#     result = predict_row(
#         packet_rate=float(log["packet_rate"]),
#         port=int(log["port"]),
#         packet_size=float(log["packet_size"]),
#     )

#     explanation = None
#     if result["threat_level"] in ("high", "critical"):
#         try:
#             explanation = explain_attack({**log, **result})
#         except Exception:
#             explanation = "AI explanation unavailable."

#     return {
#         "log":            log,
#         "prediction":     result["prediction"],
#         "threat_level":   result["threat_level"],
#         "anomaly_score":  result["anomaly_score"],
#         "confidence":     result["threat_confidence"],
#         "ai_explanation": explanation,
#     }


# # ── Routes ────────────────────────────────────────────────────────────────────

# @router.get("/stream")
# async def live_stream(rate: float = 1.0):
#     """
#     Streams simulated network log events in real time.
#     rate = seconds between events (default 1.0, min 0.3)
#     """
#     rate = max(rate, 0.3)

#     async def generator() -> AsyncGenerator[str, None]:
#         seen: list[dict] = []
#         try:
#             while True:
#                 log    = _random_log()
#                 result = await _stream_log(log)
#                 seen.append(result)

#                 yield _sse("log", result)

#                 # Every 10 logs send updated stats
#                 if len(seen) % 10 == 0:
#                     counts = Counter(r["threat_level"] for r in seen)
#                     yield _sse("stats", {
#                         "total":    len(seen),
#                         "normal":   counts.get("low",      0),
#                         "medium":   counts.get("medium",   0),
#                         "high":     counts.get("high",     0),
#                         "critical": counts.get("critical", 0),
#                     })

#                 await asyncio.sleep(rate)
#         except asyncio.CancelledError:
#             pass

#     return StreamingResponse(
#         generator(),
#         media_type="text/event-stream",
#         headers={
#             "Cache-Control":               "no-cache",
#             "X-Accel-Buffering":           "no",
#             "Access-Control-Allow-Origin": "http://localhost:3000",
#         },
#     )


# @router.post("/analyze-stream")
# async def analyze_stream(file: UploadFile = File(...)):
#     """
#     Streams CSV analysis results row-by-row as SSE events.
#     The frontend receives each log result as it's processed — no waiting.
#     """
#     if not file.filename.endswith(".csv"):
#         raise HTTPException(status_code=400, detail="Only CSV files accepted.")

#     contents = await file.read()
#     try:
#         df = pd.read_csv(io.BytesIO(contents))
#     except Exception:
#         raise HTTPException(status_code=400, detail="Could not parse CSV.")

#     required = {"src_ip", "port", "packet_rate", "packet_size"}
#     missing  = required - set(df.columns)
#     if missing:
#         raise HTTPException(status_code=422, detail=f"Missing columns: {missing}")

#     predictions = predict_batch(df)
#     all_results: list[dict] = []

#     async def generator() -> AsyncGenerator[str, None]:
#         # Signal start
#         yield _sse("start", {"total": len(df)})

#         for i, (_, row) in enumerate(df.iterrows()):
#             pred = predictions[i]
#             log  = row.to_dict()

#             explanation = None
#             if pred["threat_level"] in ("high", "critical"):
#                 try:
#                     explanation = explain_attack({**log, **pred})
#                 except Exception:
#                     explanation = "AI explanation unavailable."

#             result = {
#                 "log":            log,
#                 "prediction":     pred["prediction"],
#                 "threat_level":   pred["threat_level"],
#                 "anomaly_score":  pred["anomaly_score"],
#                 "confidence":     pred["threat_confidence"],
#                 "ai_explanation": explanation,
#                 "index":          i,
#             }
#             all_results.append(result)
#             yield _sse("log", result)

#             # Small delay so the frontend renders progressively
#             await asyncio.sleep(0.05)

#         # Final summary
#         counts       = Counter(r["threat_level"] for r in all_results)
#         attack_types = Counter(r["prediction"] for r in all_results if r["prediction"] != "Normal")

#         try:
#             exec_summary = generate_threat_summary(all_results)
#         except Exception:
#             exec_summary = None

#         yield _sse("done", {
#             "summary": {
#                 "total_logs":       len(all_results),
#                 "normal":           counts.get("low",      0),
#                 "suspicious":       counts.get("medium",   0),
#                 "high_threats":     counts.get("high",     0),
#                 "critical_threats": counts.get("critical", 0),
#                 "top_attack_types": dict(attack_types.most_common(5)),
#                 "threat_rate":      round((len(all_results) - counts.get("low", 0)) / max(len(all_results), 1) * 100, 1),
#                 "exec_summary":     exec_summary,
#             }
#         })

#     return StreamingResponse(
#         generator(),
#         media_type="text/event-stream",
#         headers={
#             "Cache-Control":               "no-cache",
#             "X-Accel-Buffering":           "no",
#             "Access-Control-Allow-Origin": "http://localhost:3000",
#         },
#     )

# """
# live.py — Real-time threat streaming via Server-Sent Events (SSE)
# ─────────────────────────────────────────────────────────────────
# Mount this on the FastAPI app in main.py:

#     from app.live import router as live_router
#     app.include_router(live_router)

# Frontend connects to GET /live/stream and receives a new threat
# event every ~1-2 seconds, formatted as JSON over SSE.
# """

# import asyncio
# import json
# import random
# from datetime import datetime

# from fastapi import APIRouter
# from fastapi.responses import StreamingResponse

# from app.model import predict_row

# router = APIRouter(prefix="/live", tags=["live"])

# # ── Traffic simulation (same profiles as mock_log_generator) ──────────────────

# _NORMAL_IPS  = [f"192.168.1.{i}" for i in range(10, 60)]
# _ATTACK_IPS  = [f"185.{random.randint(100,200)}.{random.randint(0,255)}.{i}" for i in range(1, 20)]
# _INTERNAL    = [f"10.0.0.{i}" for i in range(1, 30)]

# def _gen_packet() -> dict:
#     roll = random.random()

#     if roll < 0.55:       # normal
#         return {"src_ip": random.choice(_NORMAL_IPS),  "port": random.choice([80,443,8080,3306]), "packet_rate": random.randint(50,400),   "packet_size": random.randint(200,1200)}
#     elif roll < 0.67:     # DoS
#         return {"src_ip": random.choice(_ATTACK_IPS),  "port": random.choice([80,443,53]),        "packet_rate": random.randint(800,2000), "packet_size": random.randint(40,120)}
#     elif roll < 0.78:     # port scan
#         return {"src_ip": random.choice(_ATTACK_IPS),  "port": random.randint(1,1023),            "packet_rate": random.randint(150,500),  "packet_size": random.randint(40,80)}
#     elif roll < 0.89:     # brute force
#         return {"src_ip": random.choice(_ATTACK_IPS),  "port": random.choice([22,23,3389,445]),   "packet_rate": random.randint(120,600),  "packet_size": random.randint(80,300)}
#     else:                 # exfiltration
#         return {"src_ip": random.choice(_INTERNAL),    "port": random.choice([4444,6666,9999]),   "packet_rate": random.randint(80,350),   "packet_size": random.randint(1300,1500)}


# # ── SSE stream ────────────────────────────────────────────────────────────────

# async def _event_generator(max_events: int = 500):
#     """
#     Yields Server-Sent Event strings forever (up to max_events).
#     Each event is a JSON object the frontend can parse directly.
#     """
#     count = 0
#     while count < max_events:
#         pkt    = _gen_packet()
#         result = predict_row(pkt["packet_rate"], pkt["port"], pkt["packet_size"])

#         payload = {
#             "id":           count,
#             "timestamp":    datetime.utcnow().isoformat() + "Z",
#             "src_ip":       pkt["src_ip"],
#             "port":         pkt["port"],
#             "packet_rate":  pkt["packet_rate"],
#             "packet_size":  pkt["packet_size"],
#             "prediction":   result["prediction"],
#             "threat_level": result["threat_level"],
#             "anomaly_score":result["anomaly_score"],
#             "confidence":   result["confidence"],
#         }

#         # SSE format: "data: <json>\n\n"
#         yield f"data: {json.dumps(payload)}\n\n"

#         count += 1
#         # Vary delay: threats arrive faster than normal traffic (makes demo feel alive)
#         delay = 0.4 if result["threat_level"] in ("high","critical") else random.uniform(0.8, 1.8)
#         await asyncio.sleep(delay)

#     yield "data: {\"type\": \"stream_end\"}\n\n"


# @router.get("/stream")
# async def live_stream():
#     """
#     SSE endpoint. Connect from frontend with:
#         const es = new EventSource("http://localhost:8000/live/stream")
#         es.onmessage = (e) => { const threat = JSON.parse(e.data); ... }
#     """
#     return StreamingResponse(
#         _event_generator(),
#         media_type="text/event-stream",
#         headers={
#             "Cache-Control":               "no-cache",
#             "X-Accel-Buffering":           "no",    # disable nginx buffering
#             "Access-Control-Allow-Origin": "*",
#         },
#     )


# @router.get("/status")
# async def live_status():
#     return {"status": "live stream available at /live/stream", "protocol": "SSE"}


"""
live.py  —  Real-time threat streaming via Server-Sent Events (SSE)
─────────────────────────────────────────────────────────────────────
Mount this router in main.py with:
    from app.live import router as live_router
    app.include_router(live_router)

Frontend connects to:
    GET /live/stream          — SSE stream of simulated live logs
    POST /live/analyze-stream — SSE stream while analyzing an uploaded CSV
"""

import asyncio
import json
import random
from collections import Counter
from typing import AsyncGenerator

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
import pandas as pd
import io

from app.model import predict_row, predict_batch
from app.gemini_client import explain_attack, generate_threat_summary

# ── Column auto-mapper (self-contained — no circular import from main.py) ─────

_KDD_SERVICE_PORT: dict[str, int] = {
    "http": 80, "https": 443, "http_443": 443, "http_8001": 8001,
    "ftp": 21, "ftp_data": 20, "ssh": 22, "smtp": 25, "dns": 53,
    "domain": 53, "domain_u": 53, "pop_3": 110, "imap4": 143,
    "telnet": 23, "finger": 79, "auth": 113, "bgp": 179,
    "irc": 6667, "ldap": 389, "login": 513, "shell": 514,
    "exec": 512, "klogin": 543, "kshell": 544,
    "netbios_dgm": 138, "netbios_ns": 137, "netbios_ssn": 139,
    "nntp": 119, "ntp_u": 123, "printer": 515, "sql_net": 1521,
    "sunrpc": 111, "tftp_u": 69, "uucp": 540, "whois": 43,
    "x11": 6000, "gopher": 70, "name": 42, "netstat": 15,
    "eco_i": 8, "ecr_i": 8, "red_i": 8, "icmp": 0,
    "private": 1024, "other": 0, "courier": 530, "daytime": 13,
    "discard": 9, "echo": 7, "mtp": 57, "supdup": 95,
    "time": 37, "tim_i": 37, "urh_i": 0, "urp_i": 0,
    "pop_2": 109, "uucp_path": 117, "vmnet": 175,
}

_COLUMN_MAP: dict[str, str] = {
    "srcip": "src_ip", "src_ip_addr": "src_ip", "source_ip": "src_ip",
    "ip_src": "src_ip", "sourceip": "src_ip", "sip": "src_ip",
    "sport": "port", "src_port": "port", "source_port": "port",
    "dport": "port", "dst_port": "port", "destination_port": "port",
    "l4_src_port": "port",
    "rate": "packet_rate", "pkt_rate": "packet_rate", "count": "packet_rate",
    "flow_pkts_s": "packet_rate", "tot_fwd_pkts": "packet_rate",
    "total_fwd_packets": "packet_rate", "pkts_per_sec": "packet_rate",
    "smean": "packet_size", "sbytes": "packet_size", "src_bytes": "packet_size",
    "avg_pkt_size": "packet_size", "fwd_pkt_len_mean": "packet_size",
    "total_length_of_fwd_packets": "packet_size", "flow_byts_s": "packet_size",
}


def _automap_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    cols_lower = {c.lower().strip().replace(" ", "_"): c for c in df.columns}
    rename: dict[str, str] = {}
    mapped: set[str] = set()

    for raw, target in _COLUMN_MAP.items():
        if target in mapped:
            continue
        key = raw.lower().replace(" ", "_")
        if key in cols_lower and cols_lower[key] not in rename:
            rename[cols_lower[key]] = target
            mapped.add(target)

    df = df.rename(columns=rename)
    notes = [f"{s} → {d}" for s, d in rename.items()]

    if "src_ip" not in df.columns:
        ip_cols = [c for c in df.columns if "ip" in c.lower()]
        if ip_cols:
            df["src_ip"] = df[ip_cols[0]].astype(str)
            notes.append(f"src_ip ← {ip_cols[0]}")
        else:
            df["src_ip"] = [f"10.0.{(i//254)%255}.{(i%254)+1}" for i in range(len(df))]
            notes.append("src_ip synthesized (no IP column)")

    if "port" not in df.columns:
        if "service" in df.columns:
            df["port"] = df["service"].str.lower().str.strip().map(_KDD_SERVICE_PORT).fillna(0).astype(int)
            notes.append("port ← service (KDD mapping)")
        else:
            port_cols = [c for c in df.columns if "port" in c.lower()]
            df["port"] = pd.to_numeric(df[port_cols[0]], errors="coerce").fillna(0) if port_cols else 0
            notes.append(f"port ← {port_cols[0]}" if port_cols else "port defaulted to 0")

    if "packet_rate" not in df.columns:
        dur  = next((c for c in df.columns if "dur" in c.lower()), None)
        byts = next((c for c in df.columns if "byt" in c.lower()), None)
        if dur and byts:
            d = pd.to_numeric(df[dur],  errors="coerce").replace(0, 1).fillna(1)
            b = pd.to_numeric(df[byts], errors="coerce").fillna(0)
            df["packet_rate"] = (b / d).clip(0, 5000)
            notes.append(f"packet_rate derived from {byts}/{dur}")
        else:
            df["packet_rate"] = 100.0
            notes.append("packet_rate defaulted to 100")

    if "packet_size" not in df.columns:
        df["packet_size"] = 512.0
        notes.append("packet_size defaulted to 512")

    df["port"]        = pd.to_numeric(df["port"],        errors="coerce").fillna(0).clip(0, 65535).astype(int)
    df["packet_rate"] = pd.to_numeric(df["packet_rate"], errors="coerce").fillna(0).clip(0, 10000)
    df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce").fillna(512).clip(0, 65535)
    return df, notes


router = APIRouter(prefix="/live", tags=["live"])

# ── Simulated traffic generator ───────────────────────────────────────────────

ATTACK_PROFILES = [
    # (weight, profile_fn)
    (0.55, lambda: {"src_ip": f"192.168.1.{random.randint(1,254)}", "port": random.choice([80,443,8080,3306]),  "packet_rate": random.randint(50,400),   "packet_size": random.randint(200,1200)}),
    (0.12, lambda: {"src_ip": f"10.0.0.{random.randint(1,50)}",     "port": random.choice([80,443,53]),         "packet_rate": random.randint(900,2000),  "packet_size": random.randint(40,100)}),   # DoS
    (0.13, lambda: {"src_ip": f"172.16.{random.randint(0,3)}.{random.randint(1,100)}", "port": random.randint(1,1023), "packet_rate": random.randint(150,500), "packet_size": random.randint(40,80)}),   # Scan
    (0.12, lambda: {"src_ip": f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}", "port": random.choice([22,23,3389,445,1433]), "packet_rate": random.randint(120,600), "packet_size": random.randint(80,300)}),  # Brute
    (0.08, lambda: {"src_ip": f"192.168.1.{random.randint(1,254)}", "port": random.choice([4444,6666,31337]),   "packet_rate": random.randint(80,350),   "packet_size": random.randint(1300,1500)}),  # Exfil
]

def _random_log() -> dict:
    weights   = [p[0] for p in ATTACK_PROFILES]
    profile   = random.choices(ATTACK_PROFILES, weights=weights, k=1)[0][1]
    return profile()


# ── SSE helpers ───────────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _stream_log(log: dict) -> dict:
    result = predict_row(
        packet_rate=float(log["packet_rate"]),
        port=int(log["port"]),
        packet_size=float(log["packet_size"]),
    )

    explanation = None
    if result["threat_level"] in ("high", "critical"):
        try:
            explanation = explain_attack({**log, **result})
        except Exception:
            explanation = "AI explanation unavailable."

    return {
        "log":            log,
        "prediction":     result["prediction"],
        "threat_level":   result["threat_level"],
        "anomaly_score":  result["anomaly_score"],
        "confidence":     result["threat_confidence"],
        "ai_explanation": explanation,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/stream")
async def live_stream(rate: float = 1.0):
    """
    Streams simulated network log events in real time.
    rate = seconds between events (default 1.0, min 0.3)
    """
    rate = max(rate, 0.3)

    async def generator() -> AsyncGenerator[str, None]:
        seen: list[dict] = []
        try:
            while True:
                log    = _random_log()
                result = await _stream_log(log)
                seen.append(result)

                yield _sse("log", result)

                # Every 10 logs send updated stats
                if len(seen) % 10 == 0:
                    counts = Counter(r["threat_level"] for r in seen)
                    yield _sse("stats", {
                        "total":    len(seen),
                        "normal":   counts.get("low",      0),
                        "medium":   counts.get("medium",   0),
                        "high":     counts.get("high",     0),
                        "critical": counts.get("critical", 0),
                    })

                await asyncio.sleep(rate)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "http://localhost:3000",
        },
    )


@router.post("/analyze-stream")
async def analyze_stream(file: UploadFile = File(...)):
    """
    Streams CSV analysis results row-by-row as SSE events.
    Accepts any CSV format — KDD Cup 99, NSL-KDD, UNSW-NB15, CIC-IDS,
    or custom CSVs. Columns are auto-mapped before analysis.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files accepted.")

    contents = await file.read()

    # Try multiple encodings
    df = None
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
            break
        except Exception:
            continue
    if df is None:
        raise HTTPException(status_code=400, detail="Could not parse CSV.")

    # Auto-map columns — handles KDD, UNSW-NB15, CIC-IDS, custom formats
    df, mapping_notes = _automap_columns(df)

    # Sample large files for performance
    if len(df) > 2000:
        df = df.sample(2000, random_state=42).reset_index(drop=True)

    predictions = predict_batch(df)
    all_results: list[dict] = []

    async def generator() -> AsyncGenerator[str, None]:
        yield _sse("start", {"total": len(df), "column_mapping": mapping_notes})

        for i, (_, row) in enumerate(df.iterrows()):
            pred = predictions[i]
            log  = row.to_dict()

            explanation = None
            if pred["threat_level"] in ("high", "critical"):
                try:
                    explanation = explain_attack({**log, **pred})
                except Exception:
                    explanation = "AI explanation unavailable."

            result = {
                "log":            log,
                "prediction":     pred["prediction"],
                "threat_level":   pred["threat_level"],
                "anomaly_score":  pred["anomaly_score"],
                "confidence":     pred["threat_confidence"],
                "ai_explanation": explanation,
                "index":          i,
            }
            all_results.append(result)
            yield _sse("log", result)

            await asyncio.sleep(0.05)

        counts       = Counter(r["threat_level"] for r in all_results)
        attack_types = Counter(r["prediction"] for r in all_results if r["prediction"] != "Normal")

        try:
            exec_summary = generate_threat_summary(all_results)
        except Exception:
            exec_summary = None

        yield _sse("done", {
            "summary": {
                "total_logs":       len(all_results),
                "normal":           counts.get("low",      0),
                "suspicious":       counts.get("medium",   0),
                "high_threats":     counts.get("high",     0),
                "critical_threats": counts.get("critical", 0),
                "top_attack_types": dict(attack_types.most_common(5)),
                "threat_rate":      round((len(all_results) - counts.get("low", 0)) / max(len(all_results), 1) * 100, 1),
                "exec_summary":     exec_summary,
                "column_mapping":   mapping_notes,
            }
        })

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "http://localhost:3000",
        },
    )