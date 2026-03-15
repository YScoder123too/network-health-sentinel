# # from dotenv import load_dotenv
# # load_dotenv()

# # import os
# # import io
# # import ipaddress
# # from collections import Counter

# # import httpx
# # import pandas as pd
# # from fastapi import FastAPI, UploadFile, File, HTTPException
# # from fastapi.middleware.cors import CORSMiddleware
# # from pydantic import BaseModel

# # from app.model import predict_batch, retrain
# # from app.gemini_client import explain_attack
# # from app.live import router as live_router
# # from app.chat import chat_router
# # from app.news import news_router
# # from app.pcap_parser import (
# #     parse_pcap, pcap_df_to_model_input,
# #     enrich_result_with_pcap_meta, PCAPParseError,
# # )

# # # ── App ───────────────────────────────────────────────────────────────────────

# # app = FastAPI(title="Network Health Sentinel", version="2.2")

# # app.add_middleware(
# #     CORSMiddleware,
# #     allow_origins=["http://localhost:3000"],
# #     allow_credentials=True,
# #     allow_methods=["*"],
# #     allow_headers=["*"],
# # )

# # app.include_router(live_router)
# # app.include_router(chat_router)
# # app.include_router(news_router)

# # REQUIRED_CSV_COLS = {"src_ip", "port", "packet_rate", "packet_size"}

# # # ── Column auto-mapper ────────────────────────────────────────────────────────
# # # Upload UNSW-NB15, CIC-IDS-2017, KDD99, or any CSV — no renaming needed.

# # COLUMN_MAP = {
# #     # src_ip
# #     "srcip": "src_ip", "src_ip_addr": "src_ip", "source_ip": "src_ip",
# #     "ip_src": "src_ip", "sourceip": "src_ip", "src": "src_ip",
# #     "source": "src_ip", "sip": "src_ip",
# #     # port
# #     "sport": "port", "src_port": "port", "source_port": "port",
# #     "dport": "port", "dst_port": "port", "destination_port": "port",
# #     "l4_src_port": "port",
# #     # packet_rate
# #     "rate": "packet_rate", "pkt_rate": "packet_rate",
# #     "flow_pkts_s": "packet_rate", "flow_pkts/s": "packet_rate",
# #     "total_fwd_packets": "packet_rate", "pkts_per_sec": "packet_rate",
# #     "num_pkts_sent": "packet_rate", "pkts": "packet_rate",
# #     "tot_fwd_pkts": "packet_rate", "totfwdpkts": "packet_rate",
# #     # packet_size
# #     "smean": "packet_size", "sbytes": "packet_size", "dmean": "packet_size",
# #     "pktlen_mean": "packet_size", "avg_pkt_size": "packet_size",
# #     "total_length_of_fwd_packets": "packet_size", "totlenfwdpkts": "packet_size",
# #     "byts_per_sec": "packet_size", "bytes": "packet_size",
# #     "flow_byts_s": "packet_size", "flow_byts/s": "packet_size",
# #     "fwd_pkt_len_mean": "packet_size",
# # }


# # def _automap_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
# #     """
# #     Renames dataset columns to our internal schema automatically.
# #     Falls back gracefully for any missing columns.
# #     Returns (remapped_df, notes) where notes describe what was mapped.
# #     """
# #     col_lookup = {c.lower().strip().replace(" ", "_"): c for c in df.columns}
# #     rename: dict[str, str] = {}
# #     mapped_targets: set[str] = set()

# #     for raw, target in COLUMN_MAP.items():
# #         if target in mapped_targets:
# #             continue
# #         key = raw.lower().replace(" ", "_")
# #         if key in col_lookup and col_lookup[key] not in rename:
# #             rename[col_lookup[key]] = target
# #             mapped_targets.add(target)

# #     df = df.rename(columns=rename)
# #     notes = [f"{src} → {dst}" for src, dst in rename.items()]

# #     # Fill still-missing columns
# #     if "src_ip" not in df.columns:
# #         ip_cols = [c for c in df.columns if "ip" in c.lower()]
# #         df["src_ip"] = df[ip_cols[0]].astype(str) if ip_cols else "0.0.0.0"
# #         notes.append(f"src_ip {'← ' + ip_cols[0] if ip_cols else 'defaulted to 0.0.0.0'}")

# #     if "port" not in df.columns:
# #         port_cols = [c for c in df.columns if "port" in c.lower()]
# #         df["port"] = pd.to_numeric(df[port_cols[0]], errors="coerce").fillna(0) if port_cols else 0
# #         notes.append(f"port {'← ' + port_cols[0] if port_cols else 'defaulted to 0'}")

# #     if "packet_rate" not in df.columns:
# #         dur  = next((c for c in df.columns if "dur" in c.lower()), None)
# #         byts = next((c for c in df.columns if "byt" in c.lower() or "byte" in c.lower()), None)
# #         if dur and byts:
# #             d = pd.to_numeric(df[dur], errors="coerce").replace(0, 1).fillna(1)
# #             b = pd.to_numeric(df[byts], errors="coerce").fillna(0)
# #             df["packet_rate"] = (b / d).clip(0, 5000)
# #             notes.append(f"packet_rate derived from {byts}/{dur}")
# #         else:
# #             df["packet_rate"] = 100.0
# #             notes.append("packet_rate defaulted to 100")

# #     if "packet_size" not in df.columns:
# #         df["packet_size"] = 512.0
# #         notes.append("packet_size defaulted to 512")

# #     # Sanitise
# #     df["port"]        = pd.to_numeric(df["port"],        errors="coerce").fillna(0).clip(0, 65535).astype(int)
# #     df["packet_rate"] = pd.to_numeric(df["packet_rate"], errors="coerce").fillna(0).clip(0, 10000)
# #     df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce").fillna(0).clip(0, 65535)

# #     return df, notes


# # # ── IP Geolocation ────────────────────────────────────────────────────────────

# # _RFC1918 = [
# #     ipaddress.ip_network("10.0.0.0/8"),
# #     ipaddress.ip_network("172.16.0.0/12"),
# #     ipaddress.ip_network("192.168.0.0/16"),
# #     ipaddress.ip_network("127.0.0.0/8"),
# # ]

# # def _is_private(ip_str: str) -> bool:
# #     try:
# #         return any(ipaddress.ip_address(ip_str) in net for net in _RFC1918)
# #     except ValueError:
# #         return True


# # async def _geolocate(ip: str) -> dict | None:
# #     if _is_private(ip):
# #         return None
# #     try:
# #         async with httpx.AsyncClient(timeout=3.0) as client:
# #             r = await client.get(
# #                 f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
# #             )
# #         data = r.json()
# #         if data.get("status") == "success":
# #             return {
# #                 "country":      data.get("country"),
# #                 "country_code": data.get("countryCode"),
# #                 "city":         data.get("city"),
# #                 "isp":          data.get("isp"),
# #             }
# #     except Exception:
# #         pass
# #     return None


# # # ── Slack Alerts ──────────────────────────────────────────────────────────────

# # SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# # async def _send_slack_alert(result: dict) -> None:
# #     if not SLACK_WEBHOOK_URL:
# #         return
# #     ip          = result.get("log", {}).get("src_ip", "unknown")
# #     attack_type = result.get("prediction", "Unknown")
# #     score       = result.get("anomaly_score", 0)
# #     explanation = result.get("ai_explanation") or ""
# #     truncated   = explanation[:300] + "…" if len(explanation) > 300 else explanation
# #     geo         = result.get("geo") or {}
# #     location    = f"{geo.get('city','')}, {geo.get('country','')}".strip(", ") or "Unknown"
# #     try:
# #         async with httpx.AsyncClient(timeout=5.0) as client:
# #             await client.post(SLACK_WEBHOOK_URL, json={
# #                 "text": (
# #                     f":rotating_light: *CRITICAL THREAT* :rotating_light:\n"
# #                     f">*IP:* `{ip}` ({location})\n"
# #                     f">*Type:* {attack_type}  |  *Score:* `{score}`\n"
# #                     f">*Summary:* {truncated or '_unavailable_'}"
# #                 )
# #             })
# #     except Exception:
# #         pass


# # # ── Shared result builder ─────────────────────────────────────────────────────

# # async def _build_results(
# #     df: pd.DataFrame,
# #     predictions: list[dict],
# #     pcap_df: pd.DataFrame | None = None,
# # ) -> list[dict]:
# #     results = []
# #     for i, (_, row) in enumerate(df.iterrows()):
# #         pred = predictions[i]
# #         log  = row.to_dict()
# #         if pcap_df is not None:
# #             pred = enrich_result_with_pcap_meta(pred, pcap_df.iloc[i])
# #         geo = await _geolocate(str(log.get("src_ip", "")))
# #         explanation = None
# #         if pred["threat_level"] in ("high", "critical"):
# #             try:
# #                 explanation = explain_attack({**log, **pred})
# #             except Exception as e:
# #                 explanation = f"AI explanation unavailable: {e}"
# #         entry = {
# #             "log":            log,
# #             "prediction":     pred["prediction"],
# #             "threat_level":   pred["threat_level"],
# #             "anomaly_score":  pred["anomaly_score"],
# #             "confidence":     pred.get("threat_confidence", 0),
# #             "ai_explanation": explanation,
# #             "geo":            geo,
# #             "packet_count":   pred.get("packet_count"),
# #             "unique_ports":   pred.get("unique_ports"),
# #             "duration_sec":   pred.get("duration_sec"),
# #             "data_source":    pred.get("data_source", "csv"),
# #         }
# #         if pred["threat_level"] == "critical":
# #             await _send_slack_alert(entry)
# #         results.append(entry)
# #     return results


# # def _build_summary(results: list[dict]) -> dict:
# #     threat_counts = Counter(r["threat_level"] for r in results)
# #     attack_types  = Counter(r["prediction"] for r in results if r["prediction"] != "Normal")
# #     total = len(results)
# #     return {
# #         "total_logs":       total,
# #         "normal":           threat_counts.get("low",      0),
# #         "suspicious":       threat_counts.get("medium",   0),
# #         "high_threats":     threat_counts.get("high",     0),
# #         "critical_threats": threat_counts.get("critical", 0),
# #         "top_attack_types": dict(attack_types.most_common(5)),
# #         "threat_rate":      round((total - threat_counts.get("low", 0)) / max(total, 1) * 100, 1),
# #     }


# # # ── Health ────────────────────────────────────────────────────────────────────

# # @app.get("/")
# # def home():
# #     return {"status": "Network Sentinel Running", "version": "2.2"}

# # @app.get("/health")
# # def health():
# #     return {"status": "ok", "model": "IsolationForest v2", "features": 7}


# # # ── CSV Analysis — accepts any common network dataset ─────────────────────────

# # @app.post("/analyze", tags=["analysis"])
# # async def analyze_csv(file: UploadFile = File(...)):
# #     if not file.filename.lower().endswith(".csv"):
# #         raise HTTPException(400, "Only CSV files are accepted.")
# #     contents = await file.read()

# #     # Try multiple encodings — UNSW-NB15 uses latin-1
# #     df = None
# #     for enc in ("utf-8", "latin-1", "cp1252"):
# #         try:
# #             df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
# #             break
# #         except (UnicodeDecodeError, Exception):
# #             continue
# #     if df is None:
# #         raise HTTPException(400, "Could not parse CSV. Try saving as UTF-8.")

# #     # Auto-map columns — works with UNSW-NB15, CIC-IDS, custom CSVs
# #     try:
# #         df, mapping_notes = _automap_columns(df)
# #     except ValueError as e:
# #         raise HTTPException(422, str(e))

# #     # Sample to 2000 rows for performance — enough for a clear demo
# #     if len(df) > 2000:
# #         df = df.sample(2000, random_state=42).reset_index(drop=True)

# #     predictions = predict_batch(df)
# #     results     = await _build_results(df, predictions)
# #     summary     = _build_summary(results)
# #     summary["column_mapping"] = mapping_notes
# #     return {"summary": summary, "results": results}


# # # ── PCAP Analysis ─────────────────────────────────────────────────────────────

# # @app.post("/analyze-pcap", tags=["analysis"])
# # async def analyze_pcap(file: UploadFile = File(...)):
# #     fname = (file.filename or "").lower()
# #     if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
# #         raise HTTPException(400, "Only .pcap / .pcapng files accepted.")
# #     contents = await file.read()
# #     try:
# #         pcap_df = parse_pcap(contents)
# #     except PCAPParseError as e:
# #         raise HTTPException(422, str(e))
# #     model_df    = pcap_df_to_model_input(pcap_df)
# #     predictions = predict_batch(model_df)
# #     results     = await _build_results(model_df, predictions, pcap_df=pcap_df)
# #     summary = _build_summary(results)
# #     summary["data_source"]    = "pcap"
# #     summary["total_packets"]  = int(pcap_df["_packet_count"].sum()) if "_packet_count" in pcap_df.columns else None
# #     summary["unique_hosts"]   = len(pcap_df)
# #     summary["capture_window"] = float(pcap_df["_duration_sec"].max()) if "_duration_sec" in pcap_df.columns else None
# #     return {"summary": summary, "results": results}


# # # ── Single predict ────────────────────────────────────────────────────────────

# # class LogEntry(BaseModel):
# #     src_ip:      str   = "0.0.0.0"
# #     port:        int
# #     packet_rate: float
# #     packet_size: float = 512.0


# # @app.post("/predict", tags=["analysis"])
# # async def predict_single(entry: LogEntry):
# #     df     = pd.DataFrame([entry.dict()])
# #     result = predict_batch(df)[0]
# #     geo    = await _geolocate(entry.src_ip)
# #     explanation = None
# #     if result["threat_level"] in ("high", "critical"):
# #         try:
# #             explanation = explain_attack({**entry.dict(), **result})
# #         except Exception as e:
# #             explanation = f"AI explanation unavailable: {e}"
# #     payload = {**result, "ai_explanation": explanation, "geo": geo}
# #     if result["threat_level"] == "critical":
# #         await _send_slack_alert({"log": entry.dict(), **payload})
# #     return payload


# # # ── Model Retraining ──────────────────────────────────────────────────────────

# # @app.post("/train", tags=["ml"])
# # async def train_model(file: UploadFile = File(...)):
# #     if not file.filename.lower().endswith(".csv"):
# #         raise HTTPException(400, "Only CSV files are accepted for training.")
# #     contents = await file.read()
# #     df = None
# #     for enc in ("utf-8", "latin-1", "cp1252"):
# #         try:
# #             df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
# #             break
# #         except Exception:
# #             continue
# #     if df is None:
# #         raise HTTPException(400, "Could not parse training CSV.")
# #     try:
# #         df, _ = _automap_columns(df)
# #         stats  = retrain(df)
# #     except ValueError as e:
# #         raise HTTPException(422, str(e))
# #     return stats



# # from dotenv import load_dotenv
# # load_dotenv()  # must be FIRST — loads GEMINI_API_KEY before any client imports

# # import os
# # import io
# # import ipaddress
# # from collections import Counter

# # import httpx
# # import pandas as pd
# # from fastapi import FastAPI, UploadFile, File, HTTPException
# # from fastapi.middleware.cors import CORSMiddleware
# # from pydantic import BaseModel

# # from app.model import predict_batch, retrain
# # from app.gemini_client import explain_attack
# # from app.live import router as live_router
# # from app.chat import chat_router
# # from app.news import news_router
# # from app.pcap_parser import (
# #     parse_pcap, pcap_df_to_model_input,
# #     enrich_result_with_pcap_meta, PCAPParseError,
# # )

# # # ── App ───────────────────────────────────────────────────────────────────────

# # app = FastAPI(title="Network Health Sentinel", version="2.2")

# # app.add_middleware(
# #     CORSMiddleware,
# #     allow_origins=["http://localhost:3000"],
# #     allow_credentials=True,
# #     allow_methods=["*"],
# #     allow_headers=["*"],
# # )

# # # ← routers registered AFTER app is created
# # app.include_router(live_router)
# # app.include_router(chat_router)
# # app.include_router(news_router)

# # REQUIRED_CSV_COLS = {"src_ip", "port", "packet_rate", "packet_size"}


# # # ── IP Geolocation ────────────────────────────────────────────────────────────

# # _RFC1918 = [
# #     ipaddress.ip_network("10.0.0.0/8"),
# #     ipaddress.ip_network("172.16.0.0/12"),
# #     ipaddress.ip_network("192.168.0.0/16"),
# #     ipaddress.ip_network("127.0.0.0/8"),
# # ]

# # def _is_private(ip_str: str) -> bool:
# #     try:
# #         addr = ipaddress.ip_address(ip_str)
# #         return any(addr in net for net in _RFC1918)
# #     except ValueError:
# #         return True


# # async def _geolocate(ip: str) -> dict | None:
# #     if _is_private(ip):
# #         return None
# #     try:
# #         async with httpx.AsyncClient(timeout=3.0) as client:
# #             r = await client.get(
# #                 f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
# #             )
# #         data = r.json()
# #         if data.get("status") == "success":
# #             return {
# #                 "country":      data.get("country"),
# #                 "country_code": data.get("countryCode"),
# #                 "city":         data.get("city"),
# #                 "isp":          data.get("isp"),
# #             }
# #     except Exception:
# #         pass
# #     return None


# # # ── Slack Alerts ──────────────────────────────────────────────────────────────

# # SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# # async def _send_slack_alert(result: dict) -> None:
# #     if not SLACK_WEBHOOK_URL:
# #         return
# #     ip          = result.get("log", {}).get("src_ip", "unknown")
# #     attack_type = result.get("prediction", "Unknown")
# #     score       = result.get("anomaly_score", 0)
# #     explanation = result.get("ai_explanation") or ""
# #     truncated   = explanation[:300] + "…" if len(explanation) > 300 else explanation
# #     geo         = result.get("geo") or {}
# #     location    = f"{geo.get('city','')}, {geo.get('country','')}".strip(", ") or "Unknown"
# #     payload = {
# #         "text": (
# #             f":rotating_light: *CRITICAL THREAT* :rotating_light:\n"
# #             f">*IP:* `{ip}` ({location})\n"
# #             f">*Type:* {attack_type}  |  *Score:* `{score}`\n"
# #             f">*Summary:* {truncated or '_unavailable_'}"
# #         )
# #     }
# #     try:
# #         async with httpx.AsyncClient(timeout=5.0) as client:
# #             await client.post(SLACK_WEBHOOK_URL, json=payload)
# #     except Exception:
# #         pass


# # # ── Shared result builder ─────────────────────────────────────────────────────

# # async def _build_results(
# #     df: pd.DataFrame,
# #     predictions: list[dict],
# #     pcap_df: pd.DataFrame | None = None,
# # ) -> list[dict]:
# #     results = []
# #     for i, (_, row) in enumerate(df.iterrows()):
# #         pred = predictions[i]
# #         log  = row.to_dict()

# #         if pcap_df is not None:
# #             pred = enrich_result_with_pcap_meta(pred, pcap_df.iloc[i])

# #         geo = await _geolocate(str(log.get("src_ip", "")))

# #         explanation = None
# #         if pred["threat_level"] in ("high", "critical"):
# #             try:
# #                 explanation = explain_attack({**log, **pred})
# #             except Exception as e:
# #                 explanation = f"AI explanation unavailable: {e}"

# #         entry = {
# #             "log":            log,
# #             "prediction":     pred["prediction"],
# #             "threat_level":   pred["threat_level"],
# #             "anomaly_score":  pred["anomaly_score"],
# #             "confidence":     pred.get("threat_confidence", 0),
# #             "ai_explanation": explanation,
# #             "geo":            geo,
# #             "packet_count":   pred.get("packet_count"),
# #             "unique_ports":   pred.get("unique_ports"),
# #             "duration_sec":   pred.get("duration_sec"),
# #             "data_source":    pred.get("data_source", "csv"),
# #         }

# #         if pred["threat_level"] == "critical":
# #             await _send_slack_alert(entry)

# #         results.append(entry)
# #     return results


# # def _build_summary(results: list[dict]) -> dict:
# #     threat_counts = Counter(r["threat_level"] for r in results)
# #     attack_types  = Counter(
# #         r["prediction"] for r in results if r["prediction"] != "Normal"
# #     )
# #     total = len(results)
# #     return {
# #         "total_logs":       total,
# #         "normal":           threat_counts.get("low",      0),
# #         "suspicious":       threat_counts.get("medium",   0),
# #         "high_threats":     threat_counts.get("high",     0),
# #         "critical_threats": threat_counts.get("critical", 0),
# #         "top_attack_types": dict(attack_types.most_common(5)),
# #         "threat_rate":      round(
# #             (total - threat_counts.get("low", 0)) / max(total, 1) * 100, 1
# #         ),
# #     }


# # # ── Health ────────────────────────────────────────────────────────────────────

# # @app.get("/")
# # def home():
# #     return {"status": "Network Sentinel Running", "version": "2.2"}


# # @app.get("/health")
# # def health():
# #     return {"status": "ok", "model": "IsolationForest v2", "features": 7}


# # # ── CSV Analysis ──────────────────────────────────────────────────────────────

# # @app.post("/analyze", tags=["analysis"])
# # async def analyze_csv(file: UploadFile = File(...)):
# #     if not file.filename.endswith(".csv"):
# #         raise HTTPException(400, "Only CSV files are accepted.")
# #     contents = await file.read()
# #     try:
# #         df = pd.read_csv(io.BytesIO(contents))
# #     except Exception:
# #         raise HTTPException(400, "Could not parse CSV.")
# #     missing = REQUIRED_CSV_COLS - set(df.columns)
# #     if missing:
# #         raise HTTPException(422, f"CSV missing columns: {missing}")
# #     predictions = predict_batch(df)
# #     results     = await _build_results(df, predictions)
# #     return {"summary": _build_summary(results), "results": results}


# # # ── PCAP Analysis ─────────────────────────────────────────────────────────────

# # @app.post("/analyze-pcap", tags=["analysis"])
# # async def analyze_pcap(file: UploadFile = File(...)):
# #     fname = (file.filename or "").lower()
# #     if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
# #         raise HTTPException(400, "Only .pcap / .pcapng files accepted.")
# #     contents = await file.read()
# #     try:
# #         pcap_df = parse_pcap(contents)
# #     except PCAPParseError as e:
# #         raise HTTPException(422, str(e))
# #     model_df    = pcap_df_to_model_input(pcap_df)
# #     predictions = predict_batch(model_df)
# #     results     = await _build_results(model_df, predictions, pcap_df=pcap_df)
# #     summary = _build_summary(results)
# #     summary["data_source"]    = "pcap"
# #     summary["total_packets"]  = int(pcap_df["_packet_count"].sum()) \
# #                                  if "_packet_count" in pcap_df.columns else None
# #     summary["unique_hosts"]   = len(pcap_df)
# #     summary["capture_window"] = float(pcap_df["_duration_sec"].max()) \
# #                                  if "_duration_sec" in pcap_df.columns else None
# #     return {"summary": summary, "results": results}


# # # ── Single predict ────────────────────────────────────────────────────────────

# # class LogEntry(BaseModel):
# #     src_ip:      str   = "0.0.0.0"
# #     port:        int
# #     packet_rate: float
# #     packet_size: float = 512.0


# # @app.post("/predict", tags=["analysis"])
# # async def predict_single(entry: LogEntry):
# #     df     = pd.DataFrame([entry.dict()])
# #     result = predict_batch(df)[0]
# #     geo    = await _geolocate(entry.src_ip)
# #     explanation = None
# #     if result["threat_level"] in ("high", "critical"):
# #         try:
# #             explanation = explain_attack({**entry.dict(), **result})
# #         except Exception as e:
# #             explanation = f"AI explanation unavailable: {e}"
# #     payload = {**result, "ai_explanation": explanation, "geo": geo}
# #     if result["threat_level"] == "critical":
# #         await _send_slack_alert({"log": entry.dict(), **payload})
# #     return payload


# # # ── Model Retraining ──────────────────────────────────────────────────────────

# # @app.post("/train", tags=["ml"])
# # async def train_model(file: UploadFile = File(...)):
# #     if not file.filename.endswith(".csv"):
# #         raise HTTPException(400, "Only CSV files are accepted for training.")
# #     contents = await file.read()
# #     try:
# #         df = pd.read_csv(io.BytesIO(contents))
# #     except Exception:
# #         raise HTTPException(400, "Could not parse training CSV.")
# #     try:
# #         stats = retrain(df)
# #     except ValueError as e:
# #         raise HTTPException(422, str(e))
# #     return stats



# from dotenv import load_dotenv
# load_dotenv()

# import os
# import io
# import ipaddress
# from collections import Counter

# import httpx
# import pandas as pd
# from fastapi import FastAPI, UploadFile, File, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel

# from app.model import predict_batch, retrain
# from app.gemini_client import explain_attack
# from app.live import router as live_router
# from app.chat import chat_router
# from app.news import news_router
# from app.pcap_parser import (
#     parse_pcap, pcap_df_to_model_input,
#     enrich_result_with_pcap_meta, PCAPParseError,
# )

# # ── App ───────────────────────────────────────────────────────────────────────

# app = FastAPI(title="Network Health Sentinel", version="2.2")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:3000", "https://network-health-sentinel.vercel.app"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# app.include_router(live_router)
# app.include_router(chat_router)
# app.include_router(news_router)

# REQUIRED_CSV_COLS = {"src_ip", "port", "packet_rate", "packet_size"}

# # ── Column auto-mapper ────────────────────────────────────────────────────────
# # Upload UNSW-NB15, CIC-IDS-2017, KDD99, or any CSV — no renaming needed.

# COLUMN_MAP = {
#     # src_ip
#     "srcip": "src_ip", "src_ip_addr": "src_ip", "source_ip": "src_ip",
#     "ip_src": "src_ip", "sourceip": "src_ip", "src": "src_ip",
#     "source": "src_ip", "sip": "src_ip",
#     # port
#     "sport": "port", "src_port": "port", "source_port": "port",
#     "dport": "port", "dst_port": "port", "destination_port": "port",
#     "l4_src_port": "port",
#     # packet_rate — KDD: count = connections/sec to same host
#     "rate": "packet_rate", "pkt_rate": "packet_rate",
#     "flow_pkts_s": "packet_rate", "flow_pkts/s": "packet_rate",
#     "total_fwd_packets": "packet_rate", "pkts_per_sec": "packet_rate",
#     "num_pkts_sent": "packet_rate", "pkts": "packet_rate",
#     "tot_fwd_pkts": "packet_rate", "totfwdpkts": "packet_rate",
#     "count": "packet_rate",
#     # packet_size — KDD: src_bytes = bytes sent from source
#     "smean": "packet_size", "sbytes": "packet_size", "dmean": "packet_size",
#     "src_bytes": "packet_size", "pktlen_mean": "packet_size",
#     "avg_pkt_size": "packet_size",
#     "total_length_of_fwd_packets": "packet_size", "totlenfwdpkts": "packet_size",
#     "byts_per_sec": "packet_size", "bytes": "packet_size",
#     "flow_byts_s": "packet_size", "flow_byts/s": "packet_size",
#     "fwd_pkt_len_mean": "packet_size",
# }

# # KDD Cup 99 / NSL-KDD service name → well-known port number
# _KDD_SERVICE_PORT: dict[str, int] = {
#     "http": 80, "https": 443, "http_443": 443, "http_8001": 8001,
#     "ftp": 21, "ftp_data": 20, "ssh": 22, "smtp": 25, "dns": 53,
#     "domain": 53, "domain_u": 53, "pop_3": 110, "imap4": 143,
#     "telnet": 23, "finger": 79, "auth": 113, "bgp": 179,
#     "irc": 6667, "ldap": 389, "login": 513, "shell": 514,
#     "exec": 512, "klogin": 543, "kshell": 544,
#     "netbios_dgm": 138, "netbios_ns": 137, "netbios_ssn": 139,
#     "nntp": 119, "ntp_u": 123, "printer": 515, "rje": 77,
#     "sql_net": 1521, "sunrpc": 111, "systat": 11, "tftp_u": 69,
#     "uucp": 540, "whois": 43, "x11": 6000, "Z39_50": 210,
#     "gopher": 70, "mtp": 57, "name": 42, "netstat": 15,
#     "supdup": 95, "time": 37, "eco_i": 8, "ecr_i": 8, "red_i": 8,
#     "urh_i": 0, "urp_i": 0, "tim_i": 37, "icmp": 0,
#     "private": 1024, "other": 0, "pm_dump": 0, "vmnet": 175,
#     "courier": 530, "csnet_ns": 105, "ctf": 84, "daytime": 13,
#     "discard": 9, "echo": 7, "efs": 520, "harvest": 8000,
#     "hostnames": 101, "iso_tsap": 102, "link": 245, "nnsp": 433,
#     "pop_2": 109, "remote_job": 514, "uucp_path": 117,
# }


# def _automap_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
#     """
#     Renames dataset columns to our internal schema automatically.
#     Handles: custom CSVs, UNSW-NB15, CIC-IDS-2017, KDD Cup 99, NSL-KDD.
#     Returns (remapped_df, notes).
#     """
#     cols_lower = {c.lower().strip().replace(" ", "_"): c for c in df.columns}
#     rename: dict[str, str] = {}
#     mapped_targets: set[str] = set()

#     for raw, target in COLUMN_MAP.items():
#         if target in mapped_targets:
#             continue
#         key = raw.lower().replace(" ", "_")
#         if key in cols_lower and cols_lower[key] not in rename:
#             rename[cols_lower[key]] = target
#             mapped_targets.add(target)

#     df = df.rename(columns=rename)
#     notes = [f"{src} → {dst}" for src, dst in rename.items()]

#     # ── src_ip ────────────────────────────────────────────────────────────────
#     if "src_ip" not in df.columns:
#         ip_cols = [c for c in df.columns if "ip" in c.lower()]
#         if ip_cols:
#             df["src_ip"] = df[ip_cols[0]].astype(str)
#             notes.append(f"src_ip ← {ip_cols[0]}")
#         else:
#             # KDD has no IPs — synthesize plausible addresses from row index
#             # so that different rows appear as different hosts in the UI
#             df["src_ip"] = [f"10.0.{(i // 254) % 255}.{(i % 254) + 1}"
#                             for i in range(len(df))]
#             notes.append("src_ip synthesized (KDD has no IP column)")

#     # ── port ─────────────────────────────────────────────────────────────────
#     if "port" not in df.columns:
#         # KDD uses a 'service' column (e.g. 'http', 'ftp', 'ssh')
#         if "service" in df.columns:
#             df["port"] = df["service"].str.lower().str.strip().map(
#                 _KDD_SERVICE_PORT
#             ).fillna(0).astype(int)
#             notes.append("port ← service (KDD service→port mapping)")
#         else:
#             port_cols = [c for c in df.columns if "port" in c.lower()]
#             if port_cols:
#                 df["port"] = pd.to_numeric(df[port_cols[0]], errors="coerce").fillna(0)
#                 notes.append(f"port ← {port_cols[0]}")
#             else:
#                 df["port"] = 0
#                 notes.append("port defaulted to 0")

#     # ── packet_rate ───────────────────────────────────────────────────────────
#     if "packet_rate" not in df.columns:
#         dur  = next((c for c in df.columns if "dur" in c.lower()), None)
#         byts = next((c for c in df.columns if "byt" in c.lower()), None)
#         if dur and byts:
#             d = pd.to_numeric(df[dur],  errors="coerce").replace(0, 1).fillna(1)
#             b = pd.to_numeric(df[byts], errors="coerce").fillna(0)
#             df["packet_rate"] = (b / d).clip(0, 5000)
#             notes.append(f"packet_rate derived from {byts}/{dur}")
#         else:
#             df["packet_rate"] = 100.0
#             notes.append("packet_rate defaulted to 100")

#     # ── packet_size ───────────────────────────────────────────────────────────
#     if "packet_size" not in df.columns:
#         df["packet_size"] = 512.0
#         notes.append("packet_size defaulted to 512")

#     # ── Sanitise ──────────────────────────────────────────────────────────────
#     df["port"]        = pd.to_numeric(df["port"],        errors="coerce").fillna(0).clip(0, 65535).astype(int)
#     df["packet_rate"] = pd.to_numeric(df["packet_rate"], errors="coerce").fillna(0).clip(0, 10000)
#     df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce").fillna(512).clip(0, 65535)

#     return df, notes


# # ── IP Geolocation ────────────────────────────────────────────────────────────

# _RFC1918 = [
#     ipaddress.ip_network("10.0.0.0/8"),
#     ipaddress.ip_network("172.16.0.0/12"),
#     ipaddress.ip_network("192.168.0.0/16"),
#     ipaddress.ip_network("127.0.0.0/8"),
# ]

# def _is_private(ip_str: str) -> bool:
#     try:
#         return any(ipaddress.ip_address(ip_str) in net for net in _RFC1918)
#     except ValueError:
#         return True


# async def _geolocate(ip: str) -> dict | None:
#     if _is_private(ip):
#         return None
#     try:
#         async with httpx.AsyncClient(timeout=3.0) as client:
#             r = await client.get(
#                 f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
#             )
#         data = r.json()
#         if data.get("status") == "success":
#             return {
#                 "country":      data.get("country"),
#                 "country_code": data.get("countryCode"),
#                 "city":         data.get("city"),
#                 "isp":          data.get("isp"),
#             }
#     except Exception:
#         pass
#     return None


# # ── Slack Alerts ──────────────────────────────────────────────────────────────

# SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# async def _send_slack_alert(result: dict) -> None:
#     if not SLACK_WEBHOOK_URL:
#         return
#     ip          = result.get("log", {}).get("src_ip", "unknown")
#     attack_type = result.get("prediction", "Unknown")
#     score       = result.get("anomaly_score", 0)
#     explanation = result.get("ai_explanation") or ""
#     truncated   = explanation[:300] + "…" if len(explanation) > 300 else explanation
#     geo         = result.get("geo") or {}
#     location    = f"{geo.get('city','')}, {geo.get('country','')}".strip(", ") or "Unknown"
#     try:
#         async with httpx.AsyncClient(timeout=5.0) as client:
#             await client.post(SLACK_WEBHOOK_URL, json={
#                 "text": (
#                     f":rotating_light: *CRITICAL THREAT* :rotating_light:\n"
#                     f">*IP:* `{ip}` ({location})\n"
#                     f">*Type:* {attack_type}  |  *Score:* `{score}`\n"
#                     f">*Summary:* {truncated or '_unavailable_'}"
#                 )
#             })
#     except Exception:
#         pass


# # ── Shared result builder ─────────────────────────────────────────────────────

# async def _build_results(
#     df: pd.DataFrame,
#     predictions: list[dict],
#     pcap_df: pd.DataFrame | None = None,
# ) -> list[dict]:
#     results = []
#     for i, (_, row) in enumerate(df.iterrows()):
#         pred = predictions[i]
#         log  = row.to_dict()
#         if pcap_df is not None:
#             pred = enrich_result_with_pcap_meta(pred, pcap_df.iloc[i])
#         geo = await _geolocate(str(log.get("src_ip", "")))
#         explanation = None
#         if pred["threat_level"] in ("high", "critical"):
#             try:
#                 explanation = explain_attack({**log, **pred})
#             except Exception as e:
#                 explanation = f"AI explanation unavailable: {e}"
#         entry = {
#             "log":            log,
#             "prediction":     pred["prediction"],
#             "threat_level":   pred["threat_level"],
#             "anomaly_score":  pred["anomaly_score"],
#             "confidence":     pred.get("threat_confidence", 0),
#             "ai_explanation": explanation,
#             "geo":            geo,
#             "packet_count":   pred.get("packet_count"),
#             "unique_ports":   pred.get("unique_ports"),
#             "duration_sec":   pred.get("duration_sec"),
#             "data_source":    pred.get("data_source", "csv"),
#         }
#         if pred["threat_level"] == "critical":
#             await _send_slack_alert(entry)
#         results.append(entry)
#     return results


# def _build_summary(results: list[dict]) -> dict:
#     threat_counts = Counter(r["threat_level"] for r in results)
#     attack_types  = Counter(r["prediction"] for r in results if r["prediction"] != "Normal")
#     total = len(results)
#     return {
#         "total_logs":       total,
#         "normal":           threat_counts.get("low",      0),
#         "suspicious":       threat_counts.get("medium",   0),
#         "high_threats":     threat_counts.get("high",     0),
#         "critical_threats": threat_counts.get("critical", 0),
#         "top_attack_types": dict(attack_types.most_common(5)),
#         "threat_rate":      round((total - threat_counts.get("low", 0)) / max(total, 1) * 100, 1),
#     }


# # ── Health ────────────────────────────────────────────────────────────────────

# @app.get("/")
# def home():
#     return {"status": "Network Sentinel Running", "version": "2.2"}

# @app.get("/health")
# def health():
#     return {"status": "ok", "model": "IsolationForest v2", "features": 7}


# # ── CSV Analysis — accepts any common network dataset ─────────────────────────

# @app.post("/analyze", tags=["analysis"])
# async def analyze_csv(file: UploadFile = File(...)):
#     if not file.filename.lower().endswith(".csv"):
#         raise HTTPException(400, "Only CSV files are accepted.")
#     contents = await file.read()

#     # Try multiple encodings — UNSW-NB15 uses latin-1
#     df = None
#     for enc in ("utf-8", "latin-1", "cp1252"):
#         try:
#             df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
#             break
#         except (UnicodeDecodeError, Exception):
#             continue
#     if df is None:
#         raise HTTPException(400, "Could not parse CSV. Try saving as UTF-8.")

#     # Auto-map columns — works with UNSW-NB15, CIC-IDS, custom CSVs
#     try:
#         df, mapping_notes = _automap_columns(df)
#     except ValueError as e:
#         raise HTTPException(422, str(e))

#     # Sample to 2000 rows for performance — enough for a clear demo
#     if len(df) > 2000:
#         df = df.sample(2000, random_state=42).reset_index(drop=True)

#     predictions = predict_batch(df)
#     results     = await _build_results(df, predictions)
#     summary     = _build_summary(results)
#     summary["column_mapping"] = mapping_notes
#     return {"summary": summary, "results": results}


# # ── PCAP Analysis ─────────────────────────────────────────────────────────────

# @app.post("/analyze-pcap", tags=["analysis"])
# async def analyze_pcap(file: UploadFile = File(...)):
#     fname = (file.filename or "").lower()
#     if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
#         raise HTTPException(400, "Only .pcap / .pcapng files accepted.")
#     contents = await file.read()
#     try:
#         pcap_df = parse_pcap(contents)
#     except PCAPParseError as e:
#         raise HTTPException(422, str(e))
#     model_df    = pcap_df_to_model_input(pcap_df)
#     predictions = predict_batch(model_df)
#     results     = await _build_results(model_df, predictions, pcap_df=pcap_df)
#     summary = _build_summary(results)
#     summary["data_source"]    = "pcap"
#     summary["total_packets"]  = int(pcap_df["_packet_count"].sum()) if "_packet_count" in pcap_df.columns else None
#     summary["unique_hosts"]   = len(pcap_df)
#     summary["capture_window"] = float(pcap_df["_duration_sec"].max()) if "_duration_sec" in pcap_df.columns else None
#     return {"summary": summary, "results": results}


# # ── Single predict ────────────────────────────────────────────────────────────

# class LogEntry(BaseModel):
#     src_ip:      str   = "0.0.0.0"
#     port:        int
#     packet_rate: float
#     packet_size: float = 512.0


# @app.post("/predict", tags=["analysis"])
# async def predict_single(entry: LogEntry):
#     df     = pd.DataFrame([entry.dict()])
#     result = predict_batch(df)[0]
#     geo    = await _geolocate(entry.src_ip)
#     explanation = None
#     if result["threat_level"] in ("high", "critical"):
#         try:
#             explanation = explain_attack({**entry.dict(), **result})
#         except Exception as e:
#             explanation = f"AI explanation unavailable: {e}"
#     payload = {**result, "ai_explanation": explanation, "geo": geo}
#     if result["threat_level"] == "critical":
#         await _send_slack_alert({"log": entry.dict(), **payload})
#     return payload


# # ── Model Retraining ──────────────────────────────────────────────────────────

# @app.post("/train", tags=["ml"])
# async def train_model(file: UploadFile = File(...)):
#     if not file.filename.lower().endswith(".csv"):
#         raise HTTPException(400, "Only CSV files are accepted for training.")
#     contents = await file.read()
#     df = None
#     for enc in ("utf-8", "latin-1", "cp1252"):
#         try:
#             df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
#             break
#         except Exception:
#             continue
#     if df is None:
#         raise HTTPException(400, "Could not parse training CSV.")
#     try:
#         df, _ = _automap_columns(df)
#         stats  = retrain(df)
#     except ValueError as e:
#         raise HTTPException(422, str(e))
#     return stats
# from dotenv import load_dotenv
# load_dotenv()  # must be FIRST — loads GEMINI_API_KEY before any client imports

# import os
# import io
# import ipaddress
# from collections import Counter

# import httpx
# import pandas as pd
# from fastapi import FastAPI, UploadFile, File, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel

# from app.model import predict_batch, retrain
# from app.gemini_client import explain_attack
# from app.live import router as live_router
# from app.chat import chat_router
# from app.news import news_router
# from app.pcap_parser import (
#     parse_pcap, pcap_df_to_model_input,
#     enrich_result_with_pcap_meta, PCAPParseError,
# )

# # ── App ───────────────────────────────────────────────────────────────────────

# app = FastAPI(title="Network Health Sentinel", version="2.2")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:3000", "https://network-health-sentinel.vercel.app", "https://network-health-sentinel-git-main.vercel.app"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # ← routers registered AFTER app is created
# app.include_router(live_router)
# app.include_router(chat_router)
# app.include_router(news_router)

# REQUIRED_CSV_COLS = {"src_ip", "port", "packet_rate", "packet_size"}


# # ── IP Geolocation ────────────────────────────────────────────────────────────

# _RFC1918 = [
#     ipaddress.ip_network("10.0.0.0/8"),
#     ipaddress.ip_network("172.16.0.0/12"),
#     ipaddress.ip_network("192.168.0.0/16"),
#     ipaddress.ip_network("127.0.0.0/8"),
# ]

# def _is_private(ip_str: str) -> bool:
#     try:
#         addr = ipaddress.ip_address(ip_str)
#         return any(addr in net for net in _RFC1918)
#     except ValueError:
#         return True


# async def _geolocate(ip: str) -> dict | None:
#     if _is_private(ip):
#         return None
#     try:
#         async with httpx.AsyncClient(timeout=3.0) as client:
#             r = await client.get(
#                 f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
#             )
#         data = r.json()
#         if data.get("status") == "success":
#             return {
#                 "country":      data.get("country"),
#                 "country_code": data.get("countryCode"),
#                 "city":         data.get("city"),
#                 "isp":          data.get("isp"),
#             }
#     except Exception:
#         pass
#     return None


# # ── Slack Alerts ──────────────────────────────────────────────────────────────

# SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# async def _send_slack_alert(result: dict) -> None:
#     if not SLACK_WEBHOOK_URL:
#         return
#     ip          = result.get("log", {}).get("src_ip", "unknown")
#     attack_type = result.get("prediction", "Unknown")
#     score       = result.get("anomaly_score", 0)
#     explanation = result.get("ai_explanation") or ""
#     truncated   = explanation[:300] + "…" if len(explanation) > 300 else explanation
#     geo         = result.get("geo") or {}
#     location    = f"{geo.get('city','')}, {geo.get('country','')}".strip(", ") or "Unknown"
#     payload = {
#         "text": (
#             f":rotating_light: *CRITICAL THREAT* :rotating_light:\n"
#             f">*IP:* `{ip}` ({location})\n"
#             f">*Type:* {attack_type}  |  *Score:* `{score}`\n"
#             f">*Summary:* {truncated or '_unavailable_'}"
#         )
#     }
#     try:
#         async with httpx.AsyncClient(timeout=5.0) as client:
#             await client.post(SLACK_WEBHOOK_URL, json=payload)
#     except Exception:
#         pass


# # ── Shared result builder ─────────────────────────────────────────────────────

# async def _build_results(
#     df: pd.DataFrame,
#     predictions: list[dict],
#     pcap_df: pd.DataFrame | None = None,
# ) -> list[dict]:
#     results = []
#     for i, (_, row) in enumerate(df.iterrows()):
#         pred = predictions[i]
#         log  = row.to_dict()

#         if pcap_df is not None:
#             pred = enrich_result_with_pcap_meta(pred, pcap_df.iloc[i])

#         geo = await _geolocate(str(log.get("src_ip", "")))

#         explanation = None
#         if pred["threat_level"] in ("high", "critical"):
#             try:
#                 explanation = explain_attack({**log, **pred})
#             except Exception as e:
#                 explanation = f"AI explanation unavailable: {e}"

#         entry = {
#             "log":            log,
#             "prediction":     pred["prediction"],
#             "threat_level":   pred["threat_level"],
#             "anomaly_score":  pred["anomaly_score"],
#             "confidence":     pred.get("threat_confidence", 0),
#             "ai_explanation": explanation,
#             "geo":            geo,
#             "packet_count":   pred.get("packet_count"),
#             "unique_ports":   pred.get("unique_ports"),
#             "duration_sec":   pred.get("duration_sec"),
#             "data_source":    pred.get("data_source", "csv"),
#         }

#         if pred["threat_level"] == "critical":
#             await _send_slack_alert(entry)

#         results.append(entry)
#     return results


# def _build_summary(results: list[dict]) -> dict:
#     threat_counts = Counter(r["threat_level"] for r in results)
#     attack_types  = Counter(
#         r["prediction"] for r in results if r["prediction"] != "Normal"
#     )
#     total = len(results)
#     return {
#         "total_logs":       total,
#         "normal":           threat_counts.get("low",      0),
#         "suspicious":       threat_counts.get("medium",   0),
#         "high_threats":     threat_counts.get("high",     0),
#         "critical_threats": threat_counts.get("critical", 0),
#         "top_attack_types": dict(attack_types.most_common(5)),
#         "threat_rate":      round(
#             (total - threat_counts.get("low", 0)) / max(total, 1) * 100, 1
#         ),
#     }


# # ── Health ────────────────────────────────────────────────────────────────────

# @app.get("/")
# def home():
#     return {"status": "Network Sentinel Running", "version": "2.2"}


# @app.get("/health")
# def health():
#     return {"status": "ok", "model": "IsolationForest v2", "features": 7}


# # ── CSV Analysis ──────────────────────────────────────────────────────────────

# @app.post("/analyze", tags=["analysis"])
# async def analyze_csv(file: UploadFile = File(...)):
#     if not file.filename.endswith(".csv"):
#         raise HTTPException(400, "Only CSV files are accepted.")
#     contents = await file.read()
#     try:
#         df = pd.read_csv(io.BytesIO(contents))
#     except Exception:
#         raise HTTPException(400, "Could not parse CSV.")
#     missing = REQUIRED_CSV_COLS - set(df.columns)
#     if missing:
#         raise HTTPException(422, f"CSV missing columns: {missing}")
#     predictions = predict_batch(df)
#     results     = await _build_results(df, predictions)
#     return {"summary": _build_summary(results), "results": results}


# # ── PCAP Analysis ─────────────────────────────────────────────────────────────

# @app.post("/analyze-pcap", tags=["analysis"])
# async def analyze_pcap(file: UploadFile = File(...)):
#     fname = (file.filename or "").lower()
#     if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
#         raise HTTPException(400, "Only .pcap / .pcapng files accepted.")
#     contents = await file.read()
#     try:
#         pcap_df = parse_pcap(contents)
#     except PCAPParseError as e:
#         raise HTTPException(422, str(e))
#     model_df    = pcap_df_to_model_input(pcap_df)
#     predictions = predict_batch(model_df)
#     results     = await _build_results(model_df, predictions, pcap_df=pcap_df)
#     summary = _build_summary(results)
#     summary["data_source"]    = "pcap"
#     summary["total_packets"]  = int(pcap_df["_packet_count"].sum()) \
#                                  if "_packet_count" in pcap_df.columns else None
#     summary["unique_hosts"]   = len(pcap_df)
#     summary["capture_window"] = float(pcap_df["_duration_sec"].max()) \
#                                  if "_duration_sec" in pcap_df.columns else None
#     return {"summary": summary, "results": results}


# # ── Single predict ────────────────────────────────────────────────────────────

# class LogEntry(BaseModel):
#     src_ip:      str   = "0.0.0.0"
#     port:        int
#     packet_rate: float
#     packet_size: float = 512.0


# @app.post("/predict", tags=["analysis"])
# async def predict_single(entry: LogEntry):
#     df     = pd.DataFrame([entry.dict()])
#     result = predict_batch(df)[0]
#     geo    = await _geolocate(entry.src_ip)
#     explanation = None
#     if result["threat_level"] in ("high", "critical"):
#         try:
#             explanation = explain_attack({**entry.dict(), **result})
#         except Exception as e:
#             explanation = f"AI explanation unavailable: {e}"
#     payload = {**result, "ai_explanation": explanation, "geo": geo}
#     if result["threat_level"] == "critical":
#         await _send_slack_alert({"log": entry.dict(), **payload})
#     return payload


# # ── Model Retraining ──────────────────────────────────────────────────────────

# @app.post("/train", tags=["ml"])
# async def train_model(file: UploadFile = File(...)):
#     if not file.filename.endswith(".csv"):
#         raise HTTPException(400, "Only CSV files are accepted for training.")
#     contents = await file.read()
#     try:
#         df = pd.read_csv(io.BytesIO(contents))
#     except Exception:
#         raise HTTPException(400, "Could not parse training CSV.")
#     try:
#         stats = retrain(df)
#     except ValueError as e:
#         raise HTTPException(422, str(e))
#     return stats

# from dotenv import load_dotenv
# load_dotenv()  # must be FIRST — loads GEMINI_API_KEY before any client imports

# import os
# import io
# import ipaddress
# from collections import Counter

# import httpx
# import pandas as pd
# from fastapi import FastAPI, UploadFile, File, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel

# from app.model import predict_batch, retrain
# from app.gemini_client import explain_attack
# from app.live import router as live_router
# from app.chat import chat_router
# from app.news import news_router
# from app.pcap_parser import (
#     parse_pcap, pcap_df_to_model_input,
#     enrich_result_with_pcap_meta, PCAPParseError,
# )

# # ── App ───────────────────────────────────────────────────────────────────────

# app = FastAPI(title="Network Health Sentinel", version="2.2")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # ← routers registered AFTER app is created
# app.include_router(live_router)
# app.include_router(chat_router)
# app.include_router(news_router)

# REQUIRED_CSV_COLS = {"src_ip", "port", "packet_rate", "packet_size"}


# # ── IP Geolocation ────────────────────────────────────────────────────────────

# _RFC1918 = [
#     ipaddress.ip_network("10.0.0.0/8"),
#     ipaddress.ip_network("172.16.0.0/12"),
#     ipaddress.ip_network("192.168.0.0/16"),
#     ipaddress.ip_network("127.0.0.0/8"),
# ]

# def _is_private(ip_str: str) -> bool:
#     try:
#         addr = ipaddress.ip_address(ip_str)
#         return any(addr in net for net in _RFC1918)
#     except ValueError:
#         return True


# async def _geolocate(ip: str) -> dict | None:
#     if _is_private(ip):
#         return None
#     try:
#         async with httpx.AsyncClient(timeout=3.0) as client:
#             r = await client.get(
#                 f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
#             )
#         data = r.json()
#         if data.get("status") == "success":
#             return {
#                 "country":      data.get("country"),
#                 "country_code": data.get("countryCode"),
#                 "city":         data.get("city"),
#                 "isp":          data.get("isp"),
#             }
#     except Exception:
#         pass
#     return None


# # ── Slack Alerts ──────────────────────────────────────────────────────────────

# SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# async def _send_slack_alert(result: dict) -> None:
#     if not SLACK_WEBHOOK_URL:
#         return
#     ip          = result.get("log", {}).get("src_ip", "unknown")
#     attack_type = result.get("prediction", "Unknown")
#     score       = result.get("anomaly_score", 0)
#     explanation = result.get("ai_explanation") or ""
#     truncated   = explanation[:300] + "…" if len(explanation) > 300 else explanation
#     geo         = result.get("geo") or {}
#     location    = f"{geo.get('city','')}, {geo.get('country','')}".strip(", ") or "Unknown"
#     payload = {
#         "text": (
#             f":rotating_light: *CRITICAL THREAT* :rotating_light:\n"
#             f">*IP:* `{ip}` ({location})\n"
#             f">*Type:* {attack_type}  |  *Score:* `{score}`\n"
#             f">*Summary:* {truncated or '_unavailable_'}"
#         )
#     }
#     try:
#         async with httpx.AsyncClient(timeout=5.0) as client:
#             await client.post(SLACK_WEBHOOK_URL, json=payload)
#     except Exception:
#         pass


# # ── Shared result builder ─────────────────────────────────────────────────────

# async def _build_results(
#     df: pd.DataFrame,
#     predictions: list[dict],
#     pcap_df: pd.DataFrame | None = None,
# ) -> list[dict]:
#     results = []
#     for i, (_, row) in enumerate(df.iterrows()):
#         pred = predictions[i]
#         log  = row.to_dict()

#         if pcap_df is not None:
#             pred = enrich_result_with_pcap_meta(pred, pcap_df.iloc[i])

#         geo = await _geolocate(str(log.get("src_ip", "")))

#         explanation = None
#         if pred["threat_level"] in ("high", "critical"):
#             try:
#                 explanation = explain_attack({**log, **pred})
#             except Exception as e:
#                 explanation = f"AI explanation unavailable: {e}"

#         entry = {
#             "log":            log,
#             "prediction":     pred["prediction"],
#             "threat_level":   pred["threat_level"],
#             "anomaly_score":  pred["anomaly_score"],
#             "confidence":     pred.get("threat_confidence", 0),
#             "ai_explanation": explanation,
#             "geo":            geo,
#             "packet_count":   pred.get("packet_count"),
#             "unique_ports":   pred.get("unique_ports"),
#             "duration_sec":   pred.get("duration_sec"),
#             "data_source":    pred.get("data_source", "csv"),
#         }

#         if pred["threat_level"] == "critical":
#             await _send_slack_alert(entry)

#         results.append(entry)
#     return results


# def _build_summary(results: list[dict]) -> dict:
#     threat_counts = Counter(r["threat_level"] for r in results)
#     attack_types  = Counter(
#         r["prediction"] for r in results if r["prediction"] != "Normal"
#     )
#     total = len(results)
#     return {
#         "total_logs":       total,
#         "normal":           threat_counts.get("low",      0),
#         "suspicious":       threat_counts.get("medium",   0),
#         "high_threats":     threat_counts.get("high",     0),
#         "critical_threats": threat_counts.get("critical", 0),
#         "top_attack_types": dict(attack_types.most_common(5)),
#         "threat_rate":      round(
#             (total - threat_counts.get("low", 0)) / max(total, 1) * 100, 1
#         ),
#     }


# # ── Health ────────────────────────────────────────────────────────────────────

# @app.get("/")
# def home():
#     return {"status": "Network Sentinel Running", "version": "2.2"}


# @app.get("/health")
# def health():
#     return {"status": "ok", "model": "IsolationForest v2", "features": 7}


# # ── CSV Analysis ──────────────────────────────────────────────────────────────

# @app.post("/analyze", tags=["analysis"])
# async def analyze_csv(file: UploadFile = File(...)):
#     if not file.filename.endswith(".csv"):
#         raise HTTPException(400, "Only CSV files are accepted.")
#     contents = await file.read()
#     try:
#         df = pd.read_csv(io.BytesIO(contents))
#     except Exception:
#         raise HTTPException(400, "Could not parse CSV.")
#     missing = REQUIRED_CSV_COLS - set(df.columns)
#     if missing:
#         raise HTTPException(422, f"CSV missing columns: {missing}")
#     predictions = predict_batch(df)
#     results     = await _build_results(df, predictions)
#     return {"summary": _build_summary(results), "results": results}


# # ── PCAP Analysis ─────────────────────────────────────────────────────────────

# @app.post("/analyze-pcap", tags=["analysis"])
# async def analyze_pcap(file: UploadFile = File(...)):
#     fname = (file.filename or "").lower()
#     if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
#         raise HTTPException(400, "Only .pcap / .pcapng files accepted.")
#     contents = await file.read()
#     try:
#         pcap_df = parse_pcap(contents)
#     except PCAPParseError as e:
#         raise HTTPException(422, str(e))
#     model_df    = pcap_df_to_model_input(pcap_df)
#     predictions = predict_batch(model_df)
#     results     = await _build_results(model_df, predictions, pcap_df=pcap_df)
#     summary = _build_summary(results)
#     summary["data_source"]    = "pcap"
#     summary["total_packets"]  = int(pcap_df["_packet_count"].sum()) \
#                                  if "_packet_count" in pcap_df.columns else None
#     summary["unique_hosts"]   = len(pcap_df)
#     summary["capture_window"] = float(pcap_df["_duration_sec"].max()) \
#                                  if "_duration_sec" in pcap_df.columns else None
#     return {"summary": summary, "results": results}


# # ── Single predict ────────────────────────────────────────────────────────────

# class LogEntry(BaseModel):
#     src_ip:      str   = "0.0.0.0"
#     port:        int
#     packet_rate: float
#     packet_size: float = 512.0


# @app.post("/predict", tags=["analysis"])
# async def predict_single(entry: LogEntry):
#     df     = pd.DataFrame([entry.dict()])
#     result = predict_batch(df)[0]
#     geo    = await _geolocate(entry.src_ip)
#     explanation = None
#     if result["threat_level"] in ("high", "critical"):
#         try:
#             explanation = explain_attack({**entry.dict(), **result})
#         except Exception as e:
#             explanation = f"AI explanation unavailable: {e}"
#     payload = {**result, "ai_explanation": explanation, "geo": geo}
#     if result["threat_level"] == "critical":
#         await _send_slack_alert({"log": entry.dict(), **payload})
#     return payload


# # ── Model Retraining ──────────────────────────────────────────────────────────

# @app.post("/train", tags=["ml"])
# async def train_model(file: UploadFile = File(...)):
#     if not file.filename.endswith(".csv"):
#         raise HTTPException(400, "Only CSV files are accepted for training.")
#     contents = await file.read()
#     try:
#         df = pd.read_csv(io.BytesIO(contents))
#     except Exception:
#         raise HTTPException(400, "Could not parse training CSV.")
#     try:
#         stats = retrain(df)
#     except ValueError as e:
#         raise HTTPException(422, str(e))
#     return stats



from dotenv import load_dotenv
load_dotenv()

import os
import io
import ipaddress
from collections import Counter

import httpx
import pandas as pd
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.model import predict_batch, retrain
from app.gemini_client import explain_attack
from app.live import router as live_router
from app.chat import chat_router
from app.news import news_router
from app.pcap_parser import (
    parse_pcap, pcap_df_to_model_input,
    enrich_result_with_pcap_meta, PCAPParseError,
)

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Network Health Sentinel", version="2.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(live_router)
app.include_router(chat_router)
app.include_router(news_router)

REQUIRED_CSV_COLS = {"src_ip", "port", "packet_rate", "packet_size"}

# ── Column auto-mapper ────────────────────────────────────────────────────────
# Upload UNSW-NB15, CIC-IDS-2017, KDD99, or any CSV — no renaming needed.

COLUMN_MAP = {
    # src_ip
    "srcip": "src_ip", "src_ip_addr": "src_ip", "source_ip": "src_ip",
    "ip_src": "src_ip", "sourceip": "src_ip", "src": "src_ip",
    "source": "src_ip", "sip": "src_ip",
    # port
    "sport": "port", "src_port": "port", "source_port": "port",
    "dport": "port", "dst_port": "port", "destination_port": "port",
    "l4_src_port": "port",
    # packet_rate
    "rate": "packet_rate", "pkt_rate": "packet_rate",
    "flow_pkts_s": "packet_rate", "flow_pkts/s": "packet_rate",
    "total_fwd_packets": "packet_rate", "pkts_per_sec": "packet_rate",
    "num_pkts_sent": "packet_rate", "pkts": "packet_rate",
    "tot_fwd_pkts": "packet_rate", "totfwdpkts": "packet_rate",
    # packet_size
    "smean": "packet_size", "sbytes": "packet_size", "dmean": "packet_size",
    "pktlen_mean": "packet_size", "avg_pkt_size": "packet_size",
    "total_length_of_fwd_packets": "packet_size", "totlenfwdpkts": "packet_size",
    "byts_per_sec": "packet_size", "bytes": "packet_size",
    "flow_byts_s": "packet_size", "flow_byts/s": "packet_size",
    "fwd_pkt_len_mean": "packet_size",
}


def _automap_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """
    Renames dataset columns to our internal schema automatically.
    Falls back gracefully for any missing columns.
    Returns (remapped_df, notes) where notes describe what was mapped.
    """
    col_lookup = {c.lower().strip().replace(" ", "_"): c for c in df.columns}
    rename: dict[str, str] = {}
    mapped_targets: set[str] = set()

    for raw, target in COLUMN_MAP.items():
        if target in mapped_targets:
            continue
        key = raw.lower().replace(" ", "_")
        if key in col_lookup and col_lookup[key] not in rename:
            rename[col_lookup[key]] = target
            mapped_targets.add(target)

    df = df.rename(columns=rename)
    notes = [f"{src} → {dst}" for src, dst in rename.items()]

    # Fill still-missing columns
    if "src_ip" not in df.columns:
        ip_cols = [c for c in df.columns if "ip" in c.lower()]
        df["src_ip"] = df[ip_cols[0]].astype(str) if ip_cols else "0.0.0.0"
        notes.append(f"src_ip {'← ' + ip_cols[0] if ip_cols else 'defaulted to 0.0.0.0'}")

    if "port" not in df.columns:
        port_cols = [c for c in df.columns if "port" in c.lower()]
        df["port"] = pd.to_numeric(df[port_cols[0]], errors="coerce").fillna(0) if port_cols else 0
        notes.append(f"port {'← ' + port_cols[0] if port_cols else 'defaulted to 0'}")

    if "packet_rate" not in df.columns:
        dur  = next((c for c in df.columns if "dur" in c.lower()), None)
        byts = next((c for c in df.columns if "byt" in c.lower() or "byte" in c.lower()), None)
        if dur and byts:
            d = pd.to_numeric(df[dur], errors="coerce").replace(0, 1).fillna(1)
            b = pd.to_numeric(df[byts], errors="coerce").fillna(0)
            df["packet_rate"] = (b / d).clip(0, 5000)
            notes.append(f"packet_rate derived from {byts}/{dur}")
        else:
            df["packet_rate"] = 100.0
            notes.append("packet_rate defaulted to 100")

    if "packet_size" not in df.columns:
        df["packet_size"] = 512.0
        notes.append("packet_size defaulted to 512")

    # Sanitise
    df["port"]        = pd.to_numeric(df["port"],        errors="coerce").fillna(0).clip(0, 65535).astype(int)
    df["packet_rate"] = pd.to_numeric(df["packet_rate"], errors="coerce").fillna(0).clip(0, 10000)
    df["packet_size"] = pd.to_numeric(df["packet_size"], errors="coerce").fillna(0).clip(0, 65535)

    return df, notes


# ── IP Geolocation ────────────────────────────────────────────────────────────

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

def _is_private(ip_str: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip_str) in net for net in _RFC1918)
    except ValueError:
        return True


async def _geolocate(ip: str) -> dict | None:
    if _is_private(ip):
        return None
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
            )
        data = r.json()
        if data.get("status") == "success":
            return {
                "country":      data.get("country"),
                "country_code": data.get("countryCode"),
                "city":         data.get("city"),
                "isp":          data.get("isp"),
            }
    except Exception:
        pass
    return None


# ── Slack Alerts ──────────────────────────────────────────────────────────────

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


async def _send_slack_alert(result: dict) -> None:
    if not SLACK_WEBHOOK_URL:
        return
    ip          = result.get("log", {}).get("src_ip", "unknown")
    attack_type = result.get("prediction", "Unknown")
    score       = result.get("anomaly_score", 0)
    explanation = result.get("ai_explanation") or ""
    truncated   = explanation[:300] + "…" if len(explanation) > 300 else explanation
    geo         = result.get("geo") or {}
    location    = f"{geo.get('city','')}, {geo.get('country','')}".strip(", ") or "Unknown"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(SLACK_WEBHOOK_URL, json={
                "text": (
                    f":rotating_light: *CRITICAL THREAT* :rotating_light:\n"
                    f">*IP:* `{ip}` ({location})\n"
                    f">*Type:* {attack_type}  |  *Score:* `{score}`\n"
                    f">*Summary:* {truncated or '_unavailable_'}"
                )
            })
    except Exception:
        pass


# ── Shared result builder ─────────────────────────────────────────────────────

async def _build_results(
    df: pd.DataFrame,
    predictions: list[dict],
    pcap_df: pd.DataFrame | None = None,
) -> list[dict]:
    results = []
    for i, (_, row) in enumerate(df.iterrows()):
        pred = predictions[i]
        log  = row.to_dict()
        if pcap_df is not None:
            pred = enrich_result_with_pcap_meta(pred, pcap_df.iloc[i])
        geo = await _geolocate(str(log.get("src_ip", "")))
        explanation = None
        if pred["threat_level"] in ("high", "critical"):
            try:
                explanation = explain_attack({**log, **pred})
            except Exception as e:
                explanation = f"AI explanation unavailable: {e}"
        entry = {
            "log":            log,
            "prediction":     pred["prediction"],
            "threat_level":   pred["threat_level"],
            "anomaly_score":  pred["anomaly_score"],
            "confidence":     pred.get("threat_confidence", 0),
            "ai_explanation": explanation,
            "geo":            geo,
            "packet_count":   pred.get("packet_count"),
            "unique_ports":   pred.get("unique_ports"),
            "duration_sec":   pred.get("duration_sec"),
            "data_source":    pred.get("data_source", "csv"),
        }
        if pred["threat_level"] == "critical":
            await _send_slack_alert(entry)
        results.append(entry)
    return results


def _build_summary(results: list[dict]) -> dict:
    threat_counts = Counter(r["threat_level"] for r in results)
    attack_types  = Counter(r["prediction"] for r in results if r["prediction"] != "Normal")
    total = len(results)
    return {
        "total_logs":       total,
        "normal":           threat_counts.get("low",      0),
        "suspicious":       threat_counts.get("medium",   0),
        "high_threats":     threat_counts.get("high",     0),
        "critical_threats": threat_counts.get("critical", 0),
        "top_attack_types": dict(attack_types.most_common(5)),
        "threat_rate":      round((total - threat_counts.get("low", 0)) / max(total, 1) * 100, 1),
    }


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
def home():
    return {"status": "Network Sentinel Running", "version": "2.2"}

@app.get("/health")
def health():
    return {"status": "ok", "model": "IsolationForest v2", "features": 7}


# ── CSV Analysis — accepts any common network dataset ─────────────────────────

@app.post("/analyze", tags=["analysis"])
async def analyze_csv(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Only CSV files are accepted.")
    contents = await file.read()

    # Try multiple encodings — UNSW-NB15 uses latin-1
    df = None
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
            break
        except (UnicodeDecodeError, Exception):
            continue
    if df is None:
        raise HTTPException(400, "Could not parse CSV. Try saving as UTF-8.")

    # Auto-map columns — works with UNSW-NB15, CIC-IDS, custom CSVs
    try:
        df, mapping_notes = _automap_columns(df)
    except ValueError as e:
        raise HTTPException(422, str(e))

    # Sample to 2000 rows for performance — enough for a clear demo
    if len(df) > 2000:
        df = df.sample(2000, random_state=42).reset_index(drop=True)

    predictions = predict_batch(df)
    results     = await _build_results(df, predictions)
    summary     = _build_summary(results)
    summary["column_mapping"] = mapping_notes
    return {"summary": summary, "results": results}


# ── PCAP Analysis ─────────────────────────────────────────────────────────────

@app.post("/analyze-pcap", tags=["analysis"])
async def analyze_pcap(file: UploadFile = File(...)):
    fname = (file.filename or "").lower()
    if not (fname.endswith(".pcap") or fname.endswith(".pcapng")):
        raise HTTPException(400, "Only .pcap / .pcapng files accepted.")
    contents = await file.read()
    try:
        pcap_df = parse_pcap(contents)
    except PCAPParseError as e:
        raise HTTPException(422, str(e))
    model_df    = pcap_df_to_model_input(pcap_df)
    predictions = predict_batch(model_df)
    results     = await _build_results(model_df, predictions, pcap_df=pcap_df)
    summary = _build_summary(results)
    summary["data_source"]    = "pcap"
    summary["total_packets"]  = int(pcap_df["_packet_count"].sum()) if "_packet_count" in pcap_df.columns else None
    summary["unique_hosts"]   = len(pcap_df)
    summary["capture_window"] = float(pcap_df["_duration_sec"].max()) if "_duration_sec" in pcap_df.columns else None
    return {"summary": summary, "results": results}


# ── Single predict ────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    src_ip:      str   = "0.0.0.0"
    port:        int
    packet_rate: float
    packet_size: float = 512.0


@app.post("/predict", tags=["analysis"])
async def predict_single(entry: LogEntry):
    df     = pd.DataFrame([entry.dict()])
    result = predict_batch(df)[0]
    geo    = await _geolocate(entry.src_ip)
    explanation = None
    if result["threat_level"] in ("high", "critical"):
        try:
            explanation = explain_attack({**entry.dict(), **result})
        except Exception as e:
            explanation = f"AI explanation unavailable: {e}"
    payload = {**result, "ai_explanation": explanation, "geo": geo}
    if result["threat_level"] == "critical":
        await _send_slack_alert({"log": entry.dict(), **payload})
    return payload


# ── Model Retraining ──────────────────────────────────────────────────────────

@app.post("/train", tags=["ml"])
async def train_model(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Only CSV files are accepted for training.")
    contents = await file.read()
    df = None
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            df = pd.read_csv(io.BytesIO(contents), encoding=enc, low_memory=False)
            break
        except Exception:
            continue
    if df is None:
        raise HTTPException(400, "Could not parse training CSV.")
    try:
        df, _ = _automap_columns(df)
        stats  = retrain(df)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return stats