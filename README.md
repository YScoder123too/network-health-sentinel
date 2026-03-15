# 🛡️ Network Health Sentinel

> Real-time AI-powered network intrusion detection system combining unsupervised machine learning with LLM-generated SOC analyst reports.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=flat-square)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-orange?style=flat-square)
![Gemini](https://img.shields.io/badge/Gemini-1.5--flash-purple?style=flat-square)
![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square)

---

## What It Does

Network Health Sentinel ingests raw network traffic logs and automatically:

1. **Detects anomalies** using an Isolation Forest model trained on 7 engineered features
2. **Classifies threats** into DoS, Port Scan, Brute-Force, Data Exfiltration, or Suspicious Activity
3. **Streams results** in real time via Server-Sent Events — logs appear as they're processed
4. **Generates SOC reports** using Gemini 1.5 Flash, structured as Tier-2 analyst threat assessments
5. **Simulates live traffic** so you can demo without real network access

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Frontend (Next.js)                  │
│   Terminal UI  ·  SSE stream client  ·  Threat timeline │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP / SSE
┌───────────────────────▼─────────────────────────────────┐
│                   Backend (FastAPI)                     │
│                                                         │
│   /analyze          →  Batch CSV analysis               │
│   /live/stream      →  Simulated real-time SSE feed     │
│   /live/analyze-stream → Streaming CSV analysis (SSE)   │
│   /predict          →  Single-row prediction            │
└──────────┬──────────────────────┬───────────────────────┘
           │                      │
┌──────────▼──────────┐  ┌───────▼──────────────────────┐
│   IsolationForest   │  │      Gemini 1.5 Flash         │
│   (scikit-learn)    │  │   Structured SOC Reports      │
│   7 features        │  │   Executive Summaries         │
└─────────────────────┘  └──────────────────────────────┘
```

---

## ML Design Decisions

### Why Isolation Forest?
Real-world network traffic doesn't come with attack labels — you can't train a supervised classifier without expensive, manually-labelled datasets. Isolation Forest is an **unsupervised anomaly detection** algorithm that learns the shape of normal traffic and flags deviations. This mirrors how production IDS systems actually work.

### Feature Engineering (7 features)
Raw packet data alone is weak signal. The model uses:

| Feature | Rationale |
|---|---|
| `packet_rate` | Raw throughput |
| `packet_size` | Payload size |
| `port` | Raw port number |
| `port_risk` | Risk score: critical ports (SSH/RDP/SMB) = 2.0, known ports = 1.0, other = 0 |
| `rate_x_risk` | Interaction term: high rate on risky port is a strong combined signal |
| `size_anomaly` | Binary flag: packets < 60 bytes or > 1400 bytes are statistically unusual |
| `rate_size_ratio` | DoS attacks typically have high rate with tiny packets — this ratio captures it |

### Attack Classification
After Isolation Forest flags an anomaly, a heuristic layer maps it to a human-readable class:

| Attack Type | Key Signals |
|---|---|
| DoS Attack | packet_rate > 700 |
| Port Scan | port < 1024, packet_size < 120, packet_rate > 150 |
| Brute-Force | critical port (22/3389/445), sustained moderate rate |
| Data Exfiltration | large packets (>1200b), non-standard port |
| Suspicious Activity | anomaly score negative, doesn't match specific pattern |

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Backend API | FastAPI | Async-native, automatic OpenAPI docs, SSE support |
| ML Model | scikit-learn IsolationForest | Unsupervised, no labelled data needed |
| AI Layer | Google Gemini 1.5 Flash | Structured SOC report generation |
| Streaming | Server-Sent Events (SSE) | Lightweight, one-way, no WebSocket overhead |
| Frontend | Next.js 14 + TypeScript | Type safety, SSR capable |
| Containerisation | Docker Compose | One-command startup |

---

## Quick Start

### Option A — Docker (recommended)
```bash
git clone https://github.com/yourusername/network-health-sentinel
cd network-health-sentinel

# Add your Gemini API key
echo "GEMINI_API_KEY=your_key_here" > backend/.env

# Start everything
docker compose up
```
Open http://localhost:3000

### Option B — Local dev
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### Generate test data
```bash
cd backend
python mock_log_generator.py --rows 200
# Creates network_logs.csv with realistic attack traffic
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/analyze` | POST | Upload CSV, returns full analysis JSON |
| `/live/stream` | GET | SSE stream of simulated live network logs |
| `/live/analyze-stream` | POST | Upload CSV, results stream back as SSE events |
| `/predict` | POST | Single log entry prediction |
| `/health` | GET | Model status |

---

## Project Structure

```
network-health-sentinel/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + routes
│   │   ├── model.py             # IsolationForest + feature engineering
│   │   ├── gemini_client.py     # Structured SOC prompts
│   │   └── live.py              # SSE streaming router
│   ├── mock_log_generator.py    # Realistic attack traffic generator
│   ├── network_logs.csv         # Sample data
│   └── requirements.txt
├── frontend/
│   └── app/
│       └── page.tsx             # Terminal SOC dashboard
├── docker-compose.yml
└── README.md
```

---

## Skills Demonstrated

- **Machine Learning**: Unsupervised anomaly detection, feature engineering, model persistence with joblib
- **Cybersecurity**: IDS/IPS concepts, attack classification (DoS, Port Scan, Brute-Force, Exfiltration), SOC workflows
- **LLM Integration**: Structured prompt engineering, Gemini API, executive summary generation
- **Backend Engineering**: FastAPI, async Python, Server-Sent Events, RESTful API design
- **Frontend**: Next.js, TypeScript, real-time SSE client, terminal UI
- **DevOps**: Docker, Docker Compose, environment management

---

## Roadmap

- [ ] WebSocket support for true bidirectional live monitoring
- [ ] PCAP file ingestion (real packet capture analysis)
- [ ] IP geolocation overlay on threat map
- [ ] Alert webhook integration (Slack/PagerDuty)
- [ ] Model retraining endpoint with uploaded baseline data