"""
app/chat.py  —  SENTINEL_AI chat endpoint
Uses Groq (free tier, no credit card) with Llama 3.3 70B.
1. Go to https://console.groq.com  →  sign up free  →  API Keys  →  Create key
2. Add to .env:  GROQ_API_KEY=gsk_...
"""

import os
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

chat_router = APIRouter(prefix="/chat", tags=["assistant"])

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

SYSTEM_PROMPT = """You are SENTINEL_AI, a focused cybersecurity and technology assistant \
embedded inside Network Health Sentinel — an AI-powered network intrusion detection system.

You ONLY answer questions about these topics. Decline everything else politely:
- Cybersecurity: threats, attack types (DoS, Port Scan, Brute-Force, Data Exfiltration), \
  incident response, SOC workflows, firewalls, IDS/IPS, SIEM, CVEs, malware, phishing, \
  penetration testing tools (Nmap, Wireshark, Metasploit, Burp Suite), network protocols
- This tool: IsolationForest anomaly scores (negative = anomalous), the 7 features \
  (packet_rate, packet_size, port, port_risk, rate_x_risk, size_anomaly, rate_size_ratio), \
  threat levels (low/medium/high/critical), Gemini SOC reports
- AI and Machine Learning: how models work, supervised vs unsupervised, neural networks, \
  LLMs, feature engineering, model evaluation — especially in security contexts
- Technology: programming, APIs, networking, Linux, cloud, databases — in engineering contexts

For anything unrelated (cooking, entertainment, relationships etc.) respond exactly:
"SENTINEL_AI is scoped to cybersecurity, AI/ML, and technology topics only."

Tone: concise, technical, professional. No markdown headers. Short paragraphs. Max 3 paragraphs."""


class ChatRequest(BaseModel):
    messages: list[dict]  # [{ "role": "user"|"assistant", "text": "..." }]


class ChatResponse(BaseModel):
    reply: str


@chat_router.post("", response_model=ChatResponse)
async def chat(req: ChatRequest):
    if not GROQ_API_KEY:
        return ChatResponse(reply="ERR: GROQ_API_KEY not set in .env — get a free key at console.groq.com")

    if not req.messages:
        return ChatResponse(reply="ERR: No messages provided.")

    messages = [
        {"role": "user" if m["role"] == "user" else "assistant", "content": m["text"]}
        for m in req.messages
    ]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            res = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type":  "application/json",
                },
                json={
                    "model":       "llama-3.3-70b-versatile",
                    "messages":    [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                    "max_tokens":  600,
                    "temperature": 0.4,
                },
            )
        data = res.json()
        if res.status_code != 200:
            err = data.get("error", {}).get("message", "Unknown error")
            return ChatResponse(reply=f"ERR: {err}")
        return ChatResponse(reply=data["choices"][0]["message"]["content"])

    except Exception as e:
        return ChatResponse(reply=f"ERR: {str(e)}")