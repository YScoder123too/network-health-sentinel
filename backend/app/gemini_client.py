"""
gemini_client.py  —  SOC report generation
─────────────────────────────────────────────
Primary  : Google Gemini 1.5 Flash  (generous free tier, no daily TPD cap)
Fallback : Groq  Llama-3.3-70B      (used only if Gemini fails / key missing)

Public interface (unchanged):
  explain_attack(log: dict) -> str
  generate_threat_summary(results: list[dict]) -> str
"""

import os
import httpx

# ── API config ────────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent"

GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
GROQ_URL       = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"


# ── Provider calls ────────────────────────────────────────────────────────────

def _gemini(prompt: str, max_tokens: int = 600) -> str:
    """Call Gemini 1.5 Flash. Returns text or an ERR: string."""
    if not GEMINI_API_KEY:
        return "ERR: GEMINI_API_KEY not set"
    try:
        r = httpx.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature":     0.2,
                    "maxOutputTokens": max_tokens,
                },
            },
            timeout=25.0,
        )
        data = r.json()
        if r.status_code != 200:
            msg = data.get("error", {}).get("message", "Unknown Gemini error")
            return f"ERR: {msg}"
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except Exception as e:
        return f"ERR: {str(e)}"


def _groq(prompt: str, max_tokens: int = 600) -> str:
    """Call Groq Llama 3.3 70B. Returns text or an ERR: string."""
    if not GROQ_API_KEY:
        return "ERR: GROQ_API_KEY not set"
    try:
        r = httpx.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "model":       GROQ_MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  max_tokens,
                "temperature": 0.2,
            },
            timeout=20.0,
        )
        data = r.json()
        if r.status_code != 200:
            return f"ERR: {data.get('error', {}).get('message', 'Unknown Groq error')}"
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"ERR: {str(e)}"


def _call_ai(prompt: str, max_tokens: int = 600) -> str:
    """
    Try Gemini first. If it returns an ERR (quota / unavailable),
    automatically fall back to Groq. Prefixes the response with
    the provider name so the UI/PDF can show which engine was used.
    """
    result = _gemini(prompt, max_tokens)
    if not result.startswith("ERR:"):
        return result  # Gemini succeeded

    # Gemini failed — try Groq
    groq_result = _groq(prompt, max_tokens)
    if not groq_result.startswith("ERR:"):
        return groq_result  # Groq succeeded

    # Both failed — return the most descriptive error
    return f"[Gemini] {result}\n[Groq] {groq_result}"


# ── Attack-specific prompt builder ────────────────────────────────────────────

def _build_prompt(log: dict) -> str:
    attack_type = log.get("prediction",    "Unknown")
    src_ip      = log.get("src_ip",        "unknown")
    port        = log.get("port",          "unknown")
    rate        = log.get("packet_rate",   "unknown")
    size        = log.get("packet_size",   "unknown")
    score       = log.get("anomaly_score", "unknown")
    confidence  = log.get("threat_confidence", log.get("confidence", "unknown"))

    context = f"""THREAT INTELLIGENCE REPORT
═══════════════════════════════════════════════
Lead Engineer : Yogita Singh (CEH Certified)
Portfolio     : https://yogitasingh.me/
Report For    : Tanishq Pal
═══════════════════════════════════════════════
Source IP     : {src_ip}
Port          : {port}
Packet Rate   : {rate} packets/sec
Packet Size   : {size} bytes
Attack Type   : {attack_type}
Anomaly Score : {score}  (more negative = more anomalous)
ML Confidence : {confidence}
═══════════════════════════════════════════════

"""

    if attack_type == "DoS Attack":
        return context + f"""You are a Tier-2 SOC analyst. This is a confirmed volumetric Denial-of-Service event.
Respond in EXACTLY this format, no extra text:

ATTACK_SUMMARY
One sentence: what is happening and why the packet rate of {rate} pps indicates DoS.

TECHNICAL_INDICATORS
- Why this packet rate is anomalous vs normal baseline (50-400 pps)
- What the small packet size ({size}B) suggests (SYN flood? UDP amplification?)
- Which service on port {port} is being targeted

BLAST_RADIUS
What systems or users are affected if this attack succeeds.

IMMEDIATE_ACTIONS
1. Block source IP {src_ip} at perimeter firewall immediately
2. (Second specific action)
3. (Third specific action)

MITRE_ATT&CK
T1498 - Network Denial of Service"""

    elif attack_type == "Port Scan":
        return context + f"""You are a Tier-1 SOC analyst. This is a reconnaissance port scan — the first phase of a larger attack.
Respond in EXACTLY this format, no extra text:

ATTACK_SUMMARY
One sentence: what the attacker from {src_ip} is doing and what services they are mapping.

TECHNICAL_INDICATORS
- Why low port {port} + small packet size {size}B + rate {rate} pps confirms a scan
- Type of scan likely being used (SYN scan? Nmap service detection?)
- What intelligence the attacker is gathering

RISK_ASSESSMENT
What attack could follow if the attacker finds an open service.

IMMEDIATE_ACTIONS
1. Block {src_ip} at firewall and add to threat watchlist
2. (Second specific action)
3. (Third specific action)

MITRE_ATT&CK
T1046 - Network Service Discovery"""

    elif attack_type == "Brute-Force Attempt":
        return context + f"""You are a Tier-2 SOC analyst. This is a credential brute-force attack on an authentication service.
Respond in EXACTLY this format, no extra text:

ATTACK_SUMMARY
One sentence: what service on port {port} is being attacked and the likely goal.

TECHNICAL_INDICATORS
- Why port {port} is a high-value authentication target (name the service: SSH/RDP/SMB/etc)
- What sustained rate of {rate} pps suggests about the attack tool (Hydra? Medusa? botnet?)
- Whether this looks automated or manual based on the packet pattern

CREDENTIAL_RISK
What an attacker achieves if they succeed on port {port}.

IMMEDIATE_ACTIONS
1. Enforce account lockout after 5 failed attempts on port {port}
2. Block {src_ip} and check sibling IPs in same /24 subnet
3. (Third specific action)

MITRE_ATT&CK
T1110 - Brute Force"""

    elif attack_type == "Data Exfiltration":
        return context + f"""You are a Tier-3 SOC analyst. This is suspected data exfiltration — the final stage of a breach.
Respond in EXACTLY this format, no extra text:

ATTACK_SUMMARY
One sentence: what data movement pattern from {src_ip} is observed and why it is suspicious.

TECHNICAL_INDICATORS
- Why port {port} is abnormal for legitimate outbound traffic
- What large packet size {size}B suggests about data volume being moved
- Whether this resembles staged exfiltration or a live C2 stream

SEVERITY_ASSESSMENT
What category of data is likely being stolen and the regulatory/business impact.

IMMEDIATE_ACTIONS
1. Isolate host {src_ip} immediately — do not shut down (preserve forensics)
2. Capture full packet trace on this flow
3. Identify and revoke any credentials that may have been compromised

MITRE_ATT&CK
T1041 - Exfiltration Over C2 Channel"""

    else:
        return context + f"""You are a SOC analyst reviewing an ML-flagged network anomaly.
Respond in EXACTLY this format, no extra text:

ATTACK_SUMMARY
One sentence: what anomaly was detected from {src_ip} and why it warrants investigation.

TECHNICAL_INDICATORS
- What specific values triggered anomaly score of {score}
- Which features deviate most from normal baseline
- Benign vs malicious explanation for this pattern

RECOMMENDED_INVESTIGATION
What logs or systems to check next to confirm or rule out a threat.

IMMEDIATE_ACTIONS
1. Query SIEM for all connections from {src_ip} in last 24h
2. (Second specific action)
3. (Third specific action)

MITRE_ATT&CK
Most likely technique ID and name if malicious"""


# ── Public interface ──────────────────────────────────────────────────────────

def explain_attack(log: dict) -> str:
    """
    Takes a log dict (with prediction/threat_level merged in).
    Returns a structured SOC analyst report.
    Uses Gemini 1.5 Flash first; falls back to Groq if Gemini is unavailable.
    """
    return _call_ai(_build_prompt(log), max_tokens=600)


def generate_threat_summary(results: list[dict]) -> str:
    """Executive threat summary — called after full CSV analysis completes."""
    attack_counts: dict[str, int] = {}
    for r in results:
        if r.get("prediction") != "Normal":
            k = r["prediction"]
            attack_counts[k] = attack_counts.get(k, 0) + 1

    total      = len(results)
    threats    = total - sum(1 for r in results if r.get("threat_level") == "low")
    threat_pct = round(threats / max(total, 1) * 100, 1)

    prompt = f"""You are a CISO briefing an executive team. Write a 3-sentence max summary.
Be direct, use numbers, end with one recommended action.

Scan stats:
- Total connections analyzed : {total}
- Threat rate               : {threat_pct}%
- Attack breakdown          : {attack_counts}
"""
    return _call_ai(prompt, max_tokens=200)