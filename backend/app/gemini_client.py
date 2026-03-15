# # import google.generativeai as genai
# # import os

# # genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# # model = genai.GenerativeModel("gemini-1.5-flash")

# # # ── Attack-specific prompt templates ─────────────────────────────────────────
# # # Each returns a tailored prompt so Gemini responds like a specialist,
# # # not a generic chatbot. This is what makes the AI layer actually useful.

# # def _build_prompt(log: dict) -> str:
# #     attack_type = log.get("prediction", "Unknown")
# #     src_ip      = log.get("src_ip", "unknown")
# #     port        = log.get("port", "unknown")
# #     rate        = log.get("packet_rate", "unknown")
# #     size        = log.get("packet_size", "unknown")
# #     score       = log.get("anomaly_score", "unknown")
# #     confidence  = log.get("confidence", "unknown")

# #     # Shared context block
# #     context = f"""
# # THREAT INTELLIGENCE REPORT
# # ═══════════════════════════
# # Source IP     : {src_ip}
# # Port          : {port}
# # Packet Rate   : {rate} packets/sec
# # Packet Size   : {size} bytes
# # Attack Type   : {attack_type}
# # Anomaly Score : {score}  (more negative = more anomalous)
# # ML Confidence : {confidence}
# # """

# #     # Attack-specific analyst instructions
# #     if attack_type == "DoS Attack":
# #         directive = """
# # You are a Tier-2 SOC analyst. This is a confirmed volumetric Denial-of-Service event.

# # Respond in this EXACT format with no extra text:

# # ATTACK_SUMMARY
# # One sentence: what is happening and why the packet rate indicates DoS.

# # TECHNICAL_INDICATORS
# # - Why this packet rate ({rate} pps) is anomalous
# # - What the small packet size suggests (amplification? UDP flood? SYN flood?)
# # - Which service on port {port} is being targeted

# # BLAST_RADIUS
# # What systems or users are affected if this attack succeeds.

# # IMMEDIATE_ACTIONS
# # 1. (First thing to do — specific, actionable)
# # 2. (Second thing)
# # 3. (Third thing)

# # MITRE_ATT&CK
# # Technique ID and name (e.g., T1498 - Network Denial of Service)
# # """.format(rate=rate, port=port)

# #     elif attack_type == "Port Scan":
# #         directive = """
# # You are a Tier-1 SOC analyst. This is a reconnaissance port scan — likely the first phase of a larger attack.

# # Respond in this EXACT format with no extra text:

# # ATTACK_SUMMARY
# # One sentence: what the attacker is doing and what they are looking for.

# # TECHNICAL_INDICATORS
# # - Why this combination of low port ({port}) + low packet size ({size}B) + rate ({rate} pps) confirms a scan
# # - Type of scan likely being used (SYN scan? service version scan?)
# # - What intelligence the attacker is gathering

# # RISK_ASSESSMENT
# # What attack could follow if the attacker finds an open port here.

# # IMMEDIATE_ACTIONS
# # 1. (First thing to do — specific, actionable)
# # 2. (Second thing)
# # 3. (Third thing)

# # MITRE_ATT&CK
# # Technique ID and name (e.g., T1046 - Network Service Discovery)
# # """.format(port=port, size=size, rate=rate)

# #     elif attack_type == "Brute-Force Attempt":
# #         directive = """
# # You are a Tier-2 SOC analyst. This is a credential brute-force attack on a sensitive authentication port.

# # Respond in this EXACT format with no extra text:

# # ATTACK_SUMMARY
# # One sentence: what service is being attacked and the likely goal.

# # TECHNICAL_INDICATORS
# # - Why port {port} is a high-value target (name the service)
# # - What the sustained packet rate of {rate} pps suggests about the attack tool
# # - Whether this looks automated (botnet/tool) or manual

# # CREDENTIAL_RISK
# # What happens if the attacker succeeds — specific to the service on port {port}.

# # IMMEDIATE_ACTIONS
# # 1. (First thing to do — specific, actionable)
# # 2. (Second thing)
# # 3. (Third thing)

# # MITRE_ATT&CK
# # Technique ID and name (e.g., T1110 - Brute Force)
# # """.format(port=port, rate=rate)

# #     elif attack_type == "Data Exfiltration":
# #         directive = """
# # You are a Tier-3 SOC analyst. This is a suspected data exfiltration event — potentially the final stage of a breach.

# # Respond in this EXACT format with no extra text:

# # ATTACK_SUMMARY
# # One sentence: what data movement pattern is observed and why it's suspicious.

# # TECHNICAL_INDICATORS
# # - Why port {port} is unusual for legitimate traffic
# # - What the large packet size ({size}B) suggests about the data being moved
# # - Whether this looks like staged exfiltration or a live data stream

# # SEVERITY_ASSESSMENT
# # What category of data is likely being stolen and regulatory implications.

# # IMMEDIATE_ACTIONS
# # 1. (First thing to do — specific, actionable, e.g. isolate host)
# # 2. (Second thing)
# # 3. (Third thing)

# # MITRE_ATT&CK
# # Technique ID and name (e.g., T1041 - Exfiltration Over C2 Channel)
# # """.format(port=port, size=size)

# #     else:  # Suspicious Activity fallback
# #         directive = """
# # You are a SOC analyst reviewing an anomaly flagged by the ML detection engine.

# # Respond in this EXACT format with no extra text:

# # ATTACK_SUMMARY
# # One sentence: what anomaly was detected and why it warrants investigation.

# # TECHNICAL_INDICATORS
# # - What specific values triggered the anomaly score of {score}
# # - Which feature(s) deviate most from normal baseline traffic
# # - Possible benign explanation vs. malicious explanation

# # RECOMMENDED_INVESTIGATION
# # What logs or systems to check next to confirm or rule out a threat.

# # IMMEDIATE_ACTIONS
# # 1. (First thing to do)
# # 2. (Second thing)
# # 3. (Third thing)

# # MITRE_ATT&CK
# # Most likely technique if malicious (ID and name)
# # """.format(score=score)

# #     return context + directive


# # # ── Public interface ──────────────────────────────────────────────────────────

# # def explain_attack(log: dict) -> str:
# #     """
# #     Takes a log dict (with prediction/threat_level fields merged in)
# #     and returns a structured SOC analyst report from Gemini.
# #     """
# #     prompt = _build_prompt(log)

# #     try:
# #         response = model.generate_content(
# #             prompt,
# #             generation_config=genai.types.GenerationConfig(
# #                 temperature=0.2,      # low temp = consistent, factual output
# #                 max_output_tokens=600,
# #             )
# #         )
# #         return response.text.strip()
# #     except Exception as e:
# #         return f"GEMINI_UNAVAILABLE: {str(e)}"



# import google.generativeai as genai
# import os

# genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
# model = genai.GenerativeModel("gemini-2.0-flash")


# def explain_attack(log: dict) -> str:
#     """
#     Returns a structured SOC-style threat report for a suspicious log entry.
#     Prompt is engineered to produce consistent, interview-worthy output.
#     """

#     threat_level = log.get("threat_level", "unknown").upper()
#     attack_type  = log.get("prediction", "Unknown")
#     src_ip       = log.get("src_ip", "unknown")
#     port         = log.get("port", "unknown")
#     packet_rate  = log.get("packet_rate", "unknown")
#     packet_size  = log.get("packet_size", "unknown")
#     score        = log.get("anomaly_score", "unknown")
#     confidence   = log.get("confidence", "unknown")

#     prompt = f"""You are a Tier-2 SOC (Security Operations Center) analyst writing a threat report.
# A network anomaly detection system (IsolationForest ML model) flagged the following log.

# ─── FLAGGED LOG ───────────────────────────────────
#   Source IP     : {src_ip}
#   Port          : {port}
#   Packet Rate   : {packet_rate} pps
#   Packet Size   : {packet_size} bytes
#   ML Detection  : {attack_type}
#   Threat Level  : {threat_level}
#   Anomaly Score : {score}  (more negative = more anomalous)
#   Confidence    : {confidence}
# ───────────────────────────────────────────────────

# Write a concise threat report with EXACTLY these four sections.
# Keep each section to 2-3 sentences. Be specific and technical.

# ATTACK VECTOR
# Explain the likely attack technique and why the network metrics above are indicators.

# RISK ASSESSMENT  
# What systems or data are at risk. What could an attacker achieve if this is a true positive.

# IMMEDIATE ACTION
# Specific firewall/IDS rule or command a SOC analyst should run right now.

# FALSE POSITIVE CHECK
# One key thing to verify before escalating (e.g., check if the source IP is an internal scanner, load balancer, etc.).
# """

#     try:
#         response = model.generate_content(prompt)
#         return response.text.strip()
#     except Exception as e:
#         return f"Gemini unavailable: {str(e)}"


# def generate_threat_summary(results: list[dict]) -> str:
#     """
#     Takes full analysis results and asks Gemini for an executive threat summary.
#     Used by the /live/summary endpoint.
#     """
#     attack_counts = {}
#     for r in results:
#         if r.get("prediction") != "Normal":
#             k = r["prediction"]
#             attack_counts[k] = attack_counts.get(k, 0) + 1

#     total      = len(results)
#     threats    = total - sum(1 for r in results if r.get("threat_level") == "low")
#     threat_pct = round(threats / max(total, 1) * 100, 1)

#     prompt = f"""You are a CISO briefing an executive team. Summarize this network scan in 3 sentences max.
# Be direct, use numbers, and end with one recommended action.

# Scan stats:
# - Total logs analyzed : {total}
# - Threat rate         : {threat_pct}%
# - Attack breakdown    : {attack_counts}
# """

#     try:
#         response = model.generate_content(prompt)
#         return response.text.strip()
#     except Exception as e:
#         return f"Summary unavailable: {str(e)}"

"""
gemini_client.py  —  SOC report generation via Groq (Llama 3.3 70B)
─────────────────────────────────────────────────────────────────────
Dropped Gemini (quota issues on free tier).
Groq is free, fast (~300 tokens/sec), no credit card needed.
Same public interface: explain_attack() + generate_threat_summary()
Nothing else in the codebase needs to change.
"""

import os
import httpx

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"


def _groq(prompt: str, max_tokens: int = 600) -> str:
    """Single synchronous Groq call — returns text or error string."""
    if not GROQ_API_KEY:
        return "ERR: GROQ_API_KEY not set in .env — get a free key at console.groq.com"
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
                "max_tokens":  600,
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
═══════════════════════════════
Source IP     : {src_ip}
Port          : {port}
Packet Rate   : {rate} packets/sec
Packet Size   : {size} bytes
Attack Type   : {attack_type}
Anomaly Score : {score}  (more negative = more anomalous)
ML Confidence : {confidence}
═══════════════════════════════

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

    else:  # Suspicious Activity
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
    Returns a structured SOC analyst report via Groq/Llama 3.3 70B.
    Identical signature to old Gemini version — nothing else needs changing.
    """
    return _groq(_build_prompt(log), max_tokens=600)


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
    return _groq(prompt, max_tokens=200)