"use client"

import { useState, useEffect, useRef } from "react"
import CursorGlow from "./components/CursorGlow"


// ── Types ─────────────────────────────────────────────────────────────────────

interface LogResult {
  log: Record<string, string | number>
  prediction: string
  threat_level: "low" | "medium" | "high" | "critical"
  anomaly_score: number
  confidence: number
  ai_explanation: string | null
  packet_count?: number
  unique_ports?: number
  duration_sec?: number
  data_source?: string
  geo?: { country?: string; country_code?: string; city?: string; isp?: string } | null
}

interface Summary {
  total_logs: number
  normal: number
  suspicious: number
  high_threats: number
  critical_threats: number
  top_attack_types: Record<string, number>
  threat_rate: number
  exec_summary?: string | null
  data_source?: string
  total_packets?: number
  unique_hosts?: number
  capture_window?: number
}

interface NewsItem { title: string; source: string; tag: string; time: string; color: string; url?: string }

interface ChatMsg { role: "user" | "assistant"; text: string }

// ── Constants ─────────────────────────────────────────────────────────────────

const THREAT_COLORS = {
  low: { color: "#00ff41", label: "NORMAL" },
  medium: { color: "#ffd700", label: "MEDIUM" },
  high: { color: "#ff6b35", label: "HIGH" },
  critical: { color: "#ff2d55", label: "CRITICAL" },
}

const TICKER_MSGS = [
  "[RUNNING] ISOLATION_FOREST_v2...",
  "[STABLE] GEMINI_AI: CONNECTED",
  "[ACTIVE] THREAT_ENGINE_LISTENING_8000",
  "[SCANNING] /usr/network/packets...",
  "[STABLE] LATENCY: 12ms",
  "[READY] FEATURE_EXTRACTOR: 7_DIMS",
  "[READY] PCAP_PARSER: SCAPY_v2.5",
  "[ACTIVE] ANOMALY_DETECTOR: ARMED",
]

const COMMANDS = [
  "/analyze <file.csv>", "/analyze <capture.pcap>",
  "/live --rate 1", "/live stop",
  "/filter --threat critical", "/filter --threat high",
  "/filter --threat medium", "/filter --threat low", "/filter --threat all",
  "/clear logs", "/news", "/assistant", "/status model",
]

// News is fetched live from GET /news — see NewsPanel component below

// ── Particle canvas ───────────────────────────────────────────────────────────

function ParticleCanvas() {
  const ref = useRef<HTMLCanvasElement>(null)
  useEffect(() => {
    const canvas = ref.current; if (!canvas) return
    const ctx = canvas.getContext("2d"); if (!ctx) return
    let W = canvas.width = window.innerWidth
    let H = canvas.height = window.innerHeight
    const pts = Array.from({ length: 55 }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.35, vy: (Math.random() - 0.5) * 0.35,
      r: Math.random() * 1.4 + 0.3, a: Math.random() * 0.4 + 0.1,
    }))
    let raf: number
    const draw = () => {
      ctx.clearRect(0, 0, W, H)
      for (const p of pts) {
        p.x = (p.x + p.vx + W) % W; p.y = (p.y + p.vy + H) % H
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(0,255,65,${p.a})`; ctx.fill()
      }
      for (let i = 0; i < pts.length; i++)
        for (let j = i + 1; j < pts.length; j++) {
          const d = Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y)
          if (d < 110) { ctx.beginPath(); ctx.strokeStyle = `rgba(0,255,65,${0.07 * (1 - d / 110)})`; ctx.lineWidth = 0.5; ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y); ctx.stroke() }
        }
      raf = requestAnimationFrame(draw)
    }
    draw()
    const onR = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight }
    window.addEventListener("resize", onR)
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", onR) }
  }, [])
  return <canvas ref={ref} style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, opacity: 0.5 }} />
}

// ── Threat Velocity Chart ─────────────────────────────────────────────────────
// Shows counts of each threat level from the most recent analysis results.
// X-axis = threat category, Y-axis = count. Meaningful as soon as data arrives.

function ThreatVelocityChart({ results, liveMode }: { results: LogResult[]; liveMode: boolean }) {
  if (results.length === 0) {
    return (
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", opacity: 0.25, fontSize: 10, gap: 8, letterSpacing: 1, textAlign: "center", padding: 16 }}>
        <div style={{ fontSize: 22, opacity: 0.4 }}>▭▭▭</div>
        <div>NO DATA</div>
        <div style={{ opacity: 0.6, lineHeight: 1.8 }}>Run an analysis or<br />start LIVE_MONITOR</div>
      </div>
    )
  }

  const counts = {
    normal: results.filter(r => r.threat_level === "low").length,
    medium: results.filter(r => r.threat_level === "medium").length,
    high: results.filter(r => r.threat_level === "high").length,
    critical: results.filter(r => r.threat_level === "critical").length,
  }

  const bars = [
    { label: "NORMAL", val: counts.normal, color: "#00ff41", short: "NRM" },
    { label: "MEDIUM", val: counts.medium, color: "#ffd700", short: "MED" },
    { label: "HIGH", val: counts.high, color: "#ff6b35", short: "HGH" },
    { label: "CRITICAL", val: counts.critical, color: "#ff2d55", short: "CRT" },
  ]
  const maxVal = Math.max(...bars.map(b => b.val), 1)

  return (
    <div style={{ flex: 1, padding: "8px 14px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
      {/* Y-axis label */}
      <div style={{ fontSize: 8, opacity: 0.25, letterSpacing: 1, marginBottom: 2 }}>COUNT BY THREAT LEVEL — {results.length} TOTAL LOGS</div>

      {/* Bars */}
      <div style={{ flex: 1, display: "flex", alignItems: "flex-end", gap: 8, position: "relative" }}>
        {/* Gridlines */}
        {[0, 25, 50, 75, 100].map(pct => (
          <div key={pct} style={{ position: "absolute", left: 0, right: 0, bottom: `${pct}%`, borderTop: "1px solid rgba(0,255,65,0.06)", pointerEvents: "none" }} />
        ))}

        {bars.map(b => {
          const heightPct = Math.max((b.val / maxVal) * 90, b.val > 0 ? 4 : 0)
          const pct = results.length > 0 ? Math.round((b.val / results.length) * 100) : 0
          return (
            <div key={b.label} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4, height: "100%", position: "relative" }}
              onMouseEnter={e => { const tip = e.currentTarget.querySelector(".bar-tip") as HTMLElement; if (tip) tip.style.opacity = "1" }}
              onMouseLeave={e => { const tip = e.currentTarget.querySelector(".bar-tip") as HTMLElement; if (tip) tip.style.opacity = "0" }}
            >
              {/* Tooltip */}
              <div className="bar-tip" style={{ position: "absolute", top: 0, left: "50%", transform: "translateX(-50%)", background: "rgba(0,0,0,0.95)", border: `1px solid ${b.color}66`, padding: "4px 8px", fontSize: 9, whiteSpace: "nowrap", zIndex: 20, opacity: 0, transition: "opacity 0.15s", pointerEvents: "none", lineHeight: 1.8 }}>
                <span style={{ color: b.color, fontWeight: 700 }}>{b.label}</span><br />
                <span style={{ opacity: 0.7 }}>{b.val} logs · {pct}%</span>
              </div>
              <div style={{ flex: 1, width: "100%", display: "flex", alignItems: "flex-end" }}>
                <div style={{ width: "100%", height: `${heightPct}%`, minHeight: b.val > 0 ? 4 : 0, background: `${b.color}22`, border: b.val > 0 ? `1px solid ${b.color}88` : "1px dashed rgba(255,255,255,0.06)", boxShadow: b.val > 0 ? `0 0 8px ${b.color}22` : "none", transition: "height 0.5s ease, background 0.15s", cursor: "default", position: "relative" }}>
                  {b.val > 0 && (
                    <div style={{ position: "absolute", top: -18, left: "50%", transform: "translateX(-50%)", fontSize: 10, color: b.color, fontWeight: 700, whiteSpace: "nowrap" }}>{b.val}</div>
                  )}
                </div>
              </div>
              <div style={{ fontSize: 8, color: b.color, opacity: 0.7, letterSpacing: 0.5 }}>{b.short}</div>
            </div>
          )
        })}
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 4 }}>
        {bars.map(b => (
          <div key={b.label} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 8, opacity: 0.5 }}>
            <div style={{ width: 6, height: 6, background: b.color, flexShrink: 0 }} />
            <span>{b.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Network Map ───────────────────────────────────────────────────────────────
// Plots actual source IPs as nodes on a pseudo-canvas.
// Node size = threat severity. Color = threat level. Tooltip on hover.

function NetworkMap({ results }: { results: LogResult[] }) {
  const [hovered, setHovered] = useState<string | null>(null)

  if (results.length === 0) {
    return (
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", opacity: 0.25, fontSize: 10, gap: 8, letterSpacing: 1, textAlign: "center", padding: 16 }}>
        <svg width="40" height="40" viewBox="0 0 40 40" style={{ opacity: 0.4 }}>
          <circle cx="20" cy="20" r="3" fill="#00ff41" />
          <circle cx="8" cy="10" r="2" fill="#00ff41" opacity="0.5" />
          <circle cx="32" cy="12" r="2" fill="#00ff41" opacity="0.5" />
          <circle cx="10" cy="30" r="2" fill="#00ff41" opacity="0.5" />
          <line x1="20" y1="20" x2="8" y2="10" stroke="#00ff41" strokeWidth="0.5" opacity="0.3" />
          <line x1="20" y1="20" x2="32" y2="12" stroke="#00ff41" strokeWidth="0.5" opacity="0.3" />
          <line x1="20" y1="20" x2="10" y2="30" stroke="#00ff41" strokeWidth="0.5" opacity="0.3" />
        </svg>
        <div>AWAITING TRAFFIC DATA</div>
        <div style={{ opacity: 0.6, lineHeight: 1.8 }}>Source IPs will appear<br />as threat nodes</div>
      </div>
    )
  }

  // Deduplicate IPs, keep worst threat level per IP
  const ipMap: Record<string, { ip: string; level: LogResult["threat_level"]; count: number; prediction: string; geo?: LogResult["geo"]; port?: string | number; rate?: string | number }> = {}
  for (const r of results) {
    const ip = String(r.log.src_ip || "unknown")
    const existing = ipMap[ip]
    const severity = { low: 0, medium: 1, high: 2, critical: 3 }
    if (!existing || severity[r.threat_level] > severity[existing.level]) {
      ipMap[ip] = { ip, level: r.threat_level, count: (existing?.count ?? 0) + 1, prediction: r.prediction, geo: r.geo, port: r.log.port, rate: r.log.packet_rate }
    } else {
      ipMap[ip].count++
    }
  }

  const nodes = Object.values(ipMap).slice(0, 12) // max 12 nodes for clarity

  // Deterministic position from IP hash
  function ipToPos(ip: string, i: number): [number, number] {
    const hash = ip.split("").reduce((a, c) => a + c.charCodeAt(0), i * 31)
    const angle = (hash % 360) * (Math.PI / 180)
    const radius = 28 + (hash % 22)
    return [50 + radius * Math.cos(angle), 50 + radius * Math.sin(angle)]
  }

  const sizeMap = { low: 5, medium: 7, high: 9, critical: 11 }

  return (
    <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
      {/* Legend */}
      <div style={{ position: "absolute", top: 8, left: 10, zIndex: 2, display: "flex", flexDirection: "column", gap: 3 }}>
        {(["low", "medium", "high", "critical"] as const).map(lvl => (
          <div key={lvl} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 8, opacity: 0.5 }}>
            <div style={{ width: sizeMap[lvl], height: sizeMap[lvl], borderRadius: "50%", background: THREAT_COLORS[lvl].color, flexShrink: 0 }} />
            <span style={{ color: THREAT_COLORS[lvl].color }}>{THREAT_COLORS[lvl].label}</span>
          </div>
        ))}
        <div style={{ fontSize: 7, opacity: 0.3, marginTop: 2, letterSpacing: 0.5 }}>NODE SIZE = SEVERITY</div>
      </div>

      {/* SVG network */}
      <svg width="100%" height="100%" style={{ position: "absolute", inset: 0 }}>
        {/* Edges from center to each node */}
        {nodes.map((n, i) => {
          const [x, y] = ipToPos(n.ip, i)
          return <line key={`e-${i}`} x1="50%" y1="50%" x2={`${x}%`} y2={`${y}%`} stroke={THREAT_COLORS[n.level].color} strokeWidth="0.4" opacity="0.2" />
        })}

        {/* Center hub */}
        <circle cx="50%" cy="50%" r="6" fill="#0047ab" opacity="0.8" />
        <circle cx="50%" cy="50%" r="10" fill="none" stroke="#0047ab" strokeWidth="0.5" opacity="0.3" />

        {/* IP nodes */}
        {nodes.map((n, i) => {
          const [x, y] = ipToPos(n.ip, i)
          const r = sizeMap[n.level]
          const col = THREAT_COLORS[n.level].color
          const isHov = hovered === n.ip
          return (
            <g key={n.ip} style={{ cursor: "pointer" }}
              onMouseEnter={() => setHovered(n.ip)}
              onMouseLeave={() => setHovered(null)}
            >
              {n.level === "critical" && <circle cx={`${x}%`} cy={`${y}%`} r={r + 4} fill="none" stroke={col} strokeWidth="0.5" opacity="0.3" style={{ animation: "nodePulse 1.5s infinite" }} />}
              <circle cx={`${x}%`} cy={`${y}%`} r={isHov ? r + 2 : r} fill={col} opacity={isHov ? 1 : 0.75} style={{ transition: "r 0.15s" }} />
            </g>
          )
        })}
      </svg>

      {/* Hover tooltip — shown at bottom for all nodes */}
      {hovered && (() => {
        const n = ipMap[hovered]; if (!n) return null
        const col = THREAT_COLORS[n.level].color
        return (
          <div style={{ position: "absolute", bottom: 8, left: 8, right: 8, background: "rgba(0,0,0,0.96)", border: `1px solid ${col}66`, padding: "8px 12px", fontSize: 9, lineHeight: 2, zIndex: 10, animation: "fadeIn 0.15s ease" }}>
            <div style={{ color: col, fontWeight: 700, fontSize: 10, marginBottom: 2 }}>{n.ip}</div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", opacity: 0.75 }}>
              <span>TYPE: <span style={{ color: col }}>{n.prediction}</span></span>
              <span>LEVEL: <span style={{ color: col }}>{THREAT_COLORS[n.level].label}</span></span>
              <span>HITS: {n.count}</span>
              {n.port && <span>PORT: {n.port}</span>}
              {n.rate && <span>RATE: {n.rate} pps</span>}
              {n.geo?.country && <span>GEO: {n.geo.city ? n.geo.city + ", " : ""}{n.geo.country}</span>}
            </div>
          </div>
        )
      })()}

      {/* Node count */}
      <div style={{ position: "absolute", bottom: 8, right: 8, fontSize: 8, opacity: 0.2, lineHeight: 1.8, textAlign: "right" }}>
        {nodes.length} HOSTS MAPPED<br />
        HUB = THIS_SENTINEL
      </div>
    </div>
  )
}

// ── AI Assistant ──────────────────────────────────────────────────────────────
// Calls /chat on the FastAPI backend — API key stays server-side

function AIAssistant({ onClose }: { onClose: () => void }) {
  const [msgs, setMsgs] = useState<ChatMsg[]>([
    { role: "assistant", text: "SENTINEL_AI online. Ask me anything about network security, threat analysis, anomaly scores, or this tool." }
  ])
  const [input, setInput] = useState("")
  const [thinking, setThinking] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }) }, [msgs.length])

  async function send() {
    const q = input.trim()
    if (!q || thinking) return
    setInput("")
    const updated: ChatMsg[] = [...msgs, { role: "user", text: q }]
    setMsgs(updated)
    setThinking(true)
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: updated.map(m => ({ role: m.role, text: m.text })) }),
      })
      const data = await res.json()
      setMsgs(prev => [...prev, { role: "assistant", text: data.reply ?? "No response." }])
    } catch {
      setMsgs(prev => [...prev, { role: "assistant", text: "ERR: Cannot reach backend at localhost:8000. Is FastAPI running?" }])
    } finally {
      setThinking(false)
    }
  }

  return (
    <div style={{ position: "fixed", bottom: 80, right: 24, width: 380, height: 520, background: "#000", border: "1px solid rgba(0,255,65,0.4)", display: "flex", flexDirection: "column", zIndex: 1000, boxShadow: "0 0 40px rgba(0,255,65,0.1)", animation: "slideUp 0.2s ease" }}>
      <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(0,255,65,0.2)", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(0,255,65,0.04)" }}>
        <div>
          <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: 2 }}>⬡ SENTINEL_AI</span>
          <span style={{ fontSize: 9, opacity: 0.4, marginLeft: 10, letterSpacing: 1 }}>GEMINI · ONLINE</span>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "none", color: "#ff2d55", cursor: "pointer", fontSize: 14, fontFamily: "inherit" }}>✕</button>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "14px 14px 8px" }}>
        {msgs.map((m, i) => (
          <div key={i} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 9, letterSpacing: 2, opacity: 0.35, marginBottom: 4 }}>{m.role === "user" ? "▶ OPERATOR" : "⬡ SENTINEL_AI"}</div>
            <div style={{ fontSize: 11, lineHeight: 1.8, color: m.role === "user" ? "#00ff41" : "rgba(255,255,255,0.75)", background: m.role === "user" ? "rgba(0,255,65,0.04)" : "transparent", padding: m.role === "user" ? "6px 10px" : "0", border: m.role === "user" ? "1px solid rgba(0,255,65,0.12)" : "none" }}>
              {m.text}
            </div>
          </div>
        ))}
        {thinking && (
          <div style={{ fontSize: 11, opacity: 0.4, display: "flex", gap: 3 }}>
            {[0, 0.27, 0.54].map((d, i) => <span key={i} style={{ animation: `nodePulse 0.8s infinite ${d}s` }}>█</span>)}
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <div style={{ borderTop: "1px solid rgba(0,255,65,0.2)", display: "flex", alignItems: "center", padding: "8px 12px", gap: 8 }}>
        <span style={{ opacity: 0.4, fontSize: 13 }}>▶</span>
        <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && send()}
          placeholder="Ask about threats, IPs, attack types..."
          style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "#00ff41", fontSize: 11, fontFamily: "inherit", caretColor: "#00ff41" }} />
        <button onClick={send} disabled={thinking}
          style={{ background: "none", border: "1px solid rgba(0,255,65,0.3)", color: "#00ff41", padding: "3px 10px", cursor: "pointer", fontSize: 10, fontFamily: "inherit", letterSpacing: 1 }}>
          SEND
        </button>
      </div>
    </div>
  )
}

// ── News Panel ────────────────────────────────────────────────────────────────

function NewsPanel({ onClose }: { onClose: () => void }) {
  const [vis, setVis] = useState(false)
  const [articles, setArticles] = useState<NewsItem[]>([])
  const [loading, setLoading] = useState(true)
  const [isLive, setIsLive] = useState(false)

  useEffect(() => {
    setTimeout(() => setVis(true), 10)
    fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/news`)
      .then(r => r.json())
      .then(data => {
        setArticles(data.articles ?? [])
        setIsLive(data.source === "live")
      })
      .catch(() => {
        // Backend unreachable — show fallback inline
        setArticles([
          { title: "CISA warns of active exploitation of Cisco IOS XE vulnerability", source: "The Hacker News", tag: "CVE", color: "#ffd700", url: "https://thehackernews.com", time: "recent" },
          { title: "Ransomware group claims 2.5TB breach of US healthcare provider", source: "BleepingComputer", tag: "BREACH", color: "#ff2d55", url: "https://bleepingcomputer.com", time: "recent" },
          { title: "New LLM jailbreak technique bypasses safety filters in AI models", source: "Wired", tag: "AI/ML", color: "#00ff41", url: "https://wired.com", time: "recent" },
          { title: "NIST finalizes post-quantum cryptography standards", source: "NIST", tag: "CRYPTO", color: "#0047ab", url: "https://nist.gov", time: "recent" },
          { title: "North Korean APT deploys novel supply chain attack vector", source: "Mandiant", tag: "APT", color: "#ff6b35", url: "https://mandiant.com", time: "recent" },
          { title: "Cloudflare mitigates largest DDoS attack at 5.6 Tbps", source: "Cloudflare Blog", tag: "DDOS", color: "#ff2d55", url: "https://blog.cloudflare.com", time: "recent" },
          { title: "EU AI Act enforcement begins — fines up to €35M for violations", source: "Reuters", tag: "POLICY", color: "#0047ab", url: "https://reuters.com", time: "recent" },
        ])
        setIsLive(false)
      })
      .finally(() => setLoading(false))
  }, [])

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)", zIndex: 900, display: "flex", alignItems: "center", justifyContent: "center", backdropFilter: "blur(4px)", opacity: vis ? 1 : 0, transition: "opacity 0.2s" }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{ width: "100%", maxWidth: 720, maxHeight: "80vh", background: "#000", border: "1px solid rgba(0,255,65,0.3)", display: "flex", flexDirection: "column", boxShadow: "0 0 60px rgba(0,255,65,0.08)", animation: "slideUp 0.2s ease" }}>

        {/* Header */}
        <div style={{ padding: "14px 20px", borderBottom: "1px solid rgba(0,255,65,0.2)", display: "flex", justifyContent: "space-between", alignItems: "center", background: "rgba(0,255,65,0.03)" }}>
          <div>
            <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: 2, color: "#fff" }}>THREAT_INTEL_FEED</span>
            <span style={{ fontSize: 9, opacity: 0.35, marginLeft: 12, letterSpacing: 2 }}>CYBERSEC · AI · TECHNOLOGY</span>
            {!loading && (
              <span style={{ fontSize: 9, marginLeft: 12, color: isLive ? "#00ff41" : "#ffd700", letterSpacing: 1 }}>
                {isLive ? "● LIVE" : "○ CACHED"}
              </span>
            )}
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#ff2d55", cursor: "pointer", fontSize: 14, fontFamily: "inherit" }}>✕</button>
        </div>

        {/* Articles */}
        <div style={{ overflowY: "auto", padding: "16px 20px", display: "flex", flexDirection: "column", gap: 2 }}>
          {loading ? (
            <div style={{ padding: "40px 0", textAlign: "center", fontSize: 11, opacity: 0.3, letterSpacing: 2 }}>
              FETCHING THREAT INTEL...
              <div style={{ width: 160, height: 1, background: "rgba(0,255,65,0.08)", margin: "16px auto 0", overflow: "hidden" }}>
                <div style={{ height: "100%", background: "#00ff41", width: "40%", animation: "scan 1.2s ease-in-out infinite" }} />
              </div>
            </div>
          ) : articles.map((item, i) => (
            <a
              key={i}
              href={item.url ?? "#"}
              target="_blank"
              rel="noopener noreferrer"
              style={{ padding: "14px 16px", borderLeft: `2px solid ${item.color}`, background: "rgba(255,255,255,0.01)", cursor: "pointer", transition: "background 0.15s", animation: `fadeIn 0.3s ease ${i * 0.04}s both`, textDecoration: "none", display: "block" }}
              onMouseEnter={e => (e.currentTarget.style.background = "rgba(0,255,65,0.04)")}
              onMouseLeave={e => (e.currentTarget.style.background = "rgba(255,255,255,0.01)")}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, color: "rgba(255,255,255,0.85)", lineHeight: 1.5, marginBottom: 6 }}>{item.title}</div>
                  <div style={{ display: "flex", gap: 12, fontSize: 9, opacity: 0.45 }}>
                    <span>{item.source}</span><span>·</span><span>{item.time}</span>
                    <span style={{ color: "#00ff41", opacity: 0.6 }}>↗ OPEN</span>
                  </div>
                </div>
                <span style={{ fontSize: 9, padding: "2px 8px", border: `1px solid ${item.color}55`, color: item.color, letterSpacing: 1, whiteSpace: "nowrap", flexShrink: 0 }}>{item.tag}</span>
              </div>
            </a>
          ))}
        </div>

        <div style={{ padding: "10px 20px", borderTop: "1px solid rgba(0,255,65,0.1)", fontSize: 9, opacity: 0.2, letterSpacing: 1, display: "flex", justifyContent: "space-between" }}>
          <span>{isLive ? "LIVE FEED VIA NEWSDATA.IO · CACHED 30 MIN" : "STATIC FEED — ADD NEWSDATA_API_KEY TO .ENV FOR LIVE"}</span>
          <span>CLICK ANY ARTICLE TO OPEN SOURCE</span>
        </div>
      </div>
    </div>
  )
}

// ── Shared sub-components ─────────────────────────────────────────────────────

function ThreatNode({ level, active }: { level: keyof typeof THREAT_COLORS; active?: boolean }) {
  const cfg = THREAT_COLORS[level]
  if (active) return <div style={{ width: 24, height: 24, background: cfg.color, border: "4px solid black", outline: `2px solid ${cfg.color}`, animation: "nodePulse 1.5s infinite", flexShrink: 0 }} />
  return <div style={{ width: 16, height: 16, background: cfg.color, boxShadow: `0 0 8px ${cfg.color}`, flexShrink: 0 }} />
}

function DataSourceBadge({ source }: { source?: string }) {
  if (!source || source === "csv") return null
  return <span style={{ fontSize: 9, padding: "1px 6px", border: "1px solid rgba(0,71,171,0.5)", color: "#0047ab", letterSpacing: 1, marginLeft: 6 }}>PCAP</span>
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Home() {
  const [file, setFile] = useState<File | null>(null)
  const [results, setResults] = useState<LogResult[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [loading, setLoading] = useState(false)
  const [liveMode, setLiveMode] = useState(false)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [filter, setFilter] = useState("all")
  const [cmd, setCmd] = useState("")
  const [suggestions, setSugg] = useState<string[]>([])
  const [activeView, setActiveView] = useState<"upload" | "threat_feed">("upload")
  const [time, setTime] = useState("")
  const [streamTotal, setStreamTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [showAssistant, setShowAssistant] = useState(false)
  const [showNews, setShowNews] = useState(false)
  const [newsItems, setNewsItems] = useState<NewsItem[]>([])
  const [tickerIdx, setTickerIdx] = useState(0)
  const [glitch, setGlitch] = useState(false)

  const fileRef = useRef<HTMLInputElement>(null)
  const esRef = useRef<EventSource | null>(null)
  const feedBottom = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const t = setInterval(() => { const now = new Date(); const ist = new Date(now.getTime() + (5.5 * 60 * 60 * 1000)); setTime(ist.toISOString().slice(11, 19)) }, 1000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    const t = setInterval(() => setTickerIdx(p => (p + 1) % TICKER_MSGS.length), 3000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    const t = setInterval(() => { setGlitch(true); setTimeout(() => setGlitch(false), 130) }, 9000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    // Wake up Render backend on page load (free tier spins down after inactivity)
    const wakeUp = async () => {
      for (let i = 0; i < 5; i++) {
        try {
          const r = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/health`)
          if (r.ok) {
            // Backend is awake — now fetch news
            fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/news`)
              .then(r => r.json())
              .then(data => setNewsItems(data.articles ?? []))
              .catch(() => { })
            return
          }
        } catch { }
        await new Promise(res => setTimeout(res, 10000)) // wait 10s between retries
      }
    }
    wakeUp()
  }, [])

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => { if (e.key === "Escape") setSugg([]) }
    window.addEventListener("keydown", handleEsc)
    return () => window.removeEventListener("keydown", handleEsc)
  }, [])




  useEffect(() => { feedBottom.current?.scrollIntoView({ behavior: "smooth" }) }, [results.length])

  function stopStream() { esRef.current?.close(); esRef.current = null; setLiveMode(false); setLoading(false) }
  function isPcap(f: File) { return f.name.toLowerCase().endsWith(".pcap") || f.name.toLowerCase().endsWith(".pcapng") }

  async function uploadPcap(f: File) {
    setLoading(true); setError(null); setResults([]); setSummary(null); setActiveView("threat_feed")
    const form = new FormData(); form.append("file", f)
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/analyze-pcap`, { method: "POST", body: form })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || "Server error") }
      const data = await res.json(); setResults(data.results); setSummary(data.summary)
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Unknown error") }
    finally { setLoading(false) }
  }

  async function uploadStream(f: File) {
    stopStream(); setLoading(true); setError(null); setResults([]); setSummary(null); setActiveView("threat_feed")
    const form = new FormData(); form.append("file", f)
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/live/analyze-stream`, { method: "POST", body: form })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || "Server error") }
      const reader = res.body!.getReader(); const dec = new TextDecoder(); let buf = ""
      while (true) {
        const { done, value } = await reader.read(); if (done) break
        buf += dec.decode(value, { stream: true })
        const parts = buf.split("\n\n"); buf = parts.pop() ?? ""
        for (const part of parts) {
          const ev = part.split("\n").find(l => l.startsWith("event:"))?.replace("event:", "").trim()
          const dl = part.split("\n").find(l => l.startsWith("data:"))?.replace("data:", "").trim()
          if (!ev || !dl) continue
          const d = JSON.parse(dl)
          if (ev === "start") setStreamTotal(d.total)
          if (ev === "log") setResults(prev => [d, ...prev])
          if (ev === "done") { setSummary(d.summary); setLoading(false) }
        }
      }
    } catch (e: unknown) { setError(e instanceof Error ? e.message : "Unknown error"); setLoading(false) }
  }

  function handleFileSelect(f: File | null) { if (!f) return; setFile(f) }
  function runAnalysis() { if (!file) return; isPcap(file) ? uploadPcap(file) : uploadStream(file) }

  function startLiveStream(rate = 1.0) {
    stopStream(); setResults([]); setSummary(null); setError(null); setLiveMode(true); setActiveView("threat_feed")
    const es = new EventSource(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/live/stream?rate=${rate}`)
    esRef.current = es
    es.addEventListener("log", e => setResults(prev => [JSON.parse(e.data), ...prev.slice(0, 99)]))
    es.addEventListener("stats", e => {
      const s = JSON.parse(e.data)
      setSummary({ total_logs: s.total, normal: s.normal, suspicious: s.medium, high_threats: s.high, critical_threats: s.critical, top_attack_types: {}, threat_rate: Math.round((s.total - s.normal) / Math.max(s.total, 1) * 100) })
    })
    es.onerror = () => { setError("Live stream disconnected"); stopStream() }
  }

  function handleCmd(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Tab") { e.preventDefault(); if (suggestions.length) setCmd(suggestions[0]); return }
    if (e.key !== "Enter") return
    const c = cmd.trim().toLowerCase()
    if (c === "/clear logs") { stopStream(); setResults([]); setSummary(null); setFile(null); setActiveView("upload") }
    else if (c === "/live stop") { stopStream() }
    else if (c.startsWith("/live")) { startLiveStream(parseFloat(c.split("--rate")[1]) || 1) }
    else if (c.startsWith("/filter --threat ")) { setFilter(c.replace("/filter --threat ", "")); setActiveView("threat_feed") }
    else if (c === "/status model") { alert("MODEL: IsolationForest v2 | FEATURES: 7 | PCAP: scapy | STATUS: READY") }
    else if (c.startsWith("/analyze")) { fileRef.current?.click() }
    else if (c === "/news") { setShowNews(true) }
    else if (c === "/assistant") { setShowAssistant(true) }
    setCmd("")
    setSugg([])
  }

  function handleCmdChange(val: string) {
    setCmd(val); setSugg(val.startsWith("/") ? COMMANDS.filter(c => c.startsWith(val)) : [])
  }

  const filtered = results.filter(r =>
    filter === "all" ? true : filter === "critical" ? r.threat_level === "critical" :
      filter === "high" ? r.threat_level === "high" : filter === "medium" ? r.threat_level === "medium" : r.threat_level === "low"
  )

  const isPcapSession = summary?.data_source === "pcap"

  function exportJSON(data: LogResult[], sum: Summary | null) {
    const payload = {
      generated_at: new Date(Date.now() + 5.5 * 60 * 60 * 1000).toISOString().replace("T", " ").slice(0, 19) + " IST",
      model: "IsolationForest v2 · 7 features",
      ai_layer: "Groq/Llama-3.3-70B",
      summary: sum,
      results: data.map(r => ({
        src_ip: r.log.src_ip,
        port: r.log.port,
        packet_rate: r.log.packet_rate,
        packet_size: r.log.packet_size,
        prediction: r.prediction,
        threat_level: r.threat_level,
        anomaly_score: r.anomaly_score,
        confidence: r.confidence,
        geo: r.geo ?? null,
        soc_report: r.ai_explanation ?? null,
      }))
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" })
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: `sentinel_report_${Date.now()}.json` })
    a.click(); URL.revokeObjectURL(a.href)
  }

  function exportPDF(data: LogResult[], sum: Summary | null) {
    const ts = new Date(Date.now() + 5.5 * 60 * 60 * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' IST'
    const high = data.filter(r => r.threat_level === "high" || r.threat_level === "critical")
    const crit = data.filter(r => r.threat_level === "critical").length
    const hi = data.filter(r => r.threat_level === "high").length
    const threatPct = sum?.threat_rate ?? (data.length > 0 ? Math.round((data.filter(r => r.threat_level !== "low").length / data.length) * 100) : 0)

    // ── Plain-English executive verdict ──────────────────────────────────────
    const isSafe = crit === 0 && hi === 0
    const verdict = isSafe
      ? `✅ Your network appears <strong>safe</strong>. No high or critical threats were detected during this analysis window. Normal traffic patterns dominate — no immediate action is required.`
      : `🚨 Your network is <strong>under active threat</strong>. ${crit} critical and ${hi} high-severity events were detected (${threatPct}% threat rate). Immediate review of flagged IPs and firewall rules is strongly recommended.`

    // ── Remediation commands for flagged IPs ─────────────────────────────────
    const flaggedIPs = [...new Set(high.map(r => String(r.log.src_ip ?? "")))]
    const remSteps = flaggedIPs.length === 0 ? "<p style='color:#555'>No high/critical IPs flagged — no firewall changes required.</p>" : `
      <p style='margin-bottom:10px;color:#333'>Block the following source IPs on your perimeter firewall immediately:</p>
      <div style='background:#0a0a0a;color:#00e63a;font-family:Courier New,monospace;padding:14px 18px;border-left:4px solid #00e63a;font-size:11px;line-height:2'>
        ${flaggedIPs.map(ip => `<div><span style='opacity:.5'># Linux / iptables</span><br>iptables -I INPUT -s ${ip} -j DROP<br><span style='opacity:.5'># Windows firewall</span><br>netsh advfirewall firewall add rule name="Block ${ip}" dir=in action=block remoteip=${ip}<br></div>`).join("<hr style='border-color:#1a1a1a;margin:6px 0'>")}
      </div>
      <p style='margin-top:12px;font-size:10px;color:#888'>Also consider: rate-limiting port ${high[0]?.log.port ?? "N/A"} · enabling IDS/IPS signatures for detected attack types · reviewing authentication logs for lateral movement.</p>
    `

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Network Health Sentinel — Threat Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',sans-serif;background:#f8f9fa;color:#111;font-size:12px;line-height:1.6}

  /* ── Page chrome ── */
  .page{max-width:900px;margin:0 auto;padding:48px 52px}
  @media print{body{background:#fff}.page{padding:32px 40px}}

  /* ── Header ── */
  .hdr{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:20px;border-bottom:3px solid #000;margin-bottom:28px}
  .hdr-left h1{font-size:22px;font-weight:700;letter-spacing:-0.5px;color:#000}
  .hdr-left .sub{font-size:10px;letter-spacing:2px;color:#555;margin-top:4px;text-transform:uppercase}
  .hdr-right{text-align:right;font-size:10px;color:#555;line-height:2}
  .hdr-right a{color:#0047ab;text-decoration:none}
  .badge-safe{display:inline-block;background:#00c940;color:#fff;font-size:9px;font-weight:700;letter-spacing:1.5px;padding:3px 10px;margin-top:6px}
  .badge-threat{display:inline-block;background:#cc0000;color:#fff;font-size:9px;font-weight:700;letter-spacing:1.5px;padding:3px 10px;margin-top:6px}

  /* ── Section headers ── */
  .tier{margin-bottom:32px;page-break-inside:avoid}
  .tier-label{font-size:9px;font-weight:700;letter-spacing:3px;color:#0047ab;text-transform:uppercase;border-top:2px solid #0047ab;padding-top:8px;margin-bottom:14px}
  h2{font-size:14px;font-weight:700;color:#000;margin-bottom:10px}

  /* ── Verdict box ── */
  .verdict{padding:16px 20px;border-left:5px solid ${isSafe ? "#00c940" : "#cc0000"};background:${isSafe ? "#f0fff4" : "#fff5f5"};font-size:13px;line-height:1.8;color:#111}

  /* ── Stats grid ── */
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}
  .stat{background:#fff;border:1px solid #ddd;padding:12px 14px;border-top:3px solid #0047ab}
  .stat .val{font-size:22px;font-weight:700;color:#000;font-family:'JetBrains Mono',monospace}
  .stat .lbl{font-size:9px;letter-spacing:1.5px;color:#888;margin-top:2px;text-transform:uppercase}
  .stat.danger{border-top-color:#cc0000}.stat.danger .val{color:#cc0000}
  .stat.warn{border-top-color:#cc7000}.stat.warn .val{color:#cc7000}
  .stat.ok{border-top-color:#00a830}.stat.ok .val{color:#00a830}

  /* ── Tables ── */
  table{width:100%;border-collapse:collapse;margin:10px 0;font-size:10px}
  th{background:#111;color:#fff;padding:7px 10px;text-align:left;font-family:'JetBrains Mono',monospace;letter-spacing:.5px;font-size:9px}
  td{padding:6px 10px;border-bottom:1px solid #eee;font-family:'JetBrains Mono',monospace}
  tr:nth-child(even) td{background:#fafafa}
  .lvl-critical{color:#cc0000;font-weight:700}.lvl-high{color:#cc5500;font-weight:700}.lvl-medium{color:#aa7700}.lvl-low{color:#00a830}

  /* ── SOC card ── */
  .soc-card{background:#fff;border:1px solid #e0e0e0;border-left:4px solid #cc0000;padding:14px 16px;margin-bottom:16px;page-break-inside:avoid}
  .soc-card.high{border-left-color:#cc5500}
  .soc-card .soc-hdr{font-weight:700;font-size:11px;margin-bottom:6px;display:flex;gap:10px;align-items:center}
  .soc-card .soc-meta{font-size:10px;color:#666;margin-bottom:8px;font-family:'JetBrains Mono',monospace}
  .soc-card .soc-body{font-size:10px;color:#333;line-height:1.9;white-space:pre-wrap;border-top:1px solid #eee;padding-top:8px}

  /* ── Remediation ── */
  .rem{margin-top:10px}

  /* ── Footer ── */
  .footer{margin-top:40px;border-top:1px solid #ddd;padding-top:14px;display:flex;justify-content:space-between;font-size:9px;color:#aaa;letter-spacing:.5px}
</style>
</head>
<body><div class="page">

<!-- ════════ HEADER ════════ -->
<div class="hdr">
  <div class="hdr-left">
    <h1>⬡ NETWORK HEALTH SENTINEL</h1>
    <div class="sub">Automated Threat Intelligence Report &nbsp;·&nbsp; v1.0</div>
    <div style="margin-top:10px">${isSafe
        ? '<span class="badge-safe">● NETWORK SAFE</span>'
        : '<span class="badge-threat">⚠ THREATS DETECTED</span>'}</div>
  </div>
  <div class="hdr-right">
    <strong style="color:#000;font-size:11px">Lead Developer</strong><br>
    Yogita Singh<br>
    <a href="https://yogitasingh.me/" target="_blank">yogitasingh.me</a><br><br>
    <strong style="color:#000">Generated</strong><br>${ts}<br>
    Model: IsolationForest v2 · 7 features<br>
    AI Layer: Gemini-1.5-flash
  </div>
</div>

<!-- ════════ TIER 1 — EXECUTIVE SUMMARY ════════ -->
<div class="tier">
  <div class="tier-label">Tier 1 &nbsp;·&nbsp; Executive Summary &nbsp;·&nbsp; Non-Technical</div>
  <h2>Network Health Verdict</h2>
  <div class="verdict">${verdict}</div>
  ${sum ? `
  <div class="stats">
    <div class="stat ${sum.critical_threats > 0 ? "danger" : "ok"}">
      <div class="val">${sum.critical_threats}</div><div class="lbl">Critical Threats</div>
    </div>
    <div class="stat ${sum.high_threats > 0 ? "warn" : "ok"}">
      <div class="val">${sum.high_threats}</div><div class="lbl">High Threats</div>
    </div>
    <div class="stat">
      <div class="val">${sum.threat_rate}%</div><div class="lbl">Threat Rate</div>
    </div>
    <div class="stat ok">
      <div class="val">${sum.total_logs}</div><div class="lbl">Total Logs</div>
    </div>
  </div>
  ${sum.exec_summary ? `<p style="font-size:11px;color:#444;line-height:1.9;margin-top:12px;padding:12px 16px;background:#fff;border:1px solid #e8e8e8">${sum.exec_summary}</p>` : ""}
  ` : ""}
</div>

<!-- ════════ TIER 2 — SOC THREAT INTELLIGENCE ════════ -->
<div class="tier">
  <div class="tier-label">Tier 2 &nbsp;·&nbsp; Threat Intelligence &nbsp;·&nbsp; SOC Analysts</div>
  <h2>Full Threat Log &nbsp;<span style="font-size:10px;font-weight:400;color:#888">(${data.length} events)</span></h2>
  <table>
    <tr><th>SOURCE IP</th><th>GEO</th><th>PORT</th><th>RATE (pps)</th><th>SIZE (B)</th><th>DETECTION</th><th>LEVEL</th><th>SCORE</th><th>CONF %</th></tr>
    ${data.map(r => `<tr>
      <td>${r.log.src_ip ?? ""}</td>
      <td style="color:#0047ab">${r.geo?.country ? `${r.geo.city ? r.geo.city + ", " : ""}${r.geo.country}` : "-"}</td>
      <td>${r.log.port ?? ""}</td>
      <td>${r.log.packet_rate ?? ""}</td>
      <td>${r.log.packet_size ?? ""}</td>
      <td class="lvl-${r.threat_level}">${r.prediction}</td>
      <td class="lvl-${r.threat_level}">${r.threat_level.toUpperCase()}</td>
      <td>${typeof r.anomaly_score === "number" ? r.anomaly_score.toFixed(4) : ""}</td>
      <td>${r.confidence}%</td>
    </tr>`).join("")}
  </table>
  ${Object.keys(sum?.top_attack_types ?? {}).length > 0 ? `
  <h2 style="margin-top:20px">MITRE ATT&CK — Attack Breakdown</h2>
  <table><tr><th>ATTACK TYPE / TECHNIQUE</th><th>COUNT</th><th>% SHARE</th></tr>
    ${Object.entries(sum!.top_attack_types).sort((a, b) => b[1] - a[1]).map(([k, v]) => `
    <tr><td>${k}</td><td>${v}</td><td>${Math.round(v / data.length * 100)}%</td></tr>`).join("")}
  </table>`: ""}
  ${high.length > 0 ? `
  <h2 style="margin-top:24px">Gemini SOC Analysis — High &amp; Critical Events (${high.length})</h2>
  ${high.map(r => `
  <div class="soc-card ${r.threat_level}">
    <div class="soc-hdr">
      <span class="lvl-${r.threat_level}">[${r.threat_level.toUpperCase()}]</span>
      <span>${r.prediction}</span>
    </div>
    <div class="soc-meta">
      SRC: ${r.log.src_ip ?? "-"}:${r.log.port ?? "-"} &nbsp;·&nbsp;
      RATE: ${r.log.packet_rate ?? "-"} pps &nbsp;·&nbsp;
      SIZE: ${r.log.packet_size ?? "-"}B &nbsp;·&nbsp;
      SCORE: ${typeof r.anomaly_score === "number" ? r.anomaly_score.toFixed(4) : "-"} &nbsp;·&nbsp;
      CONF: ${r.confidence}%
      ${r.geo?.country ? ` &nbsp;·&nbsp; GEO: ${r.geo.city ? r.geo.city + ", " : ""}${r.geo.country}` : ""}
    </div>
    <div class="soc-body">${r.ai_explanation ? r.ai_explanation.replace(/</g, "&lt;").replace(/>/g, "&gt;") : "SOC analysis not available for this entry."}</div>
  </div>`).join("")}
  `: ""}
</div>

<!-- ════════ TIER 3 — ACTIONABLE REMEDIATION ════════ -->
<div class="tier">
  <div class="tier-label">Tier 3 &nbsp;·&nbsp; Actionable Remediation &nbsp;·&nbsp; IT / Network Engineers</div>
  <h2>Next Steps — Immediate Action Required</h2>
  <div class="rem">${remSteps}</div>
  <div style="margin-top:20px;padding:14px 16px;background:#fff;border:1px solid #ddd;font-size:11px;line-height:2">
    <strong style="display:block;margin-bottom:6px;font-size:10px;letter-spacing:1.5px;color:#0047ab">GENERAL HARDENING CHECKLIST</strong>
    <span style="display:block">☐ &nbsp;Rotate credentials on any host that communicated with flagged IPs</span>
    <span style="display:block">☐ &nbsp;Enable geo-blocking on origin countries of critical-threat IPs</span>
    <span style="display:block">☐ &nbsp;Review SIEM/IDS alerts for correlated lateral movement events</span>
    <span style="display:block">☐ &nbsp;Patch systems running services on commonly abused ports (22, 3389, 445, 80/443)</span>
    <span style="display:block">☐ &nbsp;Schedule a re-scan within 24 hours to confirm remediation effectiveness</span>
  </div>
</div>

<!-- ════════ FOOTER ════════ -->
<div class="footer">
  <span>Network Health Sentinel v1.0 &nbsp;·&nbsp; Built by Yogita Singh &nbsp;·&nbsp; yogitasingh.me</span>
  <span>IsolationForest v2 · Gemini-1.5-flash · Auto-generated report</span>
  <span>${ts}</span>
</div>

</div></body></html>`

    const win = window.open("", "_blank")
    if (win) { win.document.write(html); win.document.close(); setTimeout(() => win.print(), 600) }
  }


  return (
    <div style={{ background: "#000", color: "#00ff41", fontFamily: "'Fira Code',monospace", height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", position: "relative" }}>

      <ParticleCanvas />
      <CursorGlow />
      {showNews && <NewsPanel onClose={() => setShowNews(false)} />}
      {showAssistant && <AIAssistant onClose={() => setShowAssistant(false)} />}

      {/* Floating assistant button */}
      <button onClick={() => setShowAssistant(p => !p)} title="SENTINEL_AI"
        style={{ position: "fixed", bottom: 24, right: 24, zIndex: 500, width: 48, height: 48, background: showAssistant ? "rgba(0,255,65,0.15)" : "#000", border: "1px solid rgba(0,255,65,0.5)", color: "#00ff41", fontSize: 20, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", animation: "assistantPulse 3s ease-in-out infinite", transition: "background 0.2s" }}>
        ⬡
      </button>

      {/* Header */}
      <header style={{ height: 40, borderBottom: "1px solid rgba(0,255,65,0.3)", background: "rgba(0,0,0,0.92)", display: "flex", alignItems: "center", padding: "0 16px", flexShrink: 0, gap: 16, overflow: "hidden", position: "relative", zIndex: 10 }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "100%", background: "linear-gradient(90deg,transparent,rgba(0,255,65,0.03),transparent)", animation: "headerScan 5s linear infinite", pointerEvents: "none" }} />
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, whiteSpace: "nowrap" }}>⬡ SYSTEM_LOG:</span>
        <span style={{ fontSize: 10, opacity: 0.7, whiteSpace: "nowrap" }}>{TICKER_MSGS[tickerIdx]}</span>
        {liveMode && <span style={{ color: "#ff2d55", animation: "nodePulse 1s infinite", fontSize: 10, whiteSpace: "nowrap" }}>[LIVE] STREAMING</span>}
        {loading && <span style={{ color: "#ffd700", fontSize: 10, whiteSpace: "nowrap" }}>[SCANNING] {streamTotal > 0 ? `${results.length}/${streamTotal}` : "PROCESSING..."}</span>}
        {error && <span style={{ color: "#ff2d55", fontSize: 10, whiteSpace: "nowrap" }}>[ERROR] {error}</span>}
        <div style={{ marginLeft: "auto", display: "flex", gap: 20, fontSize: 11, flexShrink: 0 }}>
          <span style={{ opacity: 0.45 }}>CPU 14%</span>
          <span style={{ opacity: 0.45 }}>MEM 31%</span>
          <span style={{ color: "#fff" }}>IST {time}</span>
        </div>
      </header>

      <main style={{ flex: 1, display: "flex", overflow: "hidden", position: "relative", zIndex: 1 }}>

        {/* Sidebar */}
        <aside style={{ width: 220, borderRight: "1px solid rgba(0,255,65,0.2)", display: "flex", flexDirection: "column", background: "rgba(0,0,0,0.92)", flexShrink: 0 }}>
          <div style={{ padding: "14px 16px", borderBottom: "1px solid rgba(0,255,65,0.2)", position: "relative", overflow: "hidden" }}>
            <div style={{ position: "absolute", inset: 0, background: "linear-gradient(135deg,rgba(0,255,65,0.04) 0%,transparent 60%)", pointerEvents: "none" }} />
            <div style={{ fontSize: 11, fontWeight: 700, color: "#fff", letterSpacing: 1, ...(glitch ? { textShadow: "2px 0 #ff2d55,-2px 0 #00ff41", transform: "skewX(-2deg)" } : {}), transition: "all 0.05s" }}>SENTINEL_ROOT_v2.2</div>
            <div style={{ fontSize: 9, opacity: 0.25, letterSpacing: 2, marginTop: 3 }}>NETWORK HEALTH SENTINEL</div>
          </div>

          <nav style={{ flex: 1, padding: 8, fontSize: 12, overflowY: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", background: "rgba(0,255,65,0.06)", border: "1px solid rgba(0,255,65,0.12)", marginBottom: 4 }}>📁 /root/sentinel</div>
            <div style={{ paddingLeft: 16 }}>
              {[{ icon: "⬡", label: "threat_feed", view: "threat_feed" as const }, { icon: "📤", label: "upload_logs", view: "upload" as const }].map(item => (
                <div key={item.label} onClick={() => setActiveView(item.view)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 8px", cursor: "pointer", opacity: activeView === item.view ? 1 : 0.5, background: activeView === item.view ? "rgba(0,255,65,0.06)" : "transparent", marginBottom: 2, borderLeft: activeView === item.view ? "2px solid #00ff41" : "2px solid transparent", transition: "all 0.15s" }}>
                  {item.icon} {item.label}
                </div>
              ))}
              <div onClick={() => setShowNews(true)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 8px", cursor: "pointer", opacity: 0.5, marginBottom: 2, transition: "all 0.15s" }}
                onMouseEnter={e => (e.currentTarget.style.opacity = "1")} onMouseLeave={e => (e.currentTarget.style.opacity = "0.5")}>
                📡 threat_intel
              </div>
              <div onClick={() => liveMode ? stopStream() : startLiveStream(1)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 8px", cursor: "pointer", opacity: liveMode ? 1 : 0.5, color: liveMode ? "#ff2d55" : undefined, marginBottom: 2, transition: "all 0.15s" }}>
                {liveMode ? "⏹" : "▶"} {liveMode ? "stop_live" : "live_monitor"}
              </div>
            </div>

            {results.length > 0 && <>
              <div style={{ marginTop: 16, fontSize: 10, opacity: 0.3, letterSpacing: 2, padding: "0 8px", marginBottom: 6 }}>FILTERS</div>
              {(["all", "critical", "high", "medium", "low"] as const).map(f => (
                <div key={f} onClick={() => { setFilter(f); setActiveView("threat_feed") }} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "6px 10px", cursor: "pointer", background: filter === f ? "rgba(0,255,65,0.06)" : "transparent", opacity: filter === f ? 1 : 0.45, fontSize: 11, transition: "all 0.15s" }}>
                  <span style={{ color: f === "critical" ? "#ff2d55" : f === "high" ? "#ff6b35" : f === "medium" ? "#ffd700" : "#00ff41" }}>{f.toUpperCase()}</span>
                  <span style={{ fontSize: 10, opacity: 0.5 }}>
                    {f === "all" ? results.length : results.filter(r => r.threat_level === (f === "critical" ? "critical" : f === "high" ? "high" : f === "medium" ? "medium" : "low")).length}
                  </span>
                </div>
              ))}
            </>}

            {summary && (
              <div style={{ marginTop: 16, padding: "0 8px" }}>
                <div style={{ fontSize: 10, opacity: 0.3, letterSpacing: 2, marginBottom: 8 }}>SESSION</div>
                {[
                  { label: "TOTAL", val: summary.total_logs },
                  { label: "THREAT%", val: `${summary.threat_rate}%` },
                  { label: "CRITICAL", val: summary.critical_threats, color: "#ff2d55" },
                  { label: "HIGH", val: summary.high_threats, color: "#ff6b35" },
                ].map(s => (
                  <div key={s.label} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, padding: "3px 0", opacity: 0.65 }}>
                    <span>{s.label}</span><span style={{ color: s.color ?? "#00ff41" }}>{s.val}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Mini news */}
            <div style={{ marginTop: 20, padding: "10px 8px", borderTop: "1px solid rgba(0,255,65,0.08)" }}>
              <div style={{ fontSize: 9, opacity: 0.25, letterSpacing: 2, marginBottom: 8 }}>LIVE_INTEL</div>
              {(newsItems.length > 0 ? newsItems : [
                { title: "Fetching threat intel...", color: "#00ff41" },
                { title: "Cybersecurity news feed", color: "#0047ab" },
                { title: "AI & ML updates", color: "#00ff41" },
              ]).slice(0, 3).map((n, i) => (
                <div key={i} onClick={() => setShowNews(true)} style={{ fontSize: 9, opacity: 0.5, lineHeight: 1.8, cursor: "pointer", marginBottom: 4, display: "flex", gap: 6 }}>
                  <span style={{ color: n.color, flexShrink: 0 }}>■</span>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{n.title.slice(0, 28)}…</span>
                </div>
              ))}
            </div>
          </nav>
        </aside>

        {/* Main content */}
        <section style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", background: "rgba(0,0,0,0.8)" }}>
          <div style={{ padding: "10px 20px", borderBottom: "1px solid rgba(0,255,65,0.12)", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#fff", letterSpacing: 1 }}>
              {activeView === "upload" ? "UPLOAD_INTERFACE" : "THREAT_TIMELINE"}
            </span>
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={() => setShowNews(true)} style={{ fontSize: 10, padding: "4px 12px", border: "1px solid rgba(0,71,171,0.4)", background: "rgba(0,71,171,0.06)", color: "#0047ab", cursor: "pointer", fontFamily: "inherit", letterSpacing: 1 }}>📡 INTEL_FEED</button>
              {results.length > 0 && <>
                <button onClick={() => exportJSON(results, summary)} style={{ fontSize: 10, padding: "4px 12px", border: "1px solid rgba(0,255,65,0.3)", background: "rgba(0,255,65,0.05)", color: "#00ff41", cursor: "pointer", fontFamily: "inherit", letterSpacing: 1 }}>⬇ JSON</button>
                <button onClick={() => exportPDF(results, summary)} style={{ fontSize: 10, padding: "4px 12px", border: "1px solid rgba(255,107,53,0.4)", background: "rgba(255,107,53,0.06)", color: "#ff6b35", cursor: "pointer", fontFamily: "inherit", letterSpacing: 1 }}>⬇ PDF</button>
                <button onClick={() => { stopStream(); setResults([]); setSummary(null); setFile(null); setActiveView("upload") }} style={{ fontSize: 10, padding: "4px 10px", border: "1px solid rgba(0,255,65,0.2)", background: "transparent", color: "#00ff41", cursor: "pointer", fontFamily: "inherit" }}>↺ CLEAR</button>
              </>}
            </div>
          </div>

          <div style={{ flex: 1, overflowY: "auto", padding: "32px 40px", display: "flex", flexDirection: "column", alignItems: "center" }}>

            {activeView === "upload" && !loading && (
              <div style={{ width: "100%", maxWidth: 680, marginTop: 16, animation: "fadeIn 0.5s ease" }}>

                {/* ── Section 2 — Hero Title Block ───────────────────────── */}
                <div style={{ textAlign: "center", marginBottom: 28 }}>

                  {/* 2a — Decorative rule */}
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
                    <div style={{ flex: 1, height: 1, background: "linear-gradient(to right, transparent, rgba(0,255,65,0.3))" }} />
                    <span style={{ fontSize: 9, letterSpacing: 3, color: "rgba(0,255,65,0.6)", whiteSpace: "nowrap" }}>NETWORK HEALTH SENTINEL</span>
                    <div style={{ flex: 1, height: 1, background: "linear-gradient(to left, transparent, rgba(0,255,65,0.3))" }} />
                  </div>

                  {/* 2b — Main headline */}
                  <div style={{ position: "relative", display: "inline-block", marginBottom: 6 }}>
                    <h1 style={{ fontSize: 42, fontWeight: 700, letterSpacing: -1, color: "#fff", lineHeight: 1.15, margin: 0 }}>
                      AI-Powered{" "}
                      <span style={{ color: "#00ff41", textShadow: "0 0 30px rgba(0,255,65,0.4), 0 0 60px rgba(0,255,65,0.15)" }}>Intrusion</span>
                      <br />Detection System
                    </h1>
                    {/* Bottom accent scan line */}
                    <div style={{ position: "relative", height: 2, marginTop: 6, background: "rgba(0,255,65,0.06)", overflow: "hidden" }}>
                      <div style={{ position: "absolute", inset: 0, background: "linear-gradient(to right, transparent, #00ff41, #0047ab, transparent)", animation: "scan 4s linear infinite" }} />
                    </div>
                  </div>

                  {/* 2c — Subtitle */}
                  <p style={{ fontSize: 12, letterSpacing: 2, color: "rgba(255,255,255,0.35)", marginTop: 18, margin: "18px 0 22px" }}>
                    IsolationForest v2 · Gemini SOC Analysis · Real-Time Geo-Intelligence
                  </p>

                  {/* 2d — Stat pills */}
                  <div style={{ display: "flex", gap: 10, justifyContent: "center", flexWrap: "wrap" }}>
                    {[
                      { val: "10s", label: "SOC REPORT", color: "#00ff41", delay: "0ms" },
                      { val: "7", label: "ML FEATURES", color: "#0047ab", delay: "80ms" },
                      { val: "₹0", label: "COST", color: "#ffd700", delay: "160ms" },
                      { val: "L1+L2", label: "TIERS AUTO", color: "#ff6b35", delay: "240ms" },
                    ].map(chip => (
                      <div key={chip.label} style={{ padding: "5px 14px", border: `1px solid ${chip.color}28`, background: `${chip.color}08`, animation: `fadeIn 0.4s ease ${chip.delay} both` }}>
                        <div style={{ fontSize: 14, fontWeight: 700, color: chip.color }}>{chip.val}</div>
                        <div style={{ fontSize: 9, letterSpacing: 1.5, color: "rgba(255,255,255,0.35)" }}>{chip.label}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* ── Section 3 — Upload Card ─────────────────────────────── */}
                <div style={{ position: "relative", border: "1px solid rgba(0,255,65,0.25)", background: "rgba(0,0,0,0.6)", padding: "36px 40px", textAlign: "center", marginBottom: 20, transition: "border-color 0.2s, background 0.2s" }}
                  onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = "rgba(0,255,65,0.7)"; e.currentTarget.style.background = "rgba(0,255,65,0.04)" }}
                  onDragLeave={e => { e.currentTarget.style.borderColor = "rgba(0,255,65,0.25)"; e.currentTarget.style.background = "rgba(0,0,0,0.6)" }}
                  onDrop={e => { e.preventDefault(); e.currentTarget.style.borderColor = "rgba(0,255,65,0.25)"; e.currentTarget.style.background = "rgba(0,0,0,0.6)"; handleFileSelect(e.dataTransfer.files[0] ?? null) }}>

                  {/* 3a — Scanline overlay */}
                  <div style={{ position: "absolute", inset: 0, zIndex: 2, pointerEvents: "none", background: "repeating-linear-gradient(to bottom, transparent 0px, transparent 3px, rgba(0,255,65,0.012) 3px, rgba(0,255,65,0.012) 4px)" }} />

                  {/* 3c — Corner accents */}
                  {([{ top: 0, left: 0 }, { top: 0, right: 0 }, { bottom: 0, left: 0 }, { bottom: 0, right: 0 }] as React.CSSProperties[]).map((pos, i) => (
                    <div key={i} style={{ position: "absolute", ...pos, width: 20, height: 20, borderTop: i < 2 ? "2px solid #00ff41" : "none", borderBottom: i >= 2 ? "2px solid #00ff41" : "none", borderLeft: i % 2 === 0 ? "2px solid #00ff41" : "none", borderRight: i % 2 === 1 ? "2px solid #00ff41" : "none", zIndex: 3 }} />
                  ))}

                  {/* 3d — Background concentric circles */}
                  <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", width: 300, height: 300, border: "1px solid rgba(0,255,65,0.04)", borderRadius: "50%", pointerEvents: "none", zIndex: 1 }} />
                  <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", width: 180, height: 180, border: "1px solid rgba(0,255,65,0.06)", borderRadius: "50%", pointerEvents: "none", zIndex: 1 }} />

                  {/* 3e — Default state (no file) */}
                  {!file && (
                    <div style={{ position: "relative", zIndex: 4 }}>
                      {/* i. Animated SVG Shield */}
                      <div style={{ display: "inline-block", position: "relative", marginBottom: 16 }}>
                        {/* Orbit ring */}
                        <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", width: 90, height: 90, border: "1px dashed rgba(0,255,65,0.12)", borderRadius: "50%", pointerEvents: "none" }} />
                        <svg width="64" height="72" viewBox="0 0 64 72" style={{ filter: "drop-shadow(0 0 16px rgba(0,255,65,0.35))" }}>
                          <path d="M32 4 L58 16 L58 36 C58 52 44 64 32 68 C20 64 6 52 6 36 L6 16 Z" fill="rgba(0,255,65,0.04)" stroke="#00ff41" strokeWidth="1.5" />
                          <path d="M32 12 L52 21 L52 36 C52 48 42 57 32 61 C22 57 12 48 12 36 L12 21 Z" fill="none" stroke="rgba(0,255,65,0.25)" strokeWidth="1" />
                          <circle cx="32" cy="36" r="10" fill="rgba(0,255,65,0.08)" stroke="#00ff41" strokeWidth="1.5" style={{ animation: "nodePulse 2s infinite" }} />
                          <path d="M27 36 L31 40 L38 32" fill="none" stroke="#00ff41" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      </div>

                      {/* ii. Instruction text */}
                      <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 6 }}>
                        Drop your firewall log or Wireshark capture
                      </div>
                      <div style={{ fontSize: 10, marginBottom: 22, letterSpacing: 1 }}>
                        <span style={{ color: "#00ff41" }}>SUPPORTS:</span>{" "}
                        <span style={{ color: "#00ff41" }}>.CSV</span>
                        <span style={{ color: "rgba(255,255,255,0.3)" }}> · </span>
                        <span style={{ color: "#0047ab" }}>.PCAP</span>
                        <span style={{ color: "rgba(255,255,255,0.3)" }}> · </span>
                        <span style={{ color: "#0047ab" }}>.PCAPNG</span>
                      </div>

                      {/* iii & iv — Buttons (no file selected) */}
                      <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
                        <label id="select-file-btn" style={{ padding: "11px 28px", border: "1px solid rgba(0,255,65,0.4)", color: "#00ff41", background: "rgba(0,255,65,0.04)", cursor: "pointer", fontSize: 12, fontWeight: 700, letterSpacing: 2, transition: "all 0.2s" }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "rgba(0,255,65,0.10)"; (e.currentTarget as HTMLElement).style.borderColor = "rgba(0,255,65,0.8)" }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "rgba(0,255,65,0.04)"; (e.currentTarget as HTMLElement).style.borderColor = "rgba(0,255,65,0.4)" }}>
                          ↑ SELECT_FILE
                          <input ref={fileRef} type="file" accept=".csv,.pcap,.pcapng" style={{ display: "none" }} onChange={e => handleFileSelect(e.target.files?.[0] ?? null)} />
                        </label>
                        <button id="live-monitor-btn" onClick={() => startLiveStream(1)} style={{ padding: "11px 28px", border: "1px solid rgba(255,45,85,0.5)", background: "rgba(255,45,85,0.05)", color: "#ff2d55", cursor: "pointer", fontSize: 12, fontWeight: 700, letterSpacing: 2, fontFamily: "inherit", animation: "critPulse 3s ease-in-out infinite", transition: "all 0.2s" }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "rgba(255,45,85,0.14)"; (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,45,85,0.9)" }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "rgba(255,45,85,0.05)"; (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,45,85,0.5)" }}>
                          ● LIVE_MONITOR
                        </button>
                      </div>
                    </div>
                  )}

                  {/* 3f — File selected state */}
                  {file && (
                    <div style={{ position: "relative", zIndex: 4, animation: "fadeIn 0.3s ease" }}>
                      {/* i. File type emoji */}
                      <div style={{ fontSize: 36, marginBottom: 12, animation: "fadeIn 0.3s ease" }}>
                        {isPcap(file) ? "📡" : "📄"}
                      </div>

                      {/* ii. Filename */}
                      <div style={{ fontSize: 15, fontWeight: 700, color: isPcap(file) ? "#0047ab" : "#00ff41", letterSpacing: 1, marginBottom: 6 }}>
                        {file.name}
                      </div>

                      {/* iii. File metadata */}
                      <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: 2, marginBottom: 10 }}>
                        {Math.round(file.size / 1024)} KB · {isPcap(file) ? "PCAP CAPTURE" : "CSV LOG FILE"}
                      </div>

                      {/* iv. Ready badge */}
                      <div style={{ display: "inline-block", padding: "2px 12px", border: `1px solid ${isPcap(file) ? "#0047ab55" : "#00ff4155"}`, color: isPcap(file) ? "#0047ab" : "#00ff41", fontSize: 10, letterSpacing: 1, marginBottom: 20, animation: "nodePulse 2s infinite" }}>
                        ● READY TO ANALYZE
                      </div>

                      {/* v & vi — Action buttons */}
                      <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
                        <label id="change-file-btn" style={{ padding: "9px 20px", border: "1px solid rgba(0,255,65,0.2)", color: "rgba(255,255,255,0.6)", background: "transparent", cursor: "pointer", fontSize: 12, letterSpacing: 2, fontWeight: 700, transition: "all 0.2s" }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "rgba(0,255,65,0.05)"; (e.currentTarget as HTMLElement).style.color = "#00ff41" }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "transparent"; (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.6)" }}>
                          ↺ CHANGE_FILE
                          <input type="file" accept=".csv,.pcap,.pcapng" style={{ display: "none" }} onChange={e => handleFileSelect(e.target.files?.[0] ?? null)} />
                        </label>
                        <button id="run-analysis-btn" onClick={runAnalysis} disabled={!file || loading} style={{ padding: "10px 32px", border: "2px solid #00ff41", background: "rgba(0,255,65,0.1)", color: "#00ff41", cursor: "pointer", fontSize: 12, fontWeight: 700, letterSpacing: 2, fontFamily: "inherit", boxShadow: "0 0 20px rgba(0,255,65,0.15), inset 0 0 20px rgba(0,255,65,0.04)", transition: "all 0.2s" }}
                          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "rgba(0,255,65,0.18)"; (e.currentTarget as HTMLElement).style.boxShadow = "0 0 30px rgba(0,255,65,0.3), inset 0 0 20px rgba(0,255,65,0.08)" }}
                          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "rgba(0,255,65,0.1)"; (e.currentTarget as HTMLElement).style.boxShadow = "0 0 20px rgba(0,255,65,0.15), inset 0 0 20px rgba(0,255,65,0.04)" }}>
                          ▶ {isPcap(file) ? "PARSE_PCAP" : "RUN_ANALYSIS"}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* ── Section 4 — Feature Cards ───────────────────────────── */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginBottom: 20 }}>
                  {[
                    { icon: "⬡", title: "MITRE ATT&CK", desc: "Auto-mapped to attack framework with tactic & technique IDs", color: "#00ff41", delay: "100ms" },
                    { icon: "◈", title: "GEO-INTEL", desc: "Source IP geolocation — country, city, ISP per threat event", color: "#0047ab", delay: "180ms" },
                    { icon: "▶", title: "SOC REPORTS", desc: "AI-generated PDF incident reports in under 10 seconds", color: "#ff6b35", delay: "260ms" },
                  ].map(card => (
                    <div key={card.title} style={{ padding: "14px 16px", border: `1px solid ${card.color}20`, background: `${card.color}04`, animation: `fadeIn 0.4s ease ${card.delay} both`, transition: "border-color 0.2s, background 0.2s", cursor: "default" }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = `${card.color}45`; (e.currentTarget as HTMLElement).style.background = `${card.color}08` }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = `${card.color}20`; (e.currentTarget as HTMLElement).style.background = `${card.color}04` }}>
                      <div style={{ fontSize: 16, color: card.color, marginBottom: 6 }}>{card.icon}</div>
                      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 2, color: card.color, marginBottom: 5 }}>{card.title}</div>
                      <div style={{ fontSize: 9, color: "rgba(255,255,255,0.3)", lineHeight: 1.8 }}>{card.desc}</div>
                    </div>
                  ))}
                </div>

                {/* ── Section 5 — Spec Strip ──────────────────────────────── */}
                <div style={{ borderTop: "1px solid rgba(0,255,65,0.08)", borderBottom: "1px solid rgba(0,255,65,0.08)", padding: "12px 0", display: "flex", gap: 24, justifyContent: "center", flexWrap: "wrap" }}>
                  {[
                    { label: "CSV_COLS", val: "src_ip · port · packet_rate · packet_size" },
                    { label: "MODEL", val: "IsolationForest · 200 est" },
                    { label: "AI_LAYER", val: "Gemini-1.5-flash" },
                  ].map(s => (
                    <span key={s.label} style={{ fontSize: 10, whiteSpace: "nowrap" }}>
                      <span style={{ color: "rgba(0,71,171,0.7)", letterSpacing: 1.5 }}>{s.label}:</span>{" "}
                      <span style={{ color: "rgba(255,255,255,0.25)", letterSpacing: 0.5 }}>{s.val}</span>
                    </span>
                  ))}
                </div>

              </div>
            )}

            {loading && results.length === 0 && (
              <div style={{ textAlign: "center", padding: "80px 0", animation: "fadeIn 0.3s ease" }}>
                <div style={{ fontSize: 12, letterSpacing: 3, opacity: 0.6, marginBottom: 24 }}>SCANNING_TRAFFIC_VECTORS...</div>
                <div style={{ width: 240, height: 2, background: "rgba(0,255,65,0.06)", margin: "0 auto 16px", overflow: "hidden" }}>
                  <div style={{ height: "100%", background: "#00ff41", width: "40%", animation: "scan 1.2s ease-in-out infinite" }} />
                </div>
                {streamTotal > 0 && <div style={{ fontSize: 10, opacity: 0.2, letterSpacing: 2 }}>{results.length} / {streamTotal} PROCESSED</div>}
              </div>
            )}

            {summary?.exec_summary && (
              <div style={{ width: "100%", maxWidth: 680, marginBottom: 24, padding: "14px 18px", border: "1px solid rgba(0,255,65,0.18)", background: "rgba(0,255,65,0.02)", fontSize: 11, lineHeight: 1.8, color: "rgba(255,255,255,0.65)", animation: "fadeIn 0.4s ease" }}>
                <div style={{ fontSize: 9, letterSpacing: 2, color: "#00ff41", marginBottom: 8 }}>⬡ GEMINI EXECUTIVE SUMMARY</div>
                {summary.exec_summary}
              </div>
            )}

            {isPcapSession && summary && (
              <div style={{ width: "100%", maxWidth: 680, marginBottom: 24, display: "flex", gap: 12, flexWrap: "wrap" }}>
                {[
                  { label: "PACKETS", val: summary.total_packets?.toLocaleString() ?? "—" },
                  { label: "HOSTS", val: summary.unique_hosts ?? "—" },
                  { label: "DURATION", val: summary.capture_window ? `${summary.capture_window.toFixed(1)}s` : "—" },
                  { label: "THREAT_RATE", val: `${summary.threat_rate}%` },
                ].map(s => (
                  <div key={s.label} style={{ flex: 1, minWidth: 110, padding: "10px 14px", border: "1px solid rgba(0,71,171,0.2)", background: "rgba(0,71,171,0.04)" }}>
                    <div style={{ fontSize: 18, fontWeight: 700, color: "#0047ab" }}>{s.val}</div>
                    <div style={{ fontSize: 9, opacity: 0.4, letterSpacing: 1, marginTop: 4 }}>{s.label}</div>
                  </div>
                ))}
              </div>
            )}

            {(activeView === "threat_feed" || liveMode) && results.length > 0 && (
              <div style={{ width: "100%", maxWidth: 680, position: "relative" }}>
                <div style={{ position: "absolute", left: "50%", top: 0, bottom: 0, width: 1, background: "rgba(0,255,65,0.08)", transform: "translateX(-50%)", pointerEvents: "none" }} />
                <div style={{ display: "flex", flexDirection: "column", gap: 32, paddingBottom: 48 }}>
                  {filtered.slice(0, 50).map((r, i) => {
                    const cfg = THREAT_COLORS[r.threat_level]
                    const isOpen = expanded === i
                    const isCrit = r.threat_level === "critical" || r.threat_level === "high"
                    const left = i % 2 === 0

                    const labelBox = (
                      <div style={{ animation: `fadeIn 0.3s ease ${Math.min(i * 0.04, 0.5)}s both` }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, flexDirection: left ? "row-reverse" : "row" }}>
                          <span style={{ fontSize: 12, fontWeight: 700, color: cfg.color, textShadow: isCrit ? `0 0 8px ${cfg.color}` : "none" }}>{r.prediction.toUpperCase().replace(/ /g, "_")}</span>
                          <DataSourceBadge source={r.data_source} />
                        </div>
                        <div style={{ fontSize: 10, opacity: 0.4, marginTop: 2 }}>{String(r.log.src_ip)}</div>
                        {r.geo?.country && <div style={{ fontSize: 9, opacity: 0.45, color: "#0047ab", marginTop: 1 }}>{r.geo.city ? `${r.geo.city}, ` : ""}{r.geo.country}</div>}
                        <div style={{ fontSize: 10, marginTop: 6, opacity: 0.55, lineHeight: 1.7 }}>
                          PORT:{r.log.port} | RATE:{r.log.packet_rate}<br />SIZE:{r.log.packet_size}
                          {r.packet_count && <><br />PKTS:{r.packet_count} | PORTS:{r.unique_ports}</>}
                        </div>
                        {isOpen && r.ai_explanation && (
                          <div style={{ marginTop: 10, padding: "10px 12px", border: `1px solid ${cfg.color}33`, background: "rgba(0,0,0,0.95)", fontSize: 10, lineHeight: 1.9, color: "rgba(255,255,255,0.65)", whiteSpace: "pre-wrap", animation: "fadeIn 0.2s ease" }}>
                            <div style={{ fontSize: 9, letterSpacing: 2, color: cfg.color, marginBottom: 8 }}>⬡ GEMINI_SOC_ANALYSIS</div>
                            {r.ai_explanation}
                          </div>
                        )}
                      </div>
                    )

                    const infoBox = (
                      <div onClick={() => setExpanded(isOpen ? null : i)} style={{ padding: "10px 12px", border: `1px solid ${isOpen ? cfg.color : "rgba(0,255,65,0.12)"}`, background: isOpen ? `${cfg.color}0a` : "rgba(0,255,65,0.01)", fontSize: 10, lineHeight: 1.8, cursor: r.ai_explanation ? "pointer" : "default", transition: "all 0.2s", animation: `fadeIn 0.3s ease ${Math.min(i * 0.04, 0.5)}s both` }}>
                        <span style={{ color: "#0047ab", fontWeight: 700 }}>THREAT_LVL:</span> {cfg.label}<br />
                        <span style={{ color: "#0047ab", fontWeight: 700 }}>SCORE:</span> {r.anomaly_score.toFixed(4)}<br />
                        <span style={{ color: "#0047ab", fontWeight: 700 }}>CONF:</span> {r.confidence}%
                        {r.duration_sec && <><br /><span style={{ color: "#0047ab", fontWeight: 700 }}>DUR:</span> {r.duration_sec}s</>}
                        {r.ai_explanation && <div style={{ marginTop: 4, color: cfg.color, fontSize: 9 }}>▾ CLICK FOR SOC_REPORT</div>}
                      </div>
                    )

                    return (
                      <div key={i} style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, opacity: r.threat_level === "low" ? 0.4 : 1 }}>
                        <div style={{ width: "44%", textAlign: left ? "right" : "left" }}>{left ? labelBox : infoBox}</div>
                        <div style={{ position: "relative", zIndex: 10, flexShrink: 0, marginTop: 4 }}><ThreatNode level={r.threat_level} active={isCrit} /></div>
                        <div style={{ width: "44%" }}>{left ? infoBox : labelBox}</div>
                      </div>
                    )
                  })}
                  <div ref={feedBottom} />
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Right panel — fixed meaningful charts */}
        <aside style={{ width: 280, display: "flex", flexDirection: "column", background: "rgba(0,0,0,0.92)", flexShrink: 0, borderLeft: "1px solid rgba(0,255,65,0.12)" }}>

          {/* Threat Velocity — meaningful bar chart */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", borderBottom: "1px solid rgba(0,255,65,0.12)" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(0,255,65,0.12)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ fontSize: 11, fontWeight: 700, color: "#fff", letterSpacing: 1 }}>THREAT_VELOCITY</span>
                <div style={{ fontSize: 8, opacity: 0.3, letterSpacing: 1, marginTop: 2 }}>THREAT LEVEL DISTRIBUTION</div>
              </div>
              <span style={{ fontSize: 10, color: liveMode ? "#ff2d55" : "rgba(0,255,65,0.4)" }}>{liveMode ? "● LIVE" : "STATIC"}</span>
            </div>
            <ThreatVelocityChart results={results} liveMode={liveMode} />
          </div>

          {/* Network Map — real IP nodes */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
            <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(0,255,65,0.12)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span style={{ fontSize: 11, fontWeight: 700, color: "#fff", letterSpacing: 1 }}>NETWORK_MAP</span>
                <div style={{ fontSize: 8, opacity: 0.3, letterSpacing: 1, marginTop: 2 }}>SOURCE IP THREAT TOPOLOGY</div>
              </div>
              {results.length > 0 && <span style={{ fontSize: 9, opacity: 0.35 }}>{new Set(results.map(r => r.log.src_ip)).size} IPs</span>}
            </div>
            <NetworkMap results={results} />
          </div>
        </aside>
      </main>

      {/* Command bar */}
      <footer style={{ flexShrink: 0, position: "relative", zIndex: 10 }}>
        {suggestions.length > 0 && (
          <div style={{ position: "absolute", bottom: 76, left: 48, right: 200, background: "#000", border: "1px solid rgba(0,255,65,0.22)", padding: "4px 0", fontSize: 11, zIndex: 10 }}>
            {/* Header with close button */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 16px 4px 16px", borderBottom: "1px solid rgba(0,255,65,0.1)", marginBottom: 2 }}>
              <span style={{ fontSize: 9, opacity: 0.3, letterSpacing: 1.5 }}>AUTOCOMPLETE</span>
              <span
                onClick={() => setSugg([])}
                style={{ cursor: "pointer", color: "#00ff41", opacity: 0.5, fontSize: 13, lineHeight: 1, padding: "0 2px" }}
                onMouseEnter={e => (e.currentTarget.style.opacity = "1")}
                onMouseLeave={e => (e.currentTarget.style.opacity = "0.5")}
              >✕</span>
            </div>
            {suggestions.map(s => (
              <div key={s} onClick={() => { setCmd(s); setSugg([]) }} style={{ padding: "5px 16px", cursor: "pointer", opacity: 0.8 }}
                onMouseEnter={e => (e.currentTarget.style.background = "rgba(0,255,65,0.06)")}
                onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>{s}</div>
            ))}
          </div>
        )}
        <div style={{ height: 52, borderTop: "2px solid rgba(0,255,65,0.6)", background: "#000", display: "flex", alignItems: "center", padding: "0 24px", boxShadow: "0 -4px 20px rgba(0,255,65,0.08)" }}>
          <span style={{ color: "#00ff41", fontWeight: 700, fontSize: 18, marginRight: 12, userSelect: "none" }}>▶</span>
          <input autoFocus value={cmd} onChange={e => handleCmdChange(e.target.value)} onKeyDown={handleCmd}
            style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "#00ff41", fontSize: 13, fontFamily: "inherit", caretColor: "#00ff41" }}
            placeholder="/analyze · /live --rate 0.5 · /filter --threat critical · /news · /assistant" />
          <div style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 10 }}>
            <span style={{ opacity: 0.3 }}>TAB autocomplete</span>
            <span style={{ background: "#00ff41", color: "#000", padding: "3px 10px", fontWeight: 700, fontSize: 11 }}>↵ ENTER</span>
          </div>
          <input ref={fileRef} type="file" accept=".csv,.pcap,.pcapng" style={{ display: "none" }} onChange={e => handleFileSelect(e.target.files?.[0] ?? null)} />
        </div>
        <div style={{ height: 24, background: "#000", borderTop: "1px solid rgba(0,255,65,0.06)", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 20px", fontSize: 9, opacity: 0.3 }}>
          <span>NETWORK HEALTH SENTINEL · IsolationForest v2 · Groq/Llama-3.3-70B · SSE</span>
          <span style={{ letterSpacing: 1 }}>BUILT BY <span style={{ color: "#00ff41", opacity: 1 }}>YOGITA SINGH</span></span>
          <span>BUILD 2.2.0 · 2025</span>
        </div>
      </footer>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,65,0.1); }
        input::placeholder { color: rgba(0,255,65,0.35); font-family:'Fira Code',monospace; }
        @keyframes nodePulse    { 0%,100%{opacity:1;} 50%{opacity:0.15;} }
        @keyframes scan         { 0%{transform:translateX(-100%);} 100%{transform:translateX(350%);} }
        @keyframes fadeIn       { from{opacity:0;transform:translateY(6px);} to{opacity:1;transform:translateY(0);} }
        @keyframes slideUp      { from{opacity:0;transform:translateY(14px);} to{opacity:1;transform:translateY(0);} }
        @keyframes headerScan   { 0%{transform:translateX(-100%);} 100%{transform:translateX(100vw);} }
        @keyframes assistantPulse { 0%,100%{box-shadow:0 0 10px rgba(0,255,65,0.12);} 50%{box-shadow:0 0 22px rgba(0,255,65,0.3);} }
        @keyframes critPulse    { 0%,100%{box-shadow:none;} 50%{box-shadow:0 0 10px rgba(255,45,85,0.18);} }
      `}</style>
    </div>
  )
}
