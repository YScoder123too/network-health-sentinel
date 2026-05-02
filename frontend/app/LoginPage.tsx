// i havt to do lil changes in my ui, nd try run this at the end,
//   my requirements are:

// ================================================================
// NETWORK HEALTH SENTINEL — LANDING PAGE (UPLOAD VIEW) UI OVERHAUL
// FILE CHANGED: frontend/app/page.tsx
// ================================================================

// SUMMARY
// -------
// The upload/landing screen (activeView === "upload" && !loading block) was
// completely redesigned. The old UI was a single plain dashed-border box with
// an emoji icon, two lines of text, and three small buttons. The new UI is a
// full cinematic hero landing page with multiple visual layers, while keeping
// 100% of the original logic (file select, drag-drop, runAnalysis, startLiveStream).


// ================================================================
// SECTION 1 — CONTAINER
// ================================================================
// - maxWidth increased from 520px → 680px to give more breathing room.
// - marginTop reduced from 32px → 16px so the hero fills the viewport better.
// - Entrance animation: fadeIn 0.5s ease (was 0.4s).


// ================================================================
// SECTION 2 — HERO TITLE BLOCK (NEW — did not exist before)
// ================================================================
// Added a full title/branding block above the upload card:

//   2a. Decorative horizontal rule
//       - A flex row: gradient line → centered label text → gradient line.
//       - Label: "NETWORK HEALTH SENTINEL" in 9px, letterSpacing 3, green tint.
//       - Lines fade from transparent → rgba(0,255,65,0.3) on each side.

//   2b. Main H1 Headline
//       - Font size 42px, fontWeight 700, letterSpacing -1, white color.
//       - Text reads: "AI-Powered Intrusion\nDetection System"
//       - The word "Intrusion" is highlighted in #00ff41 (green) with a glowing
//         textShadow: "0 0 30px rgba(0,255,65,0.4), 0 0 60px rgba(0,255,65,0.15)"
//       - A 2px animated gradient line sits 6px below the headline (bottom accent),
//         using the existing "scan" keyframe animation (4s linear infinite).
//         Gradient: transparent → #00ff41 → #0047ab → transparent.

//   2c. Subtitle paragraph
//       - 12px, letterSpacing 2, rgba(255,255,255,0.35).
//       - Text: "IsolationForest v2 · Gemini SOC Analysis · Real-Time Geo-Intelligence"
//       - marginTop 18px.

//   2d. Animated Stat Pills row
//       Four inline stat chips displayed in a centered flex row, each staggered
//       with a fadeIn animation delay (0ms, 80ms, 160ms, 240ms):
//         ┌──────────────────────────────────────────┐
//         │  10s  SOC REPORT  │  7  ML FEATURES      │
//         │  ₹0   COST        │  L1+L2  TIERS AUTO   │
//         └──────────────────────────────────────────┘
//       Each chip: padding 5px 14px, border 1px solid {color}28, bg {color}08.
//       Value in 14px bold colored text, label in 9px letterSpacing 1.5 muted.
//       Colors: green (#00ff41), blue (#0047ab), gold (#ffd700), orange (#ff6b35).


// ================================================================
// SECTION 3 — UPLOAD CARD (redesigned)
// ================================================================

//   3a. Scanline overlay
//       A full-cover pseudo-overlay div (position absolute, inset 0, zIndex 2,
//       pointerEvents none) applies a CSS repeating-linear-gradient scanline
//       texture: alternating 3px transparent / 1px rgba(0,255,65,0.012) strips.
//       Gives a subtle CRT / terminal monitor feel to the entire card.

//   3b. Drop zone container
//       - Removed the old "1px dashed" border.
//       - New: "1px solid rgba(0,255,65,0.25)", solid not dashed.
//       - Background: rgba(0,0,0,0.6) — darker, more cinematic.
//       - Padding: 36px 40px.
//       - onDragOver: border snaps to rgba(0,255,65,0.7), bg → rgba(0,255,65,0.04)
//       - onDragLeave: resets.
//       - onDrop: calls handleFileSelect with dropped file (NEW — drag-drop now works).

//   3c. Corner accents
//       Previously: 14×14px hairline corners, 1px, faint.
//       Now: 20×20px corners, 2px solid #00ff41 — bold, sharp, clearly visible.
//       All four corners (top-left, top-right, bottom-left, bottom-right).

//   3d. Background concentric circles (NEW)
//       Two decorative concentric circle divs centered in the card:
//         - Outer: 300×300px, border 1px solid rgba(0,255,65,0.04), border-radius 50%
//         - Inner: 180×180px, border 1px solid rgba(0,255,65,0.06), border-radius 50%
//       Gives a radar/targeting reticle feel behind the content.

//   3e. DEFAULT STATE (no file selected)
//       Old: plain 📂 emoji + one line of text.
//       New:

//         i.  Animated SVG Shield icon (64×72px):
//             - Outer shield path: stroke #00ff41, fill rgba(0,255,65,0.04)
//             - Inner shield path: stroke rgba(0,255,65,0.25)
//             - Center circle: stroke #00ff41, fill rgba(0,255,65,0.08),
//               animated with nodePulse 2s infinite
//             - Checkmark path inside circle: stroke #00ff41, strokeWidth 1.5
//             - filter: drop-shadow(0 0 16px rgba(0,255,65,0.35))
//             - Surrounding orbit ring: 90×90px dashed circle, rgba(0,255,65,0.12)

//         ii. Instruction text:
//             "Drop your firewall log or Wireshark capture" — 13px, 40% white
//             "SUPPORTS: .CSV · .PCAP · .PCAPNG" — 10px, colored per format

//         iii. SELECT_FILE button (label):
//              - padding 11px 28px (was 9px 20px)
//              - border 1px solid rgba(0,255,65,0.4)
//              - color #00ff41, background rgba(0,255,65,0.04)
//              - fontWeight 700, letterSpacing 2
//              - Hover: bg → rgba(0,255,65,0.10), border → rgba(0,255,65,0.8)
//              - Text: "↑ SELECT_FILE" (upload arrow prefix added)

//         iv. LIVE_MONITOR button:
//              - padding 11px 28px (was 9px 24px)
//              - border 1px solid rgba(255,45,85,0.5) — brighter red
//              - Hover: bg → rgba(255,45,85,0.14), border → rgba(255,45,85,0.9)
//              - fontWeight 700, letterSpacing 2
//              - Still animated with critPulse 3s ease-in-out infinite

//   3f. FILE SELECTED STATE (file !== null)
//       Old: shows filename + 3 buttons in one row.
//       New:

//         i.  File type emoji (36px) with fadeIn 0.3s animation.

//         ii. Filename in 15px bold, colored by type (green=CSV, blue=PCAP),
//             letterSpacing 1.

//         iii. File metadata line: "{X} KB · PCAP CAPTURE / CSV LOG FILE"
//              10px, rgba(255,255,255,0.3), letterSpacing 2.

//         iv.  "● READY TO ANALYZE" status badge:
//              Inline-block, padding 2px 12px, border 1px solid {color}55,
//              animated with nodePulse 2s infinite. Color matches file type.

//         v.   CHANGE_FILE label button:
//              - Style: muted white text, faint green border.
//              - Hover: bg → rgba(0,255,65,0.05), text → #00ff41.
//              - Text: "↺ CHANGE_FILE"

//         vi.  RUN_ANALYSIS / PARSE_PCAP button (primary CTA):
//              - padding 10px 32px — larger than before.
//              - border 2px solid #00ff41 — thick, prominent.
//              - background rgba(0,255,65,0.1)
//              - boxShadow: "0 0 20px rgba(0,255,65,0.15), inset 0 0 20px rgba(0,255,65,0.04)"
//              - Hover: bg brighter, shadow intensifies to 0 0 30px rgba(0,255,65,0.3)
//              - fontWeight 700, letterSpacing 2.


// ================================================================
// SECTION 4 — FEATURE CARDS ROW (NEW — did not exist before)
// ================================================================
// A 3-column CSS grid of feature highlight cards below the upload card:

//   Card 1 — MITRE ATT&CK  (color: #00ff41)
//     Icon: ⬡
//     Desc: "Auto-mapped to attack framework with tactic & technique IDs"

//   Card 2 — GEO-INTEL  (color: #0047ab)
//     Icon: ◈
//     Desc: "Source IP geolocation — country, city, ISP per threat event"

//   Card 3 — SOC REPORTS  (color: #ff6b35)
//     Icon: ▶
//     Desc: "AI-generated PDF incident reports in under 10 seconds"

//   Each card:
//   - padding 14px 16px
//   - border 1px solid {color}20, bg {color}04
//   - Staggered fadeIn animations (delay: 100ms, 180ms, 260ms)
//   - Hover: border → {color}45, bg → {color}08
//   - Icon: 16px colored, marginBottom 6px
//   - Title: 10px, fontWeight 700, letterSpacing 2, colored
//   - Desc: 9px, rgba(255,255,255,0.3), lineHeight 1.8


// ================================================================
// SECTION 5 — SPEC STRIP (redesigned footer row)
// ================================================================
// Old: 4 lines of plain 10px opacity-0.25 text stacked vertically.
// New: A single horizontal flex row with a top and bottom border:

//   - borderTop + borderBottom: 1px solid rgba(0,255,65,0.08)
//   - padding 12px 0
//   - Three inline label:value pairs side by side:
//       CSV_COLS:  src_ip · port · packet_rate · packet_size
//       MODEL:     IsolationForest · 200 est
//       AI_LAYER:  Gemini-1.5-flash
//   - Labels in rgba(0,71,171,0.7) (blue tint), letterSpacing 1.5
//   - Values in rgba(255,255,255,0.25), letterSpacing 0.5
//   - flexWrap: wrap for narrow screens


// ================================================================
// WHAT WAS NOT CHANGED (logic fully preserved)
// ================================================================
// - fileRef, handleFileSelect, runAnalysis, startLiveStream — all intact.
// - File input element (accept=".csv,.pcap,.pcapng") — unchanged.
// - isPcap() check for conditional labels — unchanged.
// - All existing CSS keyframe animations reused (fadeIn, nodePulse,
//   critPulse, scan, headerScan, assistantPulse).
// - All other views (threat_feed, loading, summary, timeline) — unchanged.
// - Sidebar, header, footer command bar, right panel — unchanged.
// - ParticleCanvas, NewsPanel, AIAssistant — unchanged.


// ================================================================
// HOW TO APPLY IN VS CODE / CODEX
// ================================================================
// Target file:  frontend/app/page.tsx

// Find the block:
//   {activeView === "upload" && !loading && (
//     <div style={{ width: "100%", maxWidth: 520, marginTop: 32 ...

// Replace the entire block (ending at the closing </div> before the
// loading spinner block) with the new hero markup described above.

// The replacement ends just before:
//   {loading && results.length === 0 && (

// Everything outside the upload block is untouched.
// ================================================================"use client"

import { useState, useEffect, useRef } from "react"

interface LoginPageProps {
  onLogin: (token: string) => void
}

const BOOT_LINES = [
  "BIOS_v2.1 ... OK",
  "LOADING KERNEL MODULES ...",
  "net.ipv4.tcp_syncookies = 1",
  "INITIALIZING ISOLATION_FOREST_v2 ...",
  "LOADING SCALER.PKL ... OK",
  "GEMINI_CLIENT: CONNECTING ...",
  "GEMINI_CLIENT: AUTHENTICATED",
  "SSE_ENGINE: ARMED",
  "THREAT_CLASSIFIER: 7 FEATURES READY",
  "ALL SYSTEMS NOMINAL — AUTHENTICATE TO CONTINUE",
]

const TICKER = [
  "[SECURE] AES-256 ENCRYPTED CHANNEL",
  "[AUTH] JWT RS256 TOKEN REQUIRED",
  "[SYSTEM] SENTINEL_ROOT_v2.2 READY",
  "[ACTIVE] ANOMALY_DETECTOR: ARMED",
  "[SECURE] SESSION_TIMEOUT: 60MIN",
]

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [bootLines, setBootLines]   = useState<string[]>([])
  const [bootDone, setBootDone]     = useState(false)
  const [username, setUsername]     = useState("")
  const [password, setPassword]     = useState("")
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState<string | null>(null)
  const [time, setTime]             = useState("")
  const [tickerIdx, setTickerIdx]   = useState(0)
  const [showCursor, setShowCursor] = useState(true)
  const [phase, setPhase]           = useState<"boot" | "login">("boot")
  const [scanLine, setScanLine]     = useState(0)
  const userRef = useRef<HTMLInputElement>(null)

  // Clock
  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toUTCString().slice(17, 25)), 1000)
    return () => clearInterval(t)
  }, [])

  // Cursor blink
  useEffect(() => {
    const t = setInterval(() => setShowCursor(p => !p), 530)
    return () => clearInterval(t)
  }, [])

  // Boot sequence
  useEffect(() => {
    let i = 0
    const interval = setInterval(() => {
      if (i < BOOT_LINES.length && BOOT_LINES[i] !== undefined) {
        const line = BOOT_LINES[i]
        setBootLines(prev => [...prev, line])
        i++
      } else {
        clearInterval(interval)
        setTimeout(() => { setBootDone(true); setPhase("login") }, 600)
      }
    }, 180)
    return () => clearInterval(interval)
  }, [])

  // Auto-focus username after boot
  useEffect(() => {
    if (phase === "login") setTimeout(() => userRef.current?.focus(), 100)
  }, [phase])

  // Ticker
  useEffect(() => {
    const t = setInterval(() => setTickerIdx(p => (p + 1) % TICKER.length), 2800)
    return () => clearInterval(t)
  }, [])

  // Scan line animation
  useEffect(() => {
    const t = setInterval(() => setScanLine(p => (p + 1) % 100), 30)
    return () => clearInterval(t)
  }, [])

  async function handleLogin() {
    if (!username || !password) {
      setError("ERR: CREDENTIALS_REQUIRED — both fields must be populated")
      return
    }
    setLoading(true)
    setError(null)

    try {
      const form = new URLSearchParams()
      form.append("username", username)
      form.append("password", password)

      const res = await fetch("http://localhost:8000/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail || "AUTH_REJECTED")
      }

      const data = await res.json()
      onLogin(data.access_token)
    } catch (e: unknown) {
      setError(`ERR: ${e instanceof Error ? e.message.toUpperCase() : "AUTH_FAILED"}`)
    } finally {
      setLoading(false)
    }
  }

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === "Enter") handleLogin()
  }

  const inputStyle = (focused: boolean): React.CSSProperties => ({
    width: "100%",
    background: "transparent",
    border: "none",
    borderBottom: `1px solid ${focused ? "#00ff41" : "rgba(0,255,65,0.3)"}`,
    outline: "none",
    color: "#00ff41",
    fontSize: 13,
    fontFamily: "'Fira Code', monospace",
    padding: "8px 0",
    letterSpacing: 1,
    caretColor: "#00ff41",
  })

  const [userFocused, setUserFocused] = useState(false)
  const [passFocused, setPassFocused] = useState(false)

  return (
    <div style={{
      background: "#000",
      color: "#00ff41",
      fontFamily: "'Fira Code', monospace",
      height: "100vh",
      display: "flex",
      flexDirection: "column",
      overflow: "hidden",
      position: "relative",
    }}>

      {/* Scan line effect */}
      <div style={{
        position: "absolute",
        top: `${scanLine}%`,
        left: 0,
        right: 0,
        height: 2,
        background: "rgba(0,255,65,0.03)",
        pointerEvents: "none",
        zIndex: 1,
        transition: "top 0.03s linear",
      }} />

      {/* CRT vignette */}
      <div style={{
        position: "absolute",
        inset: 0,
        background: "radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.7) 100%)",
        pointerEvents: "none",
        zIndex: 2,
      }} />

      {/* Ticker */}
      <header style={{
        height: 40,
        borderBottom: "1px solid rgba(0,255,65,0.3)",
        background: "#000",
        display: "flex",
        alignItems: "center",
        padding: "0 16px",
        flexShrink: 0,
        gap: 16,
        overflow: "hidden",
        position: "relative",
        zIndex: 10,
      }}>
        <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, whiteSpace: "nowrap" }}>⬡ SYSTEM_LOG:</span>
        <span style={{ fontSize: 10, opacity: 0.7, whiteSpace: "nowrap" }}>{TICKER[tickerIdx]}</span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 20, fontSize: 11, flexShrink: 0, opacity: 0.6 }}>
          <span style={{ color: "#ff2d55" }}>● LOCKED</span>
          <span style={{ color: "#fff" }}>UTC {time}</span>
        </div>
      </header>

      {/* Main */}
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", position: "relative", zIndex: 10 }}>

        {/* Grid background */}
        <div style={{
          position: "absolute",
          inset: 0,
          backgroundImage: `
            linear-gradient(rgba(0,255,65,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,65,0.03) 1px, transparent 1px)
          `,
          backgroundSize: "40px 40px",
          pointerEvents: "none",
        }} />

        <div style={{ width: "100%", maxWidth: 560, padding: "0 24px", position: "relative" }}>

          {/* Corner decorations */}
          {[
            { top: -20, left: -20 },
            { top: -20, right: -20 },
            { bottom: -20, left: -20 },
            { bottom: -20, right: -20 },
          ].map((pos, i) => (
            <div key={i} style={{
              position: "absolute",
              ...pos,
              width: 20, height: 20,
              borderTop: i < 2 ? "1px solid rgba(0,255,65,0.4)" : "none",
              borderBottom: i >= 2 ? "1px solid rgba(0,255,65,0.4)" : "none",
              borderLeft: i % 2 === 0 ? "1px solid rgba(0,255,65,0.4)" : "none",
              borderRight: i % 2 === 1 ? "1px solid rgba(0,255,65,0.4)" : "none",
            }} />
          ))}

          {/* Header */}
          <div style={{ textAlign: "center", marginBottom: 40 }}>
            <div style={{
              fontSize: 11,
              letterSpacing: 4,
              opacity: 0.4,
              marginBottom: 12,
            }}>NETWORK HEALTH SENTINEL</div>
            <div style={{
              fontSize: 28,
              fontWeight: 700,
              letterSpacing: 3,
              color: "#fff",
              textShadow: "0 0 30px rgba(0,255,65,0.4)",
              marginBottom: 6,
            }}>SENTINEL_ROOT</div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
              <div style={{ height: 1, width: 60, background: "rgba(0,255,65,0.2)" }} />
              <span style={{ fontSize: 10, letterSpacing: 3, opacity: 0.5 }}>v2.2</span>
              <div style={{ height: 1, width: 60, background: "rgba(0,255,65,0.2)" }} />
            </div>
          </div>

          {/* Boot terminal */}
          <div style={{
            border: "1px solid rgba(0,255,65,0.2)",
            background: "rgba(0,255,65,0.02)",
            padding: "16px 18px",
            marginBottom: 28,
            minHeight: 180,
            position: "relative",
            overflow: "hidden",
          }}>
            <div style={{
              position: "absolute",
              top: 0, left: 0, right: 0,
              height: 28,
              background: "rgba(0,255,65,0.05)",
              borderBottom: "1px solid rgba(0,255,65,0.15)",
              display: "flex",
              alignItems: "center",
              padding: "0 12px",
              gap: 8,
            }}>
              {["#ff2d55", "#ffd700", "#00ff41"].map((c, i) => (
                <div key={i} style={{ width: 8, height: 8, borderRadius: "50%", background: c, opacity: 0.7 }} />
              ))}
              <span style={{ fontSize: 9, letterSpacing: 2, opacity: 0.4, marginLeft: 8 }}>BOOT_SEQUENCE.sh</span>
            </div>

            <div style={{ marginTop: 28, fontSize: 11, lineHeight: 1.9, letterSpacing: 0.5 }}>
              {bootLines.filter(Boolean).map((line, i) => (
                <div key={i} style={{
                  color: line.includes("OK") ? "#00ff41"
                       : line.includes("ERR") ? "#ff2d55"
                       : line.includes("WARN") ? "#ffd700"
                       : "rgba(0,255,65,0.65)",
                  display: "flex",
                  gap: 10,
                }}>
                  <span style={{ opacity: 0.3, userSelect: "none" }}>$</span>
                  {line}
                </div>
              ))}
              {!bootDone && (
                <span style={{ opacity: showCursor ? 1 : 0, color: "#00ff41" }}>█</span>
              )}
            </div>
          </div>

          {/* Auth form */}
          {phase === "login" && (
            <div style={{
              border: "1px solid rgba(0,255,65,0.25)",
              background: "rgba(0,0,0,0.8)",
              padding: "28px 28px 24px",
              position: "relative",
            }}>
              {/* Label */}
              <div style={{
                position: "absolute",
                top: -10,
                left: 20,
                background: "#000",
                padding: "0 8px",
                fontSize: 10,
                letterSpacing: 3,
                color: "rgba(0,255,65,0.6)",
              }}>AUTH_REQUIRED</div>

              {/* Username */}
              <div style={{ marginBottom: 24 }}>
                <div style={{ fontSize: 9, letterSpacing: 3, opacity: 0.4, marginBottom: 8 }}>
                  OPERATOR_ID
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ opacity: 0.4, fontSize: 13 }}>▶</span>
                  <input
                    ref={userRef}
                    type="text"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    onFocus={() => setUserFocused(true)}
                    onBlur={() => setUserFocused(false)}
                    onKeyDown={handleKey}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="enter operator id..."
                    style={{
                      ...inputStyle(userFocused),
                      "WebkitTextFillColor": "#00ff41",
                    } as React.CSSProperties}
                  />
                </div>
              </div>

              {/* Password */}
              <div style={{ marginBottom: 28 }}>
                <div style={{ fontSize: 9, letterSpacing: 3, opacity: 0.4, marginBottom: 8 }}>
                  ACCESS_KEY
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ opacity: 0.4, fontSize: 13 }}>▶</span>
                  <input
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    onFocus={() => setPassFocused(true)}
                    onBlur={() => setPassFocused(false)}
                    onKeyDown={handleKey}
                    placeholder="enter access key..."
                    style={inputStyle(passFocused)}
                  />
                </div>
              </div>

              {/* Error */}
              {error && (
                <div style={{
                  fontSize: 10,
                  color: "#ff2d55",
                  background: "rgba(255,45,85,0.08)",
                  border: "1px solid rgba(255,45,85,0.25)",
                  padding: "8px 12px",
                  marginBottom: 20,
                  letterSpacing: 0.5,
                  lineHeight: 1.6,
                }}>
                  {error}
                </div>
              )}

              {/* Submit */}
              <button
                onClick={handleLogin}
                disabled={loading}
                style={{
                  width: "100%",
                  padding: "12px 0",
                  background: loading ? "rgba(0,255,65,0.05)" : "rgba(0,255,65,0.08)",
                  border: `1px solid ${loading ? "rgba(0,255,65,0.15)" : "rgba(0,255,65,0.5)"}`,
                  color: loading ? "rgba(0,255,65,0.4)" : "#00ff41",
                  fontSize: 12,
                  letterSpacing: 4,
                  fontFamily: "'Fira Code', monospace",
                  cursor: loading ? "not-allowed" : "pointer",
                  fontWeight: 700,
                  transition: "all 0.2s",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                {loading ? (
                  <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                    <span style={{ animation: "nodePulse 0.8s infinite" }}>█</span>
                    AUTHENTICATING...
                    <span style={{ animation: "nodePulse 0.8s infinite 0.4s" }}>█</span>
                  </span>
                ) : (
                  "▶ AUTHENTICATE"
                )}
              </button>

              {/* Footer hint */}
              <div style={{
                marginTop: 16,
                fontSize: 9,
                opacity: 0.25,
                textAlign: "center",
                letterSpacing: 1,
                lineHeight: 2,
              }}>
                AUTHORIZED PERSONNEL ONLY · SESSION EXPIRES IN 60MIN<br />
                ALL ACCESS ATTEMPTS ARE LOGGED AND MONITORED
              </div>
            </div>
          )}

          {/* Status bar */}
          <div style={{
            marginTop: 20,
            display: "flex",
            justifyContent: "space-between",
            fontSize: 9,
            opacity: 0.25,
            letterSpacing: 1,
          }}>
            <span>ISOLATION_FOREST_v2 · 7 FEATURES</span>
            <span>NODE_ENV: PRODUCTION</span>
            <span>TLS 1.3</span>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer style={{
        height: 36,
        borderTop: "1px solid rgba(0,255,65,0.2)",
        display: "flex",
        alignItems: "center",
        padding: "0 20px",
        justifyContent: "space-between",
        fontSize: 9,
        opacity: 0.3,
        flexShrink: 0,
        position: "relative",
        zIndex: 10,
      }}>
        <span>NETWORK HEALTH SENTINEL © 2025</span>
        <span>GEMINI_AI · ISOLATION_FOREST · SSE_STREAM</span>
        <span>BUILD 2.2.0</span>
      </footer>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-thumb { background: rgba(0,255,65,0.15); }
        @keyframes nodePulse { 0%,100%{opacity:1;} 50%{opacity:0.2;} }
        input::placeholder { color: rgba(0,255,65,0.2); font-family: 'Fira Code', monospace; }
        input:-webkit-autofill {
          -webkit-box-shadow: 0 0 0 1000px black inset !important;
          -webkit-text-fill-color: #00ff41 !important;
        }
      `}</style>
    </div>
  )
}
