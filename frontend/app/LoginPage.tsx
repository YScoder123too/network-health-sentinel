"use client"

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
