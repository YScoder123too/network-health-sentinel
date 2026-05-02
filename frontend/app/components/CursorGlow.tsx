"use client"
import { useEffect, useRef } from "react"

// ─── Selectors that trigger the magnetic / enlarged cursor state ──────────────
const INTERACTIVE = "button, label, a, [role=button], nav div[style*='cursor']"

export default function CursorGlow() {
  const dotRef  = useRef<HTMLDivElement>(null)
  const ringRef = useRef<HTMLDivElement>(null)
  const glowRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // Raw mouse position (dot snaps here instantly — zero lag)
    let mx = 0, my = 0
    // Ring lags behind via lerp for the trailing feel
    let rx = 0, ry = 0
    // Whether we are currently hovering an interactive element
    let isHovering = false

    const dot  = dotRef.current!
    const ring = ringRef.current!
    const glow = glowRef.current!

    // ── Trail particles ──────────────────────────────────────────────────────
    const NUM = 8
    const trails: { el: HTMLDivElement; x: number; y: number }[] = []
    for (let i = 0; i < NUM; i++) {
      const t = document.createElement("div")
      Object.assign(t.style, {
        position:      "fixed",
        borderRadius:  "50%",
        pointerEvents: "none",
        zIndex:        "9994",
        transform:     "translate(-50%,-50%)",
        background:    "#00ff41",
        width:         `${3.5 - i * 0.28}px`,
        height:        `${3.5 - i * 0.28}px`,
        opacity:       `${((NUM - i) / NUM) * 0.3}`,
        filter:        "blur(0.4px)",
      })
      document.body.appendChild(t)
      trails.push({ el: t, x: 0, y: 0 })
    }

    // ── Mouse move — dot & glow are instant (no lerp) ────────────────────────
    const onMove = (e: MouseEvent) => {
      mx = e.clientX
      my = e.clientY

      // Dot is pinned exactly to mouse pointer — no lag, no offset
      dot.style.left = mx + "px"
      dot.style.top  = my + "px"

      // Ambient glow cloud follows instantly too
      glow.style.left = mx + "px"
      glow.style.top  = my + "px"
    }

    // ── Magnetic hover: detect interactive elements ──────────────────────────
    const onEnter = (e: MouseEvent) => {
      if (!(e.target instanceof Element)) return
      if (!e.target.closest(INTERACTIVE)) return
      isHovering = true

      // Dot grows into a soft filled disc
      dot.style.width       = "12px"
      dot.style.height      = "12px"
      dot.style.background  = "rgba(0,255,65,0.35)"
      dot.style.boxShadow   = "0 0 12px #00ff41, 0 0 28px rgba(0,255,65,0.5), 0 0 50px rgba(0,255,65,0.2)"
      dot.style.border      = "1.5px solid #00ff41"

      // Ring expands and brightens
      ring.style.width       = "46px"
      ring.style.height      = "46px"
      ring.style.borderColor = "rgba(0,255,65,1)"
      ring.style.boxShadow   = "0 0 10px rgba(0,255,65,0.4), inset 0 0 10px rgba(0,255,65,0.05)"
      ring.style.borderWidth = "1.5px"
    }

    const onLeave = (e: MouseEvent) => {
      if (!(e.target instanceof Element)) return
      if (!e.target.closest(INTERACTIVE)) return
      isHovering = false

      // Restore dot
      dot.style.width      = "6px"
      dot.style.height     = "6px"
      dot.style.background = "#00ff41"
      dot.style.boxShadow  = "0 0 6px #00ff41, 0 0 14px rgba(0,255,65,0.4)"
      dot.style.border     = "none"

      // Restore ring
      ring.style.width       = "28px"
      ring.style.height      = "28px"
      ring.style.borderColor = "rgba(0,255,65,0.5)"
      ring.style.boxShadow   = "none"
      ring.style.borderWidth = "1px"
    }

    // ── Click ripple ─────────────────────────────────────────────────────────
    const onClick = () => {
      dot.style.transform = "translate(-50%,-50%) scale(0.6)"
      ring.style.transform = "translate(-50%,-50%) scale(1.4)"
      ring.style.opacity = "0.4"
      setTimeout(() => {
        dot.style.transform  = "translate(-50%,-50%) scale(1)"
        ring.style.transform = "translate(-50%,-50%) scale(1)"
        ring.style.opacity   = "1"
      }, 150)
    }

    // ── Animation loop (ring + trails use lerp for fluid motion) ─────────────
    const lerp = (a: number, b: number, t: number) => a + (b - a) * t
    let raf: number
    const animate = () => {
      // Ring lerps toward mouse (trailing feel)
      const speed = isHovering ? 0.18 : 0.12
      rx = lerp(rx, mx, speed)
      ry = lerp(ry, my, speed)
      ring.style.left = rx + "px"
      ring.style.top  = ry + "px"

      // Particle trail — each follows the previous
      let px = mx, py = my
      trails.forEach(t => {
        t.x = lerp(t.x, px, 0.28)
        t.y = lerp(t.y, py, 0.28)
        t.el.style.left = t.x + "px"
        t.el.style.top  = t.y + "px"
        px = t.x; py = t.y
      })

      raf = requestAnimationFrame(animate)
    }
    animate()

    // ── Event listeners ──────────────────────────────────────────────────────
    document.addEventListener("mousemove",  onMove)
    document.addEventListener("mouseenter", onEnter, true)
    document.addEventListener("mouseleave", onLeave, true)
    document.addEventListener("mousedown",  onClick)

    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener("mousemove",  onMove)
      document.removeEventListener("mouseenter", onEnter, true)
      document.removeEventListener("mouseleave", onLeave, true)
      document.removeEventListener("mousedown",  onClick)
      trails.forEach(t => t.el.remove())
    }
  }, [])

  return (
    <>
      {/*
        cursor: none on EVERY element — the `body` selector alone is not
        enough because some browsers let child elements re-declare cursor.
        We also override SVG and input to be safe.
      */}
      <style>{`
        *, *::before, *::after {
          cursor: none !important;
        }
      `}</style>

      {/* ── Core dot — pinned exactly to mouse, zero lag ── */}
      <div
        ref={dotRef}
        style={{
          position:      "fixed",
          width:         6,
          height:        6,
          background:    "#00ff41",
          borderRadius:  "50%",
          pointerEvents: "none",          // never blocks clicks
          transform:     "translate(-50%,-50%)",
          zIndex:        9999,
          boxShadow:     "0 0 6px #00ff41, 0 0 14px rgba(0,255,65,0.4)",
          filter:        "drop-shadow(0 0 4px rgba(0,255,65,0.9))",
          transition:    "width .15s ease, height .15s ease, background .15s ease, box-shadow .15s ease",
          willChange:    "left, top",
        }}
      />

      {/* ── Lagging outer ring ── */}
      <div
        ref={ringRef}
        style={{
          position:      "fixed",
          width:         28,
          height:        28,
          border:        "1px solid rgba(0,255,65,0.5)",
          borderRadius:  "50%",
          pointerEvents: "none",          // never blocks clicks
          transform:     "translate(-50%,-50%)",
          zIndex:        9998,
          filter:        "drop-shadow(0 0 3px rgba(0,255,65,0.3))",
          transition:    "width .2s ease, height .2s ease, border-color .2s ease, box-shadow .2s ease, opacity .15s ease",
          willChange:    "left, top",
        }}
      />

      {/* ── Soft ambient glow cloud ── */}
      <div
        ref={glowRef}
        style={{
          position:      "fixed",
          width:         320,
          height:        320,
          borderRadius:  "50%",
          background:    "radial-gradient(circle, rgba(0,255,65,0.06) 0%, rgba(0,255,65,0.015) 45%, transparent 70%)",
          pointerEvents: "none",          // never blocks clicks
          transform:     "translate(-50%,-50%)",
          zIndex:        9990,
          willChange:    "left, top",
        }}
      />
    </>
  )
}