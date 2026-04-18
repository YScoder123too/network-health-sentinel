"use client"
import { useEffect, useRef } from "react"

export default function CursorGlow() {
  const dotRef  = useRef<HTMLDivElement>(null)
  const ringRef = useRef<HTMLDivElement>(null)
  const glowRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let mx = 0, my = 0, rx = 0, ry = 0
    const dot = dotRef.current!, ring = ringRef.current!, glow = glowRef.current!
    const NUM = 8
    const trails: { el: HTMLDivElement; x: number; y: number }[] = []

    for (let i = 0; i < NUM; i++) {
      const t = document.createElement("div")
      Object.assign(t.style, {
        position: "fixed", borderRadius: "50%", pointerEvents: "none",
        zIndex: "9997", transform: "translate(-50%,-50%)",
        background: "#00ff41",
        width: `${4 - i * 0.3}px`, height: `${4 - i * 0.3}px`,
        opacity: `${(NUM - i) / NUM * 0.35}`,
      })
      document.body.appendChild(t)
      trails.push({ el: t, x: 0, y: 0 })
    }

    const onMove = (e: MouseEvent) => {
      mx = e.clientX; my = e.clientY
      dot.style.left = mx + "px"; dot.style.top = my + "px"
      glow.style.left = mx + "px"; glow.style.top = my + "px"
    }

    const onEnter = (e: MouseEvent) => {
      const el = (e.target as HTMLElement)
      if (el.closest("button,label,[role=button]")) {
        dot.style.width = dot.style.height = "10px"
        ring.style.width = ring.style.height = "40px"
        ring.style.borderColor = "rgba(0,255,65,0.9)"
      }
    }
    const onLeave = (e: MouseEvent) => {
      const el = (e.target as HTMLElement)
      if (el.closest("button,label,[role=button]")) {
        dot.style.width = dot.style.height = "6px"
        ring.style.width = ring.style.height = "28px"
        ring.style.borderColor = "rgba(0,255,65,0.5)"
      }
    }

    const lerp = (a: number, b: number, t: number) => a + (b - a) * t
    let raf: number
    const animate = () => {
      rx = lerp(rx, mx, 0.12); ry = lerp(ry, my, 0.12)
      ring.style.left = rx + "px"; ring.style.top = ry + "px"
      let px = mx, py = my
      trails.forEach(t => {
        t.x = lerp(t.x, px, 0.3); t.y = lerp(t.y, py, 0.3)
        t.el.style.left = t.x + "px"; t.el.style.top = t.y + "px"
        px = t.x; py = t.y
      })
      raf = requestAnimationFrame(animate)
    }
    animate()

    document.addEventListener("mousemove", onMove)
    document.addEventListener("mouseenter", onEnter, true)
    document.addEventListener("mouseleave", onLeave, true)
    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener("mousemove", onMove)
      document.removeEventListener("mouseenter", onEnter, true)
      document.removeEventListener("mouseleave", onLeave, true)
      trails.forEach(t => t.el.remove())
    }
  }, [])

  return (
    <>
      <style>{`body { cursor: none !important; } button, label, a { cursor: none !important; }`}</style>
      <div ref={dotRef} style={{ position:"fixed", width:6, height:6, background:"#00ff41", borderRadius:"50%", pointerEvents:"none", transform:"translate(-50%,-50%)", zIndex:9999, boxShadow:"0 0 6px #00ff41, 0 0 14px rgba(0,255,65,0.4)", transition:"width .15s,height .15s" }} />
      <div ref={ringRef} style={{ position:"fixed", width:28, height:28, border:"1px solid rgba(0,255,65,0.5)", borderRadius:"50%", pointerEvents:"none", transform:"translate(-50%,-50%)", zIndex:9998, transition:"width .2s,height .2s,border-color .2s" }} />
      <div ref={glowRef} style={{ position:"fixed", width:280, height:280, borderRadius:"50%", background:"radial-gradient(circle, rgba(0,255,65,0.07) 0%, rgba(0,255,65,0.02) 50%, transparent 70%)", pointerEvents:"none", transform:"translate(-50%,-50%)", zIndex:9990 }} />
    </>
  )
}