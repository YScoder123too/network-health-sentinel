"""
app/news.py  —  Live threat intel news feed
Uses NewsData.io free tier (200 req/day, no credit card).
1. Go to https://newsdata.io  →  Sign up free  →  Copy your API key
2. Add to .env:  NEWSDATA_API_KEY=pub_...
"""

import os
import httpx
from fastapi import APIRouter
from functools import lru_cache
import time

news_router = APIRouter(prefix="/news", tags=["news"])

NEWSDATA_API_KEY = os.getenv("NEWSDATA_API_KEY", "")

# Tag mapping based on keywords in the title
TAG_RULES = [
    (["ransomware", "malware", "trojan", "worm", "botnet"],          "MALWARE",  "#ff2d55"),
    (["ddos", "denial of service", "flood"],                          "DDOS",     "#ff2d55"),
    (["apt", "nation state", "north korea", "russia", "china", "iran"], "APT",   "#ff6b35"),
    (["vulnerability", "cve", "zero-day", "patch", "exploit"],       "CVE",      "#ffd700"),
    (["phishing", "social engineering", "credential"],                "PHISHING", "#ffd700"),
    (["ai", "llm", "machine learning", "neural", "gpt", "openai",
      "deepmind", "anthropic", "gemini", "claude"],                   "AI/ML",    "#00ff41"),
    (["quantum", "cryptography", "encryption", "tls", "ssl"],        "CRYPTO",   "#0047ab"),
    (["breach", "leak", "stolen", "exposed", "data"],                 "BREACH",   "#ff2d55"),
    (["policy", "regulation", "gdpr", "law", "government", "act"],   "POLICY",   "#0047ab"),
    (["research", "paper", "study", "university", "arxiv"],          "RESEARCH", "#ffd700"),
]

FALLBACK_NEWS = [
    {"title": "CISA warns of active exploitation of Cisco IOS XE vulnerability", "source": "The Hacker News", "tag": "CVE",      "color": "#ffd700", "url": "https://thehackernews.com", "time": "recent"},
    {"title": "Ransomware group claims 2.5TB breach of US healthcare provider",   "source": "BleepingComputer","tag": "BREACH",   "color": "#ff2d55", "url": "https://bleepingcomputer.com","time": "recent"},
    {"title": "New LLM jailbreak technique bypasses safety filters in AI models",  "source": "Wired",           "tag": "AI/ML",    "color": "#00ff41", "url": "https://wired.com",           "time": "recent"},
    {"title": "NIST finalizes post-quantum cryptography standards",                "source": "NIST",            "tag": "CRYPTO",   "color": "#0047ab", "url": "https://nist.gov",            "time": "recent"},
    {"title": "North Korean APT group deploys novel supply chain attack vector",   "source": "Mandiant",        "tag": "APT",      "color": "#ff6b35", "url": "https://mandiant.com",        "time": "recent"},
    {"title": "Cloudflare mitigates largest recorded DDoS attack at 5.6 Tbps",    "source": "Cloudflare Blog", "tag": "DDOS",     "color": "#ff2d55", "url": "https://blog.cloudflare.com", "time": "recent"},
    {"title": "EU AI Act enforcement begins — fines up to €35M for violations",   "source": "Reuters",         "tag": "POLICY",   "color": "#0047ab", "url": "https://reuters.com",         "time": "recent"},
    {"title": "New side-channel attack targets AMD Zen 4 processors",             "source": "ArXiv",           "tag": "RESEARCH", "color": "#ffd700", "url": "https://arxiv.org",           "time": "recent"},
]

# Simple in-memory cache — refresh every 30 minutes to conserve free tier quota
_cache: dict = {"data": None, "fetched_at": 0}
CACHE_TTL = 1800  # 30 minutes


def _tag_article(title: str) -> tuple[str, str]:
    t = title.lower()
    for keywords, tag, color in TAG_RULES:
        if any(k in t for k in keywords):
            return tag, color
    return "CYBERSEC", "#00ff41"


def _fmt_time(published: str) -> str:
    """Convert ISO timestamp to relative label."""
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        diff = datetime.now(timezone.utc) - dt
        h = int(diff.total_seconds() // 3600)
        if h < 1:   return "just now"
        if h < 24:  return f"{h}h ago"
        return f"{h // 24}d ago"
    except Exception:
        return "recent"


@news_router.get("")
async def get_news():
    """
    Returns up to 10 live cybersecurity + AI news articles.
    Falls back to curated static headlines if API key is missing or quota hit.
    Results are cached for 30 minutes.
    """
    global _cache

    # Return cache if still fresh
    if _cache["data"] and (time.time() - _cache["fetched_at"]) < CACHE_TTL:
        return {"articles": _cache["data"], "source": "live"}

    if not NEWSDATA_API_KEY:
        return {"articles": FALLBACK_NEWS, "source": "static"}

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(
                "https://newsdata.io/api/1/news",
                params={
                    "apikey":   NEWSDATA_API_KEY,
                    "q":        "cybersecurity OR ransomware OR malware OR \"data breach\" OR \"AI security\"",
                    "language": "en",
                    "size":     10,
                },
            )
        data = r.json()

        if r.status_code != 200 or data.get("status") != "success":
            return {"articles": FALLBACK_NEWS, "source": "static"}

        articles = []
        for item in (data.get("results") or [])[:10]:
            title  = item.get("title") or ""
            source = (item.get("source_id") or item.get("source_name") or "Unknown").title()
            url    = item.get("link") or "#"
            pub    = item.get("pubDate") or ""
            tag, color = _tag_article(title)
            articles.append({
                "title":  title,
                "source": source,
                "tag":    tag,
                "color":  color,
                "url":    url,
                "time":   _fmt_time(pub),
            })

        _cache = {"data": articles, "fetched_at": time.time()}
        return {"articles": articles, "source": "live"}

    except Exception:
        return {"articles": FALLBACK_NEWS, "source": "static"}