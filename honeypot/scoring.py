"""Detection signals. Pure functions so they are easy to test and tune.

Each signal fires at most once per session. A signal has a kind:
  ai   -> evidence of a language-model-driven visitor
  bot  -> evidence of a conventional scanner/script
  both -> automation in general
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass

from . import config


@dataclass
class Signal:
    name: str
    kind: str
    points: int
    evidence: str


SCANNER_PATHS = {
    "/.env", "/.git/config", "/.git/head", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/admin.php", "/backup.zip", "/server-status", "/actuator", "/actuator/env",
    "/.aws/credentials", "/config.json", "/debug", "/console", "/.ds_store",
}

_WORD = re.compile(r"[A-Za-z]{2,}")


def _is_browser(ua: str) -> bool:
    return "mozilla" in (ua or "").lower()


def _blob(req: dict) -> str:
    return " ".join([req.get("query") or "", req.get("body") or "", " ".join((req.get("headers") or {}).values())])


def _natural_language(text: str) -> str | None:
    """Return a snippet if the text looks like an English sentence (>= 6 words)."""
    for chunk in re.split(r"[&=\n{}\[\]\"]", text or ""):
        words = _WORD.findall(chunk)
        if len(words) >= 6 and chunk.count(" ") >= 5:
            return chunk.strip()[:160]
    return None


def _gaps(history: list[dict]) -> list[float]:
    ts = [r["ts"] for r in history]
    return [b - a for a, b in zip(ts, ts[1:])]


def evaluate(history: list[dict], user_agent: str, already: set[str]) -> list[Signal]:
    """history: every request in this session so far, oldest first, including the current one."""
    out: list[Signal] = []
    cur = history[-1]
    path = (cur["path"] or "").lower()

    def fire(name, kind, points, evidence):
        if name not in already and all(s.name != name for s in out):
            out.append(Signal(name, kind, points, evidence))

    # --- AI signals -------------------------------------------------------
    if path.startswith(config.PROSE_BAIT_PATH):
        fire("prose_bait", "ai", 30,
             f"Requested {cur['path']}, an endpoint that only appears in prose in /docs (no link, not in any index).")

    if config.HONEYTOKEN_KEY in _blob(cur):
        fire("honeytoken", "ai", 25, f"Used the planted API key from /config on {cur['method']} {cur['path']}.")

    if path.startswith(config.CANARY_PATH):
        fire("canary_followed", "ai", 25,
             f"Followed the hidden instruction embedded in a JSON field and called {cur['method']} {cur['path']}.")

    nl = _natural_language((cur.get("query") or "") + "\n" + (cur.get("body") or ""))
    if nl:
        fire("nl_payload", "ai", 10, f'Natural-language text inside request parameters: "{nl}"')

    docs_ts = next((r["ts"] for r in history if r["path"].lower().startswith("/docs")), None)
    if docs_ts is not None and (path.startswith(config.PROSE_BAIT_PATH) or config.HONEYTOKEN_KEY in _blob(cur)):
        delta = cur["ts"] - docs_ts
        if delta < 20:
            fire("fast_comprehension", "ai", 10,
                 f"Went from reading documentation to acting on a detail buried in it in {delta:.1f}s.")

    gaps = _gaps(history)
    if len(history) >= 5 and not _is_browser(user_agent):
        med = statistics.median(gaps)
        if 0.8 <= med <= 30:
            fire("llm_timing", "ai", 10,
                 f"Think-then-act rhythm: median {med:.1f}s between requests over {len(history)} requests.")

    # --- Shared -----------------------------------------------------------
    if not _is_browser(user_agent):
        fire("automation_ua", "both", 5, f"Non-browser client: {user_agent or '(none)'}")

    # --- Bot signals ------------------------------------------------------
    if len(history) >= 10 and statistics.median(gaps) < 0.5:
        fire("rapid_fire", "bot", 20, f"{len(history)} requests, median gap {statistics.median(gaps)*1000:.0f}ms.")

    probes = {r["path"].lower() for r in history} & SCANNER_PATHS
    if len(probes) >= 3:
        fire("wordlist_probe", "bot", 20, f"Probed known scanner paths: {', '.join(sorted(probes)[:6])}")

    if len(history) >= 10:
        ratio = sum(1 for r in history if r.get("status") == 404) / len(history)
        if ratio > 0.5:
            fire("high_404", "bot", 10, f"{ratio:.0%} of requests hit non-existent paths.")

    return out


def totals(signals: list[dict] | list[Signal]) -> tuple[int, int]:
    ai = bot = 0
    for s in signals:
        kind = s["kind"] if isinstance(s, dict) else s.kind
        pts = s["points"] if isinstance(s, dict) else s.points
        if kind in ("ai", "both"):
            ai += pts
        if kind in ("bot", "both"):
            bot += pts
    return min(ai, 100), min(bot, 100)


def label(ai: int, bot: int) -> str:
    if ai >= config.AI_THRESHOLD:
        return "ai_agent"
    if bot >= config.BOT_THRESHOLD or ai >= config.BOT_THRESHOLD:
        return "automated"
    return "human"
