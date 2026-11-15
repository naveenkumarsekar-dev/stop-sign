"""Incident report for one session: LLM-written when a key is configured, template otherwise."""
from datetime import datetime, timezone

from . import db, llm

LABELS = {"ai_agent": "AI agent", "automated": "Automated script / scanner", "human": "Human / benign", "unknown": "Unknown"}


def _ts(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if t else "-"


def gather(session_id: str) -> dict:
    c = db.connect()
    try:
        s = dict(c.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone())
        sigs = [dict(r) for r in c.execute("SELECT * FROM signals WHERE session_id=? ORDER BY ts", (session_id,))]
        reqs = [dict(r) for r in c.execute(
            "SELECT ts, method, path, status, stopsign_served FROM requests WHERE session_id=? ORDER BY ts", (session_id,))]
    finally:
        c.close()
    return {"session": s, "signals": sigs, "requests": reqs}


def template(d: dict) -> str:
    s, sigs, reqs = d["session"], d["signals"], d["requests"]
    lines = [
        f"# Incident report: session {s['id']}",
        "",
        f"**Classification:** {LABELS.get(s['label'], s['label'])} (AI score {s['ai_score']}/100, bot score {s['bot_score']}/100)",
        f"**Source:** {s['ip']} · `{s['user_agent']}`",
        f"**Window:** {_ts(s['first_seen'])} to {_ts(s['last_seen'])} · {s['n_requests']} requests",
        "",
        "## Evidence",
    ]
    lines += [f"- {_ts(g['ts'])} · **{g['name']}** (+{g['points']}): {g['evidence']}" for g in sigs] or ["- none"]
    if s["stopsign_at"]:
        stopped = s["sensitive_after_stop"] == 0
        lines += ["", "## Stop Sign response",
                  f"- Framing served: **{s['stopsign_framing']}** at {_ts(s['stopsign_at'])}",
                  f"- Requests to sensitive endpoints after the notice: **{s['sensitive_after_stop']}**",
                  f"- Outcome: **{'agent stopped' if stopped else 'agent continued'}**"]
    touched = sorted({r["path"] for r in reqs})
    lines += ["", "## Endpoints touched", ", ".join(f"`{p}`" for p in touched[:30]),
              "", "## Recommended actions",
              "- Block the source address and rotate the planted honeytoken.",
              "- Search production logs for the same user agent and for any use of the honeytoken.",
              "- If the agent ran on a commercial model, send this report to that provider's abuse team."]
    return "\n".join(lines)


def generate(session_id: str) -> str:
    d = gather(session_id)
    base = template(d)
    if not llm.available():
        return base
    try:
        return llm.complete(
            "You are a SOC analyst. Rewrite the structured findings below into a concise incident report "
            "(max 350 words) with sections: Summary, Evidence, Stop Sign outcome, Recommended actions. "
            "Use only facts present in the findings. Do not invent details.",
            base)
    except Exception as e:  # never break the dashboard because of the LLM
        return base + f"\n\n_(LLM summary unavailable: {e})_"
