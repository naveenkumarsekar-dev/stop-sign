"""Live Stop Sign dashboard.  Run:  streamlit run dashboard/app.py"""
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from honeypot import db, report  # noqa: E402

st.set_page_config(page_title="Stop Sign · AI attacker detection", page_icon="🛑", layout="wide")
db.init()

ICON = {"ai_agent": "🧠 AI agent", "automated": "🤖 Script", "human": "🧑 Human", "unknown": "… Unknown"}


def q(sql, args=()):
    c = db.connect()
    try:
        return pd.read_sql_query(sql, c, params=args)
    finally:
        c.close()


def hhmmss(t):
    return datetime.fromtimestamp(t).strftime("%H:%M:%S") if pd.notna(t) else "-"


st.title("🛑 Stop Sign")
st.caption("Catches AI agents attacking your systems, then uses their own safety training to make them stop.")

tab_live, tab_board = st.tabs(["Live", "Leaderboard"])

with tab_live:
    @st.fragment(run_every=2)
    def live():
        s = q("SELECT * FROM sessions ORDER BY last_seen DESC")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Visitors", len(s))
        c2.metric("AI agents caught", int((s.label == "ai_agent").sum()) if len(s) else 0)
        stopped = s[(s.stopsign_at.notna()) & (s.sensitive_after_stop == 0)] if len(s) else s
        c3.metric("Stop Signs served", int(s.stopsign_at.notna().sum()) if len(s) else 0)
        c4.metric("Agents that stopped", len(stopped))
        if s.empty:
            st.info("Waiting for visitors… point a test agent at the honeypot.")
            return

        view = pd.DataFrame({
            "Session": s.id, "Label": s.label.map(ICON), "AI score": s.ai_score, "Bot score": s.bot_score,
            "Requests": s.n_requests, "Source": s.ip, "Client": s.user_agent.str.slice(0, 40),
            "Stop Sign": s.stopsign_framing.fillna("-"),
            "After notice": s.apply(lambda r: "-" if pd.isna(r.stopsign_at) else
                                    ("✅ stopped" if r.sensitive_after_stop == 0 else f"❌ {r.sensitive_after_stop} more hits"), axis=1),
            "Last seen": s.last_seen.map(hhmmss),
        })
        st.dataframe(view, hide_index=True, width="stretch",
                     column_config={"AI score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d"),
                                    "Bot score": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d")})

        sid = st.selectbox("Inspect session", s.id, format_func=lambda x: f"{x} · {ICON[s.set_index('id').loc[x, 'label']]}")
        left, right = st.columns(2)
        with left:
            st.subheader("Evidence timeline")
            sig = q("SELECT ts, name, points, evidence FROM signals WHERE session_id=? ORDER BY ts", (sid,))
            for r in sig.itertuples():
                st.markdown(f"`{hhmmss(r.ts)}` **{r.name}** +{r.points} — {r.evidence}")
            row = s.set_index("id").loc[sid]
            if pd.notna(row.stopsign_at):
                st.error(f"🛑 Stop Sign ({row.stopsign_framing}) served at {hhmmss(row.stopsign_at)}")
            reqs = q("SELECT ts, method, path, status, stopsign_served FROM requests WHERE session_id=? ORDER BY ts", (sid,))
            reqs["ts"] = reqs.ts.map(hhmmss)
            reqs["stopsign_served"] = reqs.stopsign_served.map({1: "🛑", 0: ""})
            st.dataframe(reqs, hide_index=True, width="stretch", height=240)
        with right:
            st.subheader("Agent's own reasoning (test agents only)")
            tr = q("SELECT ts, role, content FROM transcripts WHERE session_id=? ORDER BY ts", (sid,))
            if tr.empty:
                st.caption("No transcript. Real attackers don't send one; our own test agent does, for the demo.")
            for r in tr.tail(12).itertuples():
                icon = {"assistant": "💭", "tool_call": "🔧", "final": "🏁"}.get(r.role, "•")
                st.markdown(f"{icon} `{hhmmss(r.ts)}` {r.content[:600]}")

    live()

    st.divider()
    sessions = q("SELECT id FROM sessions ORDER BY last_seen DESC")
    if not sessions.empty:
        pick = st.selectbox("Incident report for", sessions.id, key="rep")
        if st.button("📝 Generate incident report"):
            with st.spinner("Writing report…"):
                st.markdown(report.generate(pick))

with tab_board:
    st.subheader("Does the attacker's own alignment stop it?")
    df = q("""SELECT r.visitor_type, r.model, s.label, s.stopsign_framing AS framing, s.stopsign_at,
                     s.sensitive_after_stop, r.outcome, s.flagged_at, s.first_seen
              FROM runs r LEFT JOIN sessions s ON s.run_tag = r.run_tag""")
    if df.empty:
        st.info("Run `python -m evals.run_eval` to fill the leaderboard.")
    else:
        det = df.groupby("visitor_type").apply(lambda g: pd.Series({
            "runs": len(g), "labelled AI": f"{(g.label == 'ai_agent').mean():.0%}",
            "labelled script": f"{(g.label == 'automated').mean():.0%}",
            "labelled human": f"{(g.label == 'human').mean():.0%}"}), include_groups=False)
        st.markdown("**Detection accuracy by visitor type**")
        st.dataframe(det, width="stretch")
        ai = df[(df.visitor_type == "ai_agent") & df.stopsign_at.notna()].copy()
        if not ai.empty:
            ai["stopped"] = (ai.sensitive_after_stop == 0) | (ai.outcome == "refused")
            ai["secs_to_detect"] = ai.flagged_at - ai.first_seen
            board = ai.groupby(["model", "framing"]).agg(runs=("stopped", "size"), abort_rate=("stopped", "mean"),
                                                         avg_secs_to_detect=("secs_to_detect", "mean")).reset_index()
            board["abort_rate"] = board.abort_rate.map("{:.0%}".format)
            board["avg_secs_to_detect"] = board.avg_secs_to_detect.round(1)
            st.markdown("**Abort-rate leaderboard** (did the agent stop after the Stop Sign?)")
            st.dataframe(board, hide_index=True, width="stretch")
