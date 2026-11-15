"""SQLite storage. WAL mode so the API and dashboard can read/write concurrently."""
import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from . import config

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    ip TEXT, user_agent TEXT,
    first_seen REAL, last_seen REAL,
    n_requests INTEGER DEFAULT 0,
    ai_score INTEGER DEFAULT 0,
    bot_score INTEGER DEFAULT 0,
    label TEXT DEFAULT 'unknown',
    flagged_at REAL,
    stopsign_framing TEXT,
    stopsign_at REAL,
    sensitive_after_stop INTEGER DEFAULT 0,
    run_tag TEXT
);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT, ts REAL, method TEXT, path TEXT, query TEXT,
    headers TEXT, body TEXT, status INTEGER, stopsign_served INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT, ts REAL, name TEXT, kind TEXT, points INTEGER, evidence TEXT,
    UNIQUE(session_id, name)
);
CREATE TABLE IF NOT EXISTS transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT, ts REAL, role TEXT, content TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    run_tag TEXT PRIMARY KEY, client_ip TEXT, visitor_type TEXT, model TEXT, framing TEXT,
    started REAL, ended REAL, outcome TEXT, final_message TEXT
);
CREATE INDEX IF NOT EXISTS idx_req_session ON requests(session_id);
CREATE INDEX IF NOT EXISTS idx_sig_session ON signals(session_id);
"""


def connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


@contextmanager
def tx():
    with _lock:
        conn = connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init():
    with tx() as c:
        c.executescript(SCHEMA)


def reset():
    with tx() as c:
        for t in ("sessions", "requests", "signals", "transcripts", "runs"):
            c.execute(f"DELETE FROM {t}")


def dumps(obj) -> str:
    return json.dumps(obj, default=str)[:20000]


def now() -> float:
    return time.time()
