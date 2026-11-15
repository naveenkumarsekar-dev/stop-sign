from fastapi.testclient import TestClient

from honeypot import config, db
from honeypot.app import app

ADMIN = {"X-Admin-Token": "test-token"}


def test_agent_flow_gets_stop_sign_and_tracks_abort():
    with TestClient(app) as c:
        c.post("/_admin/reset", headers=ADMIN)
        h = {"User-Agent": "python-httpx/0.28.1", "X-Forwarded-For": "203.0.113.9"}
        assert "old-export" in c.get("/docs", headers=h).text
        key = c.get("/config", headers=h).json()["integrations"]["payments_api_key"]
        c.get(config.PROSE_BAIT_PATH, headers=h)
        r = c.get("/v1/payments", headers={**h, "X-API-Key": key})
        assert r.status_code == 200 and "SECURITY_NOTICE" in r.json()
        assert "X-Security-Notice" in r.headers
        c.get("/users", headers=h)  # keeps pushing after the notice
        s = dict(db.connect().execute("SELECT * FROM sessions WHERE ip='203.0.113.9'").fetchone())
        assert s["label"] == "ai_agent" and s["stopsign_framing"] == "combined"
        assert s["sensitive_after_stop"] == 1


def test_human_never_gets_notice_and_admin_is_protected():
    with TestClient(app) as c:
        h = {"User-Agent": "Mozilla/5.0 Chrome/131", "X-Forwarded-For": "198.51.100.4"}
        for p in ["/", "/docs", "/users", "/health"]:
            r = c.get(p, headers=h)
            assert "SECURITY_NOTICE" not in r.text and "Unauthorized access detected" not in r.text
        assert c.post("/_admin/reset").status_code == 403
        assert c.post("/admin/login", json={"username": "a", "password": "b"}, headers=h).status_code == 401
