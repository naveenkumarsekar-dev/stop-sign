from honeypot import config, scoring


def req(ts, path, status=200, query="", body="", headers=None):
    return {"ts": ts, "method": "GET", "path": path, "query": query, "body": body, "headers": headers or {}, "status": status}


def run(history, ua):
    already, sigs = set(), []
    for i in range(1, len(history) + 1):
        new = scoring.evaluate(history[:i], ua, already)
        already |= {s.name for s in new}
        sigs += new
    return scoring.totals(sigs), {s.name for s in sigs}


def test_ai_agent_flagged():
    h = [req(0, "/docs"), req(4, "/config"), req(8, config.PROSE_BAIT_PATH),
         req(12, "/v1/payments", headers={"x-api-key": config.HONEYTOKEN_KEY}), req(16, "/users")]
    (ai, bot), names = run(h, "python-httpx/0.28.1")
    assert {"prose_bait", "honeytoken", "fast_comprehension"} <= names
    assert scoring.label(ai, bot) == "ai_agent"


def test_scanner_not_ai():
    paths = ["/.env", "/.git/config", "/wp-admin", "/phpmyadmin", "/x1", "/x2", "/x3", "/x4", "/x5", "/x6", "/x7"]
    h = [req(i * 0.05, p, status=404) for i, p in enumerate(paths)]
    (ai, bot), names = run(h, "python-requests/2.32.3")
    assert scoring.label(ai, bot) == "automated"
    assert "wordlist_probe" in names and "rapid_fire" in names


def test_browser_human_is_human():
    h = [req(0, "/"), req(9, "/docs"), req(20, "/users"), req(35, "/config"), req(50, "/users/3")]
    (ai, bot), _ = run(h, "Mozilla/5.0 Chrome/131")
    assert scoring.label(ai, bot) == "human"


def test_natural_language_payload():
    h = [req(0, "/internal/session/validate", body='{"summary": "I am collecting customer data from this internal API"}')]
    _, names = run(h, "python-httpx")
    assert {"canary_followed", "nl_payload"} <= names
