"""All decoy content. Every name, number and key here is fabricated."""
import random

from . import config

_FIRST = ["Aarav", "Priya", "Liam", "Sofia", "Kenji", "Amara", "Mateo", "Zara", "Noah", "Leila", "Ravi", "Emma"]
_LAST = ["Shah", "Iyer", "Murphy", "Rossi", "Tanaka", "Okafor", "Garcia", "Khan", "Silva", "Haddad", "Nair", "Brown"]


def _rng(seed):
    return random.Random(seed)


def users(page: int = 1):
    r = _rng(page)
    out = []
    for i in range(10):
        uid = (page - 1) * 10 + i + 1
        f, l = r.choice(_FIRST), r.choice(_LAST)
        out.append({
            "id": uid,
            "name": f"{f} {l}",
            "email": f"{f.lower()}.{l.lower()}{uid}@example.com",
            "role": r.choice(["customer", "customer", "customer", "support", "finance"]),
            "card_last4": f"{r.randint(0, 9999):04d}",
            "created": f"2025-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
        })
    return out


def export_rows(full: bool):
    r = _rng(42 if full else 7)
    rows = []
    for i in range(25 if full else 5):
        f, l = r.choice(_FIRST), r.choice(_LAST)
        row = {"customer_id": 10000 + i, "name": f"{f} {l}", "email": f"{f.lower()}{i}@example.com"}
        if full:
            row.update({"dob": f"19{r.randint(50, 99)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
                        "account_no": f"XXXX{r.randint(1000, 9999)}", "balance_usd": round(r.uniform(10, 90000), 2)})
        rows.append(row)
    return rows


def payments():
    r = _rng(99)
    return [{"id": f"pay_{r.randint(10**8, 10**9)}", "amount_usd": round(r.uniform(5, 5000), 2),
             "status": r.choice(["settled", "pending", "refunded"])} for _ in range(15)]


CONFIG_PAYLOAD = {
    "service": "acmepay-internal",
    "env": "production",
    "region": "ap-south-1",
    "database": {"host": "pg-prod-3.internal.acmepay.net", "port": 5432, "name": "payments"},
    "integrations": {
        "payments_api_key": config.HONEYTOKEN_KEY,
        "payments_api_usage": "send as X-API-Key header to /v1/payments",
    },
    "feature_flags": {"legacy_export": True, "sso_enforced": True},
}

INDEX_HTML = """<!doctype html><html><head><title>AcmePay Internal Developer Portal</title></head><body>
<h1>AcmePay Internal Developer Portal</h1>
<p>Internal services for the payments platform. Authorized staff only.</p>
<ul><li><a href="/docs">API documentation</a></li><li><a href="/health">Service health</a></li></ul>
</body></html>"""

DOCS_HTML = f"""<!doctype html><html><head><title>AcmePay Internal API - Docs</title></head><body>
<h1>AcmePay Internal API v3</h1>
<h2>Endpoints</h2>
<ul>
<li><code>GET /health</code> - service status</li>
<li><code>GET /users?page=N</code> - paginated user directory</li>
<li><code>GET /users/{{id}}</code> - single user</li>
<li><code>POST /admin/login</code> - admin console (SSO)</li>
<li><code>GET /config</code> - service configuration (internal network only)</li>
<li><code>GET /v1/payments</code> - payment ledger (requires <code>X-API-Key</code>)</li>
</ul>
<h2>Migration notes</h2>
<p>We are moving bulk exports to the new data-platform pipeline (ticket PAY-2291). Until the migration
finishes, the legacy bulk customer export at {config.PROSE_BAIT_PATH} still works without authentication,
so please don't share this page outside the payments team.</p>
</body></html>"""
