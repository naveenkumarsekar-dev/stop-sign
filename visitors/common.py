"""Shared plumbing for test visitors. Each visitor gets a unique fake client IP
(sent as X-Forwarded-For) so the honeypot sees them as separate sessions."""
from __future__ import annotations

import os
import random
import uuid

import httpx

BASE_URL = os.getenv("STOPSIGN_URL", "http://127.0.0.1:8000")
ADMIN_TOKEN = os.getenv("STOPSIGN_ADMIN_TOKEN", "change-me")


def fake_ip() -> str:
    return f"203.0.113.{random.randint(1, 254)}" if random.random() < 0.5 else f"198.51.100.{random.randint(1, 254)}"


class Visitor:
    def __init__(self, visitor_type: str, user_agent: str, model: str | None = None):
        self.ip = fake_ip()
        self.run_tag = f"{visitor_type}-{uuid.uuid4().hex[:8]}"
        self.visitor_type = visitor_type
        self.model = model
        self.client = httpx.Client(base_url=BASE_URL, timeout=20,
                                   headers={"User-Agent": user_agent, "X-Forwarded-For": self.ip})
        self._admin = httpx.Client(base_url=BASE_URL, timeout=10, headers={"X-Admin-Token": ADMIN_TOKEN})

    def start(self):
        self._admin.post("/_admin/run/start", json={"run_tag": self.run_tag, "client_ip": self.ip,
                                                     "visitor_type": self.visitor_type, "model": self.model})

    def end(self, outcome: str, final_message: str | None = None):
        self._admin.post("/_admin/run/end", json={"run_tag": self.run_tag, "outcome": outcome,
                                                   "final_message": final_message})

    def transcript(self, role: str, content: str):
        try:
            self._admin.post("/_admin/transcript", json={"client_ip": self.ip, "role": role, "content": content})
        except httpx.HTTPError:
            pass

    def get(self, path, **kw):
        return self.client.get(path, **kw)

    def request(self, method, path, **kw):
        return self.client.request(method, path, **kw)
