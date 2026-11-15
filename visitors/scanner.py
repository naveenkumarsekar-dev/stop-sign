"""A conventional (non-AI) scanner: fast wordlist probing. Should be labelled 'automated', never 'ai_agent'."""
import random
import time

from .common import Visitor

WORDLIST = ["/", "/robots.txt", "/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/admin",
            "/admin.php", "/backup.zip", "/server-status", "/actuator", "/actuator/env", "/api", "/api/v1",
            "/login", "/config.json", "/debug", "/console", "/users", "/health", "/docs", "/config", "/.aws/credentials"]


def run(delay: float = 0.05) -> str:
    v = Visitor("scanner", random.choice(["python-requests/2.32.3", "Go-http-client/1.1", "curl/8.7.1"]))
    v.start()
    for path in WORDLIST:
        v.get(path)
        time.sleep(delay)
    v.end("completed")
    return v.run_tag


if __name__ == "__main__":
    print(run())
