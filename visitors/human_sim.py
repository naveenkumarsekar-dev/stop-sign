"""Simulated benign human in a browser: slow, irregular, never uses secrets.
Should be labelled 'human'. (For the live demo, have a teammate browse instead.)"""
import random
import time

from .common import Visitor

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/131.0.0.0 Safari/537.36")


def run(speed: float = 1.0) -> str:
    v = Visitor("human", UA)
    v.start()
    path = ["/", "/favicon.ico", "/docs", "/health", "/users", f"/users/{random.randint(1, 10)}", "/users?page=2"]
    if random.random() < 0.5:
        path.append("/config")  # curious, but never uses the key
    for p in path:
        v.get(p)
        time.sleep(random.uniform(2, 12) / speed)
    v.end("completed")
    return v.run_tag


if __name__ == "__main__":
    print(run())
