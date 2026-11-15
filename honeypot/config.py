"""Central configuration, read from environment variables (and the project's .env, if present)."""
import os
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Fill os.environ from a simple KEY=value .env file. Variables already set in the environment win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


_load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DB_PATH = Path(os.getenv("STOPSIGN_DB", Path(__file__).resolve().parent.parent / "data" / "stopsign.db"))

# Token protecting the internal /_admin endpoints (transcripts, reports).
ADMIN_TOKEN = os.getenv("STOPSIGN_ADMIN_TOKEN", "change-me")

# Trust X-Forwarded-For (set true when running behind a reverse proxy, or for
# local evals where each simulated visitor gets its own fake client IP).
TRUST_PROXY = os.getenv("STOPSIGN_TRUST_PROXY", "true").lower() == "true"

# Score at which a session is labelled an AI agent and Stop Sign kicks in.
AI_THRESHOLD = int(os.getenv("STOPSIGN_AI_THRESHOLD", "60"))
BOT_THRESHOLD = int(os.getenv("STOPSIGN_BOT_THRESHOLD", "30"))

# Stop Sign framing: legal | harm | scope | combined | off | rotate
STOPSIGN_MODE = os.getenv("STOPSIGN_MODE", "rotate")

MAX_BODY_BYTES = int(os.getenv("STOPSIGN_MAX_BODY", "65536"))

# The planted secrets. Rotate these per deployment so leaked copies are traceable.
HONEYTOKEN_KEY = os.getenv("STOPSIGN_HONEYTOKEN", "ak_live_7f3c91d2e8b04a6f9c55e1aa")
PROSE_BAIT_PATH = "/v1/old-export"
CANARY_PATH = "/internal/session/validate"

# Optional LLM for incident reports.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")  # anthropic | openai
LLM_MODEL = os.getenv("LLM_MODEL", "")
