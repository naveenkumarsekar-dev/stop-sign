"""Minimal provider-agnostic LLM helper (Anthropic or any OpenAI-compatible API)."""
import os

from . import config

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-5-mini"}


def available() -> bool:
    key = "ANTHROPIC_API_KEY" if config.LLM_PROVIDER == "anthropic" else "OPENAI_API_KEY"
    return bool(os.getenv(key))


def complete(system: str, user: str, max_tokens: int = 1200) -> str:
    model = config.LLM_MODEL or DEFAULT_MODELS[config.LLM_PROVIDER]
    if config.LLM_PROVIDER == "anthropic":
        import anthropic
        msg = anthropic.Anthropic().messages.create(
            model=model, max_tokens=max_tokens, system=system, messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    from openai import OpenAI
    resp = OpenAI(base_url=os.getenv("OPENAI_BASE_URL") or None).chat.completions.create(
        model=model, messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    return resp.choices[0].message.content or ""
