"""LLM client — Anthropic Claude (async to avoid blocking the event loop)."""

from __future__ import annotations

import os
import logging

import anthropic

log = logging.getLogger("cyber.llm")

MODEL_SONNET = "claude-sonnet-4-20250514"
MODEL_HAIKU = "claude-haiku-4-5-20251001"

_async_client: anthropic.AsyncAnthropic | None = None


def _get_client() -> anthropic.AsyncAnthropic:
    global _async_client
    if _async_client is None:
        _async_client = anthropic.AsyncAnthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        )
    return _async_client


async def call_llm(
    prompt: str,
    system: str = "",
    model: str = MODEL_SONNET,
    max_tokens: int = 4096,
    temperature: float = 0,
) -> str:
    """Call Anthropic Claude API (async). Returns response text or empty string on error."""
    try:
        client = _get_client()
        messages = [{"role": "user", "content": prompt}]
        kwargs = dict(model=model, max_tokens=max_tokens, messages=messages, temperature=temperature)
        if system:
            kwargs["system"] = system

        resp = await client.messages.create(**kwargs)
        return resp.content[0].text if resp.content else ""
    except Exception as e:
        log.error("LLM call failed: %s", e)
        return ""
