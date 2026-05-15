"""Claude-powered finding explainer.

Returns a short, plain-English explanation + concrete fix for one
diagnostic finding. Used by the htmx 'Explain →' button.
"""
from __future__ import annotations

import os
from functools import lru_cache

try:
    from anthropic import Anthropic
    _client_factory = Anthropic
except ImportError:  # pragma: no cover
    _client_factory = None


SYSTEM_PROMPT = """You are a senior identity and SSO implementation engineer with 15 years \
of enterprise experience (Okta, Ping, SAML, OIDC). A linter has surfaced one \
finding from a customer's auth configuration. You will be given the finding. \
Respond with:

1. ONE sentence explaining what this means in plain language to a customer.
2. ONE sentence with the concrete next action.

Total length: max 60 words. No preamble. No bullet points. Two sentences."""


@lru_cache(maxsize=256)
def _explain_cached(kind: str, finding_id: str, title: str, detail: str) -> str:
    if _client_factory is None or not os.environ.get("ANTHROPIC_API_KEY"):
        return ""
    client = _client_factory()
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=180,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": (
                f"Config type: {kind}\n"
                f"Finding ID: {finding_id}\n"
                f"Title: {title}\n"
                f"Detail: {detail}"
            ),
        }],
    )
    return "".join(block.text for block in msg.content if hasattr(block, "text")).strip()


def explain(kind: str, finding: dict) -> str:
    """Return a 2-sentence explanation, or empty string if unavailable."""
    try:
        return _explain_cached(
            kind,
            finding.get("id", ""),
            finding.get("title", ""),
            finding.get("detail", ""),
        )
    except Exception as e:  # noqa: BLE001 — explainer must never break the page
        return f"(Claude explainer unavailable: {e})"
