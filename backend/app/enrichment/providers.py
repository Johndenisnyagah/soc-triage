"""Provider clients behind the `LLMClient` protocol.

One provider today: the Anthropic Messages API, called with `httpx` directly
rather than through an SDK. The orchestration in `llm.py` already owns retry
policy -- one retry, and only for formatting failures -- so a client library
that retries on its own would quietly double the attempt budget and retry
exactly the content failures decision 15 says must never be retried. A plain
HTTP call keeps every attempt visible in one place.

What this client guarantees, and why each matters:

* **Bounded.** A connect timeout, a read timeout and a `max_tokens` cap on
  every call (OWASP LLM10). A model that hangs or rambles costs at most one
  bounded attempt, after which `enrich()` falls back to the deterministic
  summary.
* **Deterministic-leaning.** Temperature 0. Enrichment explains a fixed set of
  facts; variety between reloads is noise to an analyst, not value.
* **Raises on anything but a usable answer.** Non-2xx, a refusal, an empty
  body, or no text block all raise. `enrich()` turns every exception into a
  recorded `transport_error` and the deterministic summary, so raising is the
  safe direction: a half-read response must never be validated as if whole.
* **Off unless asked.** `client_from_env()` returns a client only when
  enrichment is enabled *and* a key is present. Anything else returns `None`,
  which `enrich()` treats as the deterministic path. It never raises: a missing
  key is a configuration state, not an error.

Log content leaves the machine when this is on (OWASP LLM02): usernames,
addresses and account IDs in evidence are sent to the provider. That is why it
is opt-in, and why choosing a provider and its data-handling terms is the
operator's decision.
"""

from __future__ import annotations

import os

import httpx

from app.enrichment.llm import is_enabled

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"

KEY_ENV = "ANTHROPIC_API_KEY"
MODEL_ENV = "SOC_LLM_MODEL"
#: Small, fast and cheap: the task is explanation of a fixed evidence set,
#: and the validation gate rather than model size is what makes output safe.
DEFAULT_MODEL = "claude-haiku-5-5"

#: Enough for the summary, narrative and actions within validation's length
#: limits (1200 + 3000 + 10 x 300 characters), with headroom for JSON syntax.
MAX_TOKENS = 2048
TIMEOUT = httpx.Timeout(30.0, connect=5.0)


class ProviderError(RuntimeError):
    """The provider did not return a usable answer."""


class AnthropicClient:
    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_MODEL,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self.model = model
        self._http = httpx.Client(
            timeout=TIMEOUT,
            transport=transport,
            headers={
                "x-api-key": api_key,
                "anthropic-version": API_VERSION,
                "content-type": "application/json",
            },
        )

    def complete(self, system: str, user: str) -> str:
        response = self._http.post(
            API_URL,
            json={
                "model": self.model,
                "max_tokens": MAX_TOKENS,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        if response.status_code != 200:
            # The body can carry a request id worth logging, never the key.
            raise ProviderError(f"HTTP {response.status_code}: {response.text[:200]}")

        body = response.json()
        stop = body.get("stop_reason")
        if stop == "refusal":
            raise ProviderError("model refused")
        if stop == "max_tokens":
            # Truncated JSON would fail validation anyway; saying why here
            # keeps the recorded failure honest about the cause.
            raise ProviderError("response truncated at max_tokens")

        text = "".join(
            block.get("text", "")
            for block in body.get("content", [])
            if block.get("type") == "text"
        )
        if not text.strip():
            raise ProviderError("no text in response")
        return text

    def close(self) -> None:
        self._http.close()


def client_from_env() -> AnthropicClient | None:
    """The configured client, or None for the deterministic path. Never raises."""
    if not is_enabled():
        return None
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        return None
    model = os.environ.get(MODEL_ENV, "").strip() or DEFAULT_MODEL
    return AnthropicClient(key, model=model)
