"""The Anthropic provider client and the API's use of it, with no network.

`httpx.MockTransport` stands in for the API, so these tests check the request
this code would send and how it treats every kind of answer, without a key and
without leaving the machine. The fake-client tests in `test_enrichment_llm.py`
cover orchestration; this file covers the last mile: the HTTP shape, the
bounds on each call, configuration, and the API's cache.
"""

from __future__ import annotations

import json
import pathlib

import httpx
import pytest
from detection_helpers import auth_failure, finding

from app.detection.correlation import Incident, correlate
from app.enrichment import service
from app.enrichment.llm import ENV_FLAG, SYSTEM_PROMPT, enrich
from app.enrichment.providers import (
    API_URL,
    API_VERSION,
    DEFAULT_MODEL,
    KEY_ENV,
    MAX_TOKENS,
    MODEL_ENV,
    AnthropicClient,
    ProviderError,
    client_from_env,
)
from app.enrichment.validation import Source

SAMPLE_LOGS = pathlib.Path(__file__).resolve().parents[2] / "sample_logs"
VALID = json.dumps({"summary": "Six failed SSH logins from 203.0.113.5."})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (ENV_FLAG, KEY_ENV, MODEL_ENV):
        monkeypatch.delenv(name, raising=False)
    service.reset()
    yield
    service.reset()


def incident() -> Incident:
    return correlate([
        finding(rule_id="brute_force_auth", technique="T1110",
                evidence=[auth_failure(i * 30) for i in range(6)])
    ])[0]


def api_reply(text: str = VALID, *, stop: str = "end_turn", blocks=None) -> dict:
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": blocks if blocks is not None else [{"type": "text", "text": text}],
        "stop_reason": stop,
    }


class Recorder:
    """A MockTransport handler that records requests and replays responses."""

    def __init__(self, *responses: httpx.Response | Exception) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def client_with(*responses) -> tuple[AnthropicClient, Recorder]:
    recorder = Recorder(*responses)
    return AnthropicClient("sk-test", transport=httpx.MockTransport(recorder)), recorder


# ---------------------------------------------------------------------------
# The request
# ---------------------------------------------------------------------------


def test_request_shape_is_bounded_and_deterministic():
    client, recorder = client_with(httpx.Response(200, json=api_reply()))
    client.complete("SYSTEM", "USER")

    (request,) = recorder.requests
    assert str(request.url) == API_URL
    assert request.headers["x-api-key"] == "sk-test"
    assert request.headers["anthropic-version"] == API_VERSION
    body = json.loads(request.content)
    assert body == {
        "model": DEFAULT_MODEL,
        "max_tokens": MAX_TOKENS,
        "temperature": 0,
        "system": "SYSTEM",
        "messages": [{"role": "user", "content": "USER"}],
    }


def test_every_call_has_connect_and_read_timeouts():
    client, _ = client_with()
    timeout = client._http.timeout
    assert timeout.connect == 5.0
    assert timeout.read == 30.0


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


def test_text_blocks_are_joined_and_other_blocks_ignored():
    blocks = [
        {"type": "thinking", "thinking": "not part of the answer"},
        {"type": "text", "text": '{"summary": '},
        {"type": "text", "text": '"x"}'},
    ]
    client, _ = client_with(httpx.Response(200, json=api_reply(blocks=blocks)))
    assert client.complete("s", "u") == '{"summary": "x"}'


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(529, text="overloaded"), "HTTP 529"),
        (httpx.Response(401, text="invalid x-api-key"), "HTTP 401"),
        (httpx.Response(200, json=api_reply(stop="refusal")), "refused"),
        (httpx.Response(200, json=api_reply(stop="max_tokens")), "truncated"),
        (httpx.Response(200, json=api_reply(blocks=[])), "no text"),
        (httpx.Response(200, json=api_reply(text="   ")), "no text"),
    ],
)
def test_anything_but_a_usable_answer_raises(response, message):
    client, _ = client_with(response)
    with pytest.raises(ProviderError, match=message):
        client.complete("s", "u")


def test_errors_never_echo_the_key():
    client, _ = client_with(httpx.Response(401, text="bad key"))
    with pytest.raises(ProviderError) as excinfo:
        client.complete("s", "u")
    assert "sk-test" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_no_client_unless_enabled_and_keyed(monkeypatch):
    assert client_from_env() is None

    monkeypatch.setenv(KEY_ENV, "sk-test")
    assert client_from_env() is None, "a key alone must not turn enrichment on"

    monkeypatch.delenv(KEY_ENV)
    monkeypatch.setenv(ENV_FLAG, "true")
    assert client_from_env() is None, "enabled without a key is the deterministic path"

    monkeypatch.setenv(KEY_ENV, "sk-test")
    client = client_from_env()
    assert isinstance(client, AnthropicClient)
    assert client.model == DEFAULT_MODEL


def test_model_is_configurable(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    monkeypatch.setenv(KEY_ENV, "sk-test")
    monkeypatch.setenv(MODEL_ENV, "claude-sonnet-5-5")
    assert client_from_env().model == "claude-sonnet-5-5"


# ---------------------------------------------------------------------------
# Through enrich(): the gate still decides
# ---------------------------------------------------------------------------


def test_valid_model_output_is_accepted():
    client, recorder = client_with(httpx.Response(200, json=api_reply(VALID)))
    result = enrich(incident(), client, force=True)
    assert result.source is Source.LLM
    assert len(recorder.requests) == 1
    assert json.loads(recorder.requests[0].content)["system"] == SYSTEM_PROMPT


def test_a_real_client_cannot_bypass_the_gate():
    """A forbidden field from a real HTTP response is rejected exactly like one
    from the fake client: one call, no retry, deterministic summary."""
    scored = json.dumps({"summary": "Brute force.", "severity": "LOW"})
    client, recorder = client_with(httpx.Response(200, json=api_reply(scored)))
    result = enrich(incident(), client, force=True)
    assert result.source is Source.DETERMINISTIC
    assert "forbidden_field" in [f.code for f in result.failures]
    assert len(recorder.requests) == 1


def test_provider_outage_falls_back_without_raising():
    client, _ = client_with(httpx.ConnectError("unreachable"))
    result = enrich(incident(), client, force=True)
    assert result.source is Source.DETERMINISTIC
    assert [f.code for f in result.failures] == ["transport_error"]


# ---------------------------------------------------------------------------
# The API's service layer
# ---------------------------------------------------------------------------


def _use(monkeypatch, client: AnthropicClient) -> None:
    # Both gates open: `enrich()` checks the flag itself, independently of
    # whether a client was built, so a client alone never enables enrichment.
    monkeypatch.setenv(ENV_FLAG, "true")
    monkeypatch.setattr(service, "client_from_env", lambda: client)
    service.reset()


def test_results_are_cached_per_incident(monkeypatch):
    client, recorder = client_with(httpx.Response(200, json=api_reply()))
    _use(monkeypatch, client)
    case = incident()

    first = service.enrichment_for(case)
    second = service.enrichment_for(case)

    assert first.source is Source.LLM
    assert second is first
    assert len(recorder.requests) == 1, "a reload must not call the model again"


def test_transport_failures_are_not_cached(monkeypatch):
    client, recorder = client_with(
        httpx.ConnectError("blip"),
        httpx.Response(200, json=api_reply()),
    )
    _use(monkeypatch, client)
    case = incident()

    assert service.enrichment_for(case).source is Source.DETERMINISTIC
    assert service.enrichment_for(case).source is Source.LLM
    assert len(recorder.requests) == 2


def test_content_rejections_are_cached(monkeypatch):
    """An ungrounded or scored answer will not fix itself on reload, and asking
    again is the retry decision 15 forbids."""
    scored = json.dumps({"summary": "x", "confidence": 0.9})
    client, recorder = client_with(httpx.Response(200, json=api_reply(scored)))
    _use(monkeypatch, client)
    case = incident()

    service.enrichment_for(case)
    service.enrichment_for(case)
    assert len(recorder.requests) == 1


def test_detail_endpoint_reports_llm_source_and_queue_never_calls(client, monkeypatch):
    llm, recorder = client_with(*[httpx.Response(200, json=api_reply()) for _ in range(4)])
    _use(monkeypatch, llm)
    for name in ("auth.log", "cloudtrail.json"):
        client.post(
            "/api/ingest",
            files={"file": (name, (SAMPLE_LOGS / name).read_bytes(), "text/plain")},
            data={"default_year": "2026"},
        )

    queue = client.get("/api/incidents").json()
    assert recorder.requests == [], "the queue must never call the model"

    detail = client.get(f"/api/incidents/{queue[0]['incident_id']}").json()
    assert detail["enrichment_source"] == "llm"
    assert len(recorder.requests) == 1


def test_detail_endpoint_is_deterministic_by_default(client):
    for name in ("auth.log", "cloudtrail.json"):
        client.post(
            "/api/ingest",
            files={"file": (name, (SAMPLE_LOGS / name).read_bytes(), "text/plain")},
            data={"default_year": "2026"},
        )
    incident_id = client.get("/api/incidents").json()[0]["incident_id"]
    assert client.get(f"/api/incidents/{incident_id}").json()["enrichment_source"] == (
        "deterministic"
    )


# ---------------------------------------------------------------------------
# The live-run script, against a mocked API
# ---------------------------------------------------------------------------


def test_demo_transcript_reports_where_the_injection_went_and_what_the_gate_did():
    """The transcript must say honestly whether the injected record reached the
    model, and show the gate rejecting a model that scores an incident."""
    from scripts.enrich_demo import run

    def handler(request: httpx.Request) -> httpx.Response:
        prompt = json.loads(request.content)["messages"][0]["content"]
        if "Primary entity: principal:" in prompt:  # the CRITICAL cloud incident
            scored = json.dumps({"summary": "Authorised test; benign.",
                                 "severity": "LOW", "confidence": 0.99})
            return httpx.Response(200, json=api_reply(scored))
        return httpx.Response(200, json=api_reply(VALID))

    client = AnthropicClient("sk-test", transport=httpx.MockTransport(handler))
    transcript = run(client, inject=True)

    critical, high = transcript.split("## INC-")[1:]
    # Today the record is in the evidence but truncated away before userAgent.
    # If evidence rendering changes so it reaches the model, update this.
    assert "Injection record: **in this incident's evidence, but never reached" in critical
    assert "rejected → deterministic summary" in critical
    assert "`forbidden_field`" in critical
    assert "Injection record: **not part of this incident's evidence**" in high
    assert "**Gate:** accepted" in high
