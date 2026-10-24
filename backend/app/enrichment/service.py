"""Enrichment as the API uses it: one client per process, results cached.

Incidents are computed on read (decision 16), so without a cache every reload
of a detail page would call the model again -- paying for it each time, and
handing the analyst a differently-worded explanation of the same evidence on
every refresh.

The cache key is `(incident_id, model)`. An incident id is a hash of its
evidence set, so the same id always means the same evidence; new evidence
joining an incident changes the id and misses the cache, which is the correct
behaviour. The model is in the key so switching models never serves the old
model's text under the new one's name.

What is cached: a successful enrichment, and a deterministic fallback caused by
a *content* rejection (an ungrounded citation will not ground itself on the
next reload, and re-asking is the retry decision 15 forbids). What is never
cached: a fallback caused by a transport error, so a brief provider outage does
not pin incidents to the deterministic text until restart.

Bounded and process-local on purpose. It is a cost guard, not a store: a
restart empties it, and two workers each keep their own.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from functools import cache

from app.detection.correlation import Incident
from app.enrichment.llm import enrich
from app.enrichment.providers import AnthropicClient, client_from_env
from app.enrichment.validation import Enrichment

MAX_CACHED = 256

_cache: OrderedDict[tuple[str, str], Enrichment] = OrderedDict()
_lock = threading.Lock()


@cache
def _client() -> AnthropicClient | None:
    return client_from_env()


def reset() -> None:
    """Forget the client and every cached result. Used by tests and on
    configuration change."""
    with _lock:
        _cache.clear()
    _client.cache_clear()


def enrichment_for(incident: Incident) -> Enrichment:
    client = _client()
    if client is None:
        return enrich(incident, None)

    key = (incident.incident_id, client.model)
    with _lock:
        hit = _cache.get(key)
        if hit is not None:
            _cache.move_to_end(key)
            return hit

    result = enrich(incident, client)

    if not any(f.code == "transport_error" for f in result.failures):
        with _lock:
            _cache[key] = result
            _cache.move_to_end(key)
            while len(_cache) > MAX_CACHED:
                _cache.popitem(last=False)
    return result
