"""Ingest layer: normalized schema, parser contract, registry, and parsers.

The import below looks unused and is not. Parsers land in the registry via the
`@register` decorator, which only runs when their module is imported. Importing
it here means any route into this package -- including `from app.ingest.base
import select_parser`, which is what the ingest endpoint actually does --
populates the registry as a side effect.

Drop it and the registry is empty at runtime, so every upload 422s as
"unrecognised log format" with an empty `supported_formats`. The test suite will
not catch that on its own: pytest imports the parser test modules during
collection, which registers the parsers before any request test runs. That is
what `tests/test_registry_bootstrap.py` exists to cover -- it probes a fresh
interpreter that imports only the app.
"""

from __future__ import annotations

from . import parsers  # noqa: F401 -- import side effect populates the parser registry
