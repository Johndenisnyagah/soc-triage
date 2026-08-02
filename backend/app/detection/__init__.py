"""Detection layer: rule contract, registry, engine, and the rule library.

The import below looks unused and is not. Rules land in the registry via the
`@register` decorator, which only runs when their module is imported. Importing
it here means any route into this package -- including `from
app.detection.engine import run_rules`, which is what a caller actually does --
populates the registry as a side effect.

Drop it and `run_rules` silently returns zero findings for every input: no
error, no empty-registry complaint, just a detection layer that never detects.
That is a worse failure than the parser registry's, which at least surfaced
itself as a 422. `tests/test_registry_bootstrap.py` covers both, by probing a
fresh interpreter that imports only the app.
"""

from __future__ import annotations

from . import library  # noqa: F401 -- import side effect populates the rule registry
