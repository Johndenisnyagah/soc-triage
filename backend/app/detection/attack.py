"""ATT&CK technique lookup and validation.

Decision 8: a technique ID is never trusted because it looks plausible. Static
rule mappings go stale -- ATT&CK deprecates and restructures between releases,
and a rule pointing at a retired technique should resolve to None and be
noticed, not silently contribute a tactic that no longer exists. The same
validator is what will check any model-proposed ID when that path is built.

Reads the derived catalog committed at `data/attack_catalog.json`, built by
`scripts/build_attack_catalog.py`. Never the network: the suite must run
offline, and a catalog that shifts under a running system makes detection
irreproducible.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

DEFAULT_CATALOG_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "data" / "attack_catalog.json"
)


@dataclass(frozen=True, slots=True)
class TechniqueInfo:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    parent_id: str | None
    url: str

    @property
    def is_subtechnique(self) -> bool:
        return self.parent_id is not None


class Catalog:
    """An in-memory ATT&CK catalog.

    A class rather than module-level functions so tests can build a small
    catalog from a literal and exercise resolution rules -- notably the parent
    fallback -- without depending on whichever ATT&CK release happens to be
    committed. The shipped catalog is reached through `default_catalog()`.
    """

    def __init__(self, techniques: dict[str, Any], meta: dict[str, Any] | None = None):
        self._techniques = techniques
        self.meta = meta or {}

    @classmethod
    def from_file(cls, path: pathlib.Path) -> "Catalog":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(payload.get("techniques", {}), payload.get("_meta", {}))

    def __len__(self) -> int:
        return len(self._techniques)

    def entries(self) -> list[tuple[str, dict[str, Any]]]:
        """Raw catalog rows, deprecated ones included.

        For auditing the catalog itself -- "does anything map to both of these
        tactics?" -- as opposed to resolving a single ID, which is what every
        caller in the detection path should be doing instead.
        """
        return list(self._techniques.items())

    @staticmethod
    def normalize(technique_id: str) -> str:
        """`t1110.001` and ` T1110.001 ` are the same technique.

        Model output and hand-written rule mappings both arrive inconsistently
        cased; rejecting on case would be a validator that fails for the wrong
        reason.
        """
        return technique_id.strip().upper()

    def resolve(self, technique_id: str | None) -> TechniqueInfo | None:
        """Return the technique, or None if it must not be used.

        None means "do not map to this": unknown, deprecated, or revoked. The
        caller cannot tell those apart deliberately -- every one of them means
        the same thing downstream, which is that no tactic may be attributed.
        """
        if not technique_id:
            return None

        key = self.normalize(technique_id)
        entry = self._techniques.get(key)
        if entry is None or entry.get("deprecated"):
            return None

        tactics = tuple(entry.get("tactics") or ())
        parent_id = entry.get("parent_id")

        # A sub-technique with no tactics of its own inherits its parent's.
        # ATT&CK populates both today, so this is defensive -- but the
        # alternative when it does not is a technique that validates and then
        # contributes nothing to severity, which is the silent kind of wrong.
        # The parent is read even if deprecated: the parent's retirement says
        # nothing about a sub-technique that is still current.
        if not tactics and parent_id:
            parent = self._techniques.get(self.normalize(parent_id))
            if parent:
                tactics = tuple(parent.get("tactics") or ())

        return TechniqueInfo(
            technique_id=key,
            name=entry.get("name", ""),
            tactics=tactics,
            parent_id=parent_id,
            url=entry.get("url", ""),
        )

    def tactics_for(self, technique_id: str | None) -> tuple[str, ...]:
        """Tactics, or empty if the ID does not validate.

        All of them, not the first: a technique spanning four tactics that
        reported one would undercount the breadth incident severity is built on.
        """
        info = self.resolve(technique_id)
        return info.tactics if info else ()


@lru_cache(maxsize=1)
def default_catalog() -> Catalog:
    return Catalog.from_file(DEFAULT_CATALOG_PATH)


def resolve(technique_id: str | None) -> TechniqueInfo | None:
    return default_catalog().resolve(technique_id)


def tactics_for(technique_id: str | None) -> tuple[str, ...]:
    return default_catalog().tactics_for(technique_id)
