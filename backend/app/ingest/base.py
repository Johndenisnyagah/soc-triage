"""Parser interface and registry.

Design notes:

* `sniff()` returns a confidence float, not a bool. The registry picks the
  highest scorer, so adding a parser can't silently break another one by
  landing in the wrong position in an if/elif chain.
* `parse()` yields rather than returns. A 2 GB CloudTrail export must not
  be materialised in memory before the first event is available downstream.
* Parsers never raise on malformed input. One bad line must not kill an
  ingest run -- errors are recorded on the context and the parser moves on.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar, Iterator

from .schema import NormalizedEvent, SourceType

MAX_RECORDED_ERRORS = 100
SNIFF_SAMPLE_LINES = 200


@dataclass(slots=True)
class ParseError:
    line_no: int
    reason: str
    excerpt: str  # truncated: never log an unbounded attacker-controlled line


@dataclass(slots=True)
class ParseStats:
    lines_read: int = 0
    events_emitted: int = 0
    lines_skipped: int = 0
    errors: list[ParseError] = field(default_factory=list)

    def record_error(self, line_no: int, reason: str, excerpt: str) -> None:
        self.lines_skipped += 1
        if len(self.errors) < MAX_RECORDED_ERRORS:
            self.errors.append(ParseError(line_no, reason, excerpt[:200]))


@dataclass(slots=True)
class ParseContext:
    """Everything a parser needs that isn't in the payload itself."""

    filename: str | None = None

    # Syslog timestamps carry no year. Without this, every December log
    # re-ingested in January lands 12 months in the future.
    default_year: int = field(
        default_factory=lambda: datetime.now(timezone.utc).year
    )

    # Syslog also carries no timezone. Assume UTC unless the operator
    # tells us the host's local zone.
    assume_tz: timezone = timezone.utc

    # Fallback when the payload has no hostname (e.g. a bare sshd log).
    default_host: str | None = None

    stats: ParseStats = field(default_factory=ParseStats)


class BaseParser(ABC):
    """Contract every source parser implements."""

    source_type: ClassVar[SourceType]

    @classmethod
    @abstractmethod
    def sniff(cls, sample: str) -> float:
        """Confidence in [0.0, 1.0] that this parser handles `sample`.

        Cheap and read-only. Called against the first few hundred lines of
        every upload, for every registered parser.
        """

    @abstractmethod
    def parse(
        self, content: str, ctx: ParseContext
    ) -> Iterator[NormalizedEvent]:
        """Yield normalized events. Must not raise on malformed input."""


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: list[type[BaseParser]] = []


def register(cls: type[BaseParser]) -> type[BaseParser]:
    """Class decorator. Import the parser module to register it."""
    _REGISTRY.append(cls)
    return cls


def registered_parsers() -> list[type[BaseParser]]:
    return list(_REGISTRY)


def select_parser(
    content: str, *, min_confidence: float = 0.3
) -> tuple[type[BaseParser] | None, float]:
    """Pick the best parser for `content`.

    Returns (parser_class, confidence). A None parser means nothing scored
    above the floor -- surface that to the user as "unrecognised log format"
    rather than guessing and producing garbage events.
    """
    sample = "\n".join(content.splitlines()[:SNIFF_SAMPLE_LINES])
    if not sample.strip():
        return None, 0.0

    scored = [(cls.sniff(sample), cls) for cls in _REGISTRY]
    scored.sort(key=lambda pair: pair[0], reverse=True)

    if not scored or scored[0][0] < min_confidence:
        return None, scored[0][0] if scored else 0.0
    return scored[0][1], scored[0][0]
