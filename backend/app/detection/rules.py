"""Detection rule interface.

Design notes:

* Rules are **pure functions over an event sequence**. No database access, no
  network, no clock reads. A rule test is a list literal in, a list of
  Findings out. This is what makes the whole layer trustworthy.

* The engine groups events by entity key **once**, before any rule runs. If
  each rule did its own grouping query, N rules would mean N passes over the
  data and the layer could never run over a live stream.

* Rules emit `Finding`, not `Incident`. A Finding is "this rule matched this
  evidence." Turning overlapping Findings into one Incident is a separate
  stage -- otherwise every rule would need to know what incidents already
  exist, and rules would stop being pure.

* Windows slide, they don't tumble. Four failures at 09:59 and four at 10:01
  are eight failures in two minutes; a fixed-boundary window would see two
  quiet halves and miss it entirely.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Callable, ClassVar, Iterable, Iterator, Sequence

from app.ingest.schema import Category, NormalizedEvent


class Severity(IntEnum):
    """IntEnum so findings sort by severity without a lookup table."""

    INFO = 10
    LOW = 30
    MEDIUM = 50
    HIGH = 70
    CRITICAL = 90


@dataclass(slots=True)
class Finding:
    """One rule matching one set of evidence.

    `evidence` holds the actual events that triggered the match -- not a count,
    not a summary. The LLM enrichment stage needs real log lines to explain,
    and an analyst needs them to verify. A Finding that can't show its work is
    not auditable.
    """

    rule_id: str
    title: str
    severity: Severity
    entity_key: str
    evidence: list[NormalizedEvent]

    # Statically mapped at rule-definition time. The LLM may propose a
    # technique only when this is None, and its proposal is validated against
    # the ATT&CK catalog before use.
    technique: str | None = None

    metadata: dict = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.evidence if e.timestamp]
        return min(stamps) if stamps else None

    @property
    def last_seen(self) -> datetime | None:
        stamps = [e.timestamp for e in self.evidence if e.timestamp]
        return max(stamps) if stamps else None


@dataclass(slots=True)
class DetectionContext:
    """Everything a rule may look at. Deliberately minimal.

    `events` is pre-sorted by timestamp and pre-scoped to a single entity.
    Events with no timestamp are excluded by the engine -- a windowed rule
    cannot place them, and silently treating them as "now" would fabricate
    correlations that never happened.
    """

    entity_key: str
    events: list[NormalizedEvent]


Predicate = Callable[[NormalizedEvent], bool]


class Rule(ABC):
    """Contract every detection rule implements."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    technique: ClassVar[str | None] = None

    # Engine prefilter. A rule that only cares about authentication should
    # never be handed storage events.
    subscribes_to: ClassVar[frozenset[Category]] = frozenset()

    @abstractmethod
    def evaluate(self, ctx: DetectionContext) -> Iterator[Finding]:
        """Yield zero or more findings. Must not raise."""

    def _finding(
        self,
        ctx: DetectionContext,
        evidence: Sequence[NormalizedEvent],
        **metadata,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            entity_key=ctx.entity_key,
            evidence=list(evidence),
            technique=self.technique,
            metadata=metadata,
        )


class ThresholdRule(Rule):
    """N events matching a predicate within a sliding window.

    Subclasses set `window`, `threshold`, and implement `matches()`.

    Suppression matters here. Once 5 failures inside 10 minutes have fired,
    the 6th, 7th and 8th are the *same* attack -- emitting a finding per event
    would hand the enrichment stage four near-identical incidents to summarize.
    This emits one finding covering the maximal run, then resets only after the
    window drains below threshold.
    """

    window: ClassVar[timedelta]
    threshold: ClassVar[int]

    @abstractmethod
    def matches(self, event: NormalizedEvent) -> bool: ...

    def evaluate(self, ctx: DetectionContext) -> Iterator[Finding]:
        buf: deque[NormalizedEvent] = deque()
        run: list[NormalizedEvent] = []
        firing = False

        for event in ctx.events:
            if not self.matches(event):
                continue

            buf.append(event)
            while buf and (event.timestamp - buf[0].timestamp) > self.window:
                buf.popleft()

            if len(buf) >= self.threshold:
                if not firing:
                    # First breach: the run starts with everything in the
                    # window, not just this event.
                    run = list(buf)
                    firing = True
                else:
                    run.append(event)
            elif firing:
                # Window drained below threshold -- the burst is over.
                yield self._finding(ctx, run, count=len(run), window=str(self.window))
                run, firing = [], False

        if firing:
            yield self._finding(ctx, run, count=len(run), window=str(self.window))


class DistinctThresholdRule(ThresholdRule):
    """N *distinct* values inside a sliding window, not N events.

    Volume and variety are different signals and one log line can carry both.
    Enumeration is the clearest case: sshd emits `Invalid user admin` and
    `Failed password for invalid user admin` for a single attempt, so counting
    events reports six where three accounts were probed. Retrying one username
    twenty times is a brute force, not enumeration -- an event threshold cannot
    tell those apart, and a distinct-value threshold cannot confuse them.

    Subclasses implement `key()` alongside `matches()`. Events whose key is
    None are ignored: an unattributable event contributes nothing to a count of
    how many things were touched.

    Windowing is inherited unchanged -- the same sliding buffer and the same
    single-finding-per-burst suppression. Only the firing test differs, so
    `threshold` here reads as "distinct keys", not "events".
    """

    @abstractmethod
    def key(self, event: NormalizedEvent) -> str | None: ...

    def _distinct(self, events: Iterable[NormalizedEvent]) -> list[str]:
        # dict.fromkeys rather than set(): first-seen order makes the metadata
        # readable and the finding reproducible across runs.
        return list(dict.fromkeys(k for e in events if (k := self.key(e)) is not None))

    def evaluate(self, ctx: DetectionContext) -> Iterator[Finding]:
        buf: deque[NormalizedEvent] = deque()
        run: list[NormalizedEvent] = []
        firing = False

        def _emit(evidence: list[NormalizedEvent]) -> Finding:
            distinct = self._distinct(evidence)
            return self._finding(
                ctx,
                evidence,
                count=len(evidence),
                distinct_count=len(distinct),
                distinct_values=distinct,
                window=str(self.window),
            )

        for event in ctx.events:
            if not self.matches(event) or self.key(event) is None:
                continue

            buf.append(event)
            while buf and (event.timestamp - buf[0].timestamp) > self.window:
                buf.popleft()

            if len(self._distinct(buf)) >= self.threshold:
                if not firing:
                    run = list(buf)
                    firing = True
                else:
                    run.append(event)
            elif firing:
                yield _emit(run)
                run, firing = [], False

        if firing:
            yield _emit(run)


class SequenceRule(Rule):
    """An ordered pattern: something matching A, later something matching B.

    Distinct from ThresholdRule because the signal is *order*, not volume.
    "Failed logins then a success" is the classic case -- neither half is
    interesting alone, and swapping them is a benign login followed by typos.
    """

    window: ClassVar[timedelta]
    min_leading: ClassVar[int] = 1

    @abstractmethod
    def leading(self, event: NormalizedEvent) -> bool: ...

    @abstractmethod
    def trailing(self, event: NormalizedEvent) -> bool: ...

    def evaluate(self, ctx: DetectionContext) -> Iterator[Finding]:
        buf: deque[NormalizedEvent] = deque()

        for event in ctx.events:
            if self.trailing(event) and len(buf) >= self.min_leading:
                while buf and (event.timestamp - buf[0].timestamp) > self.window:
                    buf.popleft()
                if len(buf) >= self.min_leading:
                    yield self._finding(
                        ctx,
                        [*buf, event],
                        leading_count=len(buf),
                        window=str(self.window),
                    )
                    buf.clear()
                    continue

            if self.leading(event):
                buf.append(event)
                while buf and (event.timestamp - buf[0].timestamp) > self.window:
                    buf.popleft()


class SingleEventRule(Rule):
    """One event is the whole signal -- no window, no ordering, no threshold.

    Some actions are worth a finding on sight. Stopping a CloudTrail trail or
    attaching AdministratorAccess needs no corroboration: there is no volume to
    accumulate and nothing to correlate against, so both ThresholdRule (which
    needs N) and SequenceRule (which needs a preceding event) would model it
    wrongly. Forcing these through a windowed base class with `threshold = 1`
    would work by accident and read as though the count mattered.

    Emits one finding per matching event, so the evidence list is always
    exactly the event that fired it.
    """

    @abstractmethod
    def matches(self, event: NormalizedEvent) -> bool: ...

    def evaluate(self, ctx: DetectionContext) -> Iterator[Finding]:
        for event in ctx.events:
            if self.matches(event):
                yield self._finding(ctx, [event])
