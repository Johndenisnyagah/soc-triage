"""Rule registry and the pass that runs every rule over every entity group.

Mirrors `app.ingest.base`: a `@register` class decorator appends to a module
level list, and importing the module that defines the rules is what fills it.
The side-effect import lives in `app/detection/__init__.py`, not in a consumer
-- see that file for why.

The grouping happens once, here, for all rules. Two consequences worth naming:

* An event belongs to as many groups as it has entity keys. One sshd failure
  emits `ip:`, `user:` and `host:`, so a brute-force rule can fire three times
  on the same underlying evidence -- once per entity. That is intended: "this
  IP is brute forcing" and "this account is being brute forced" are different
  findings an analyst pivots on differently. Collapsing overlapping findings
  into a single incident is the correlation stage's job, not the engine's.

* Events without a timestamp are dropped before grouping. Every base class
  does timestamp arithmetic, so an unplaceable event would either crash a rule
  or, worse, be silently treated as "now" and fabricate a correlation that
  never happened. Dropping is counted and returned so it is never invisible.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from app.ingest.schema import NormalizedEvent

from .rules import DetectionContext, Finding, Rule

_REGISTRY: list[type[Rule]] = []


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator. Import the rule module to register it."""
    _REGISTRY.append(cls)
    return cls


def registered_rules() -> list[type[Rule]]:
    return list(_REGISTRY)


@dataclass(slots=True)
class DetectionStats:
    """What the pass did, so an empty result is explainable.

    "No findings" and "no events the rules could place" look identical from a
    findings list alone.
    """

    events_in: int = 0
    events_without_timestamp: int = 0
    entities: int = 0
    rules_run: int = 0
    findings: int = 0


@dataclass(slots=True)
class DetectionResult:
    findings: list[Finding] = field(default_factory=list)
    stats: DetectionStats = field(default_factory=DetectionStats)

    def by_entity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in self.findings:
            grouped[finding.entity_key].append(finding)
        return dict(grouped)


def group_by_entity(
    events: Iterable[NormalizedEvent],
) -> tuple[dict[str, list[NormalizedEvent]], int]:
    """Bucket events by entity key, sorted by timestamp within each bucket.

    Returns the groups and the count of events dropped for having no timestamp.
    """
    groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
    dropped = 0

    for event in events:
        if event.timestamp is None:
            dropped += 1
            continue
        for key in event.entity_keys():
            groups[key].append(event)

    for bucket in groups.values():
        bucket.sort(key=lambda e: e.timestamp)

    return dict(groups), dropped


def run_rules(
    events: Sequence[NormalizedEvent],
    *,
    rules: Sequence[type[Rule]] | None = None,
) -> DetectionResult:
    """Run every registered rule over every entity group.

    `rules` overrides the registry -- tests use it to exercise one rule in
    isolation without the others' findings as noise.
    """
    rule_classes = list(rules) if rules is not None else registered_rules()
    groups, dropped = group_by_entity(events)

    stats = DetectionStats(
        events_in=len(events),
        events_without_timestamp=dropped,
        entities=len(groups),
        rules_run=len(rule_classes),
    )

    findings: list[Finding] = []
    # Sorted so a run over the same input yields findings in the same order
    # every time; downstream stages and test assertions both depend on it.
    for entity_key in sorted(groups):
        bucket = groups[entity_key]
        for rule_cls in rule_classes:
            rule = rule_cls()
            scoped = _prefilter(bucket, rule_cls)
            if not scoped:
                continue
            findings.extend(rule.evaluate(DetectionContext(entity_key, scoped)))

    stats.findings = len(findings)
    return DetectionResult(findings=findings, stats=stats)


def _prefilter(
    events: list[NormalizedEvent], rule_cls: type[Rule]
) -> list[NormalizedEvent]:
    """Narrow a group to the categories a rule subscribes to.

    An empty `subscribes_to` means "everything" rather than "nothing" -- the
    base class default, so a rule that forgets to declare still sees events
    instead of silently never firing.
    """
    if not rule_cls.subscribes_to:
        return events
    return [e for e in events if e.category in rule_cls.subscribes_to]
