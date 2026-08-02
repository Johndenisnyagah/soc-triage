"""Correlation: findings -> incidents.

A finding is "this rule matched this evidence." An incident is "these findings
are the same story." The gap between them is the whole reason an analyst can
read the output.

Design notes:

* Grouping is **connected components over shared entity keys within a time
  gap**. This handles fan-out and chaining with one mechanism: the three
  copies of a burst under `ip:`, `user:` and `host:` merge because they share
  keys, and the later CloudTrail activity merges because it shares `ip:`.
  Special-casing them separately would mean two algorithms that disagree at
  the edges.

* **Not every entity key is worth correlating on.** `user:root` exists on
  every Linux host on earth; joining on it would merge unrelated intrusions
  into one useless mega-incident. Keys are excluded from *joining* by
  cardinality, but still recorded on the incident -- suppressing the join is
  not the same as discarding the information.

* **Severity is driven by breadth of ATT&CK tactic, not count of findings.**
  Twenty brute-force findings are one tactic and one story. Brute force ->
  persistence -> defense evasion is three tactics and a real intrusion. Summing
  severities would let noise inflate; taking the max would rank a full kill
  chain the same as its loudest step.

* **`MAX_COOCCURRING_KEYS` is tunable and currently unvalidated.** The value of
  12 is a guess with no corpus behind it, and it is the first knob to turn when
  output looks wrong in either direction: incidents that swallow unrelated
  activity mean it is too high, incidents that fragment across one attacker
  mean it is too low. Both failures are silent, so it wants revisiting against
  real data rather than more sample logs -- the threshold only has meaning at a
  scale synthetic fixtures do not reach.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.detection import attack
from app.detection.rules import Finding, Severity

# Sort floor for findings carrying no usable timestamp. Aware, not naive:
# `first_seen` is tz-aware per decision 7, and comparing an aware datetime to a
# naive one raises TypeError. Unreachable from engine output -- the engine drops
# untimestamped events -- but reachable from any hand-built Finding, which is
# exactly what correlation tests and future callers construct.
_EPOCH = datetime.min.replace(tzinfo=timezone.utc)

# Gap beyond which activity on the same entity is a separate story.
DEFAULT_MAX_GAP = timedelta(hours=1)

# An entity key co-occurring with more than this many distinct other entities
# is treated as ambient rather than identifying, and is not used to join.
# Unvalidated -- see the module docstring. Tune this before tuning anything else.
MAX_COOCCURRING_KEYS = 12

_KEY_PRECEDENCE = ("principal:", "ip:", "host:", "user:")


@dataclass(slots=True)
class Incident:
    incident_id: str
    findings: list[Finding]
    entity_keys: set[str]
    primary_entity: str
    severity: Severity
    tactics: set[str]

    @property
    def first_seen(self) -> datetime | None:
        stamps = [f.first_seen for f in self.findings if f.first_seen]
        return min(stamps) if stamps else None

    @property
    def last_seen(self) -> datetime | None:
        stamps = [f.last_seen for f in self.findings if f.last_seen]
        return max(stamps) if stamps else None

    @property
    def rule_ids(self) -> set[str]:
        return {f.rule_id for f in self.findings}


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _noisy_keys(findings: list[Finding]) -> set[str]:
    """Keys that touch too many different things to identify anything.

    The measure is **co-occurrence breadth, not frequency**. Frequency cannot
    work: in any batch dominated by a single intrusion the attacker's IP is by
    definition the most frequent key, so a frequency threshold suppresses
    exactly the key that should do the joining.

    Breadth separates the two cases correctly. `user:root` seen alongside forty
    hosts and three hundred addresses is ambient -- root exists everywhere and
    joining on it would merge unrelated intrusions. `ip:203.0.113.5` seen
    alongside one host and one account is identifying, however often it appears.
    """
    cooccur: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        for event in finding.evidence:
            keys = set(event.entity_keys())
            for key in keys:
                cooccur[key] |= keys - {key}
    return {k for k, others in cooccur.items() if len(others) > MAX_COOCCURRING_KEYS}


def _pick_primary(keys: set[str]) -> str:
    """The entity an analyst would pivot on.

    Precedence, not specificity: a cloud principal names an actor exactly, an
    IP names a source, a host names an asset, and a username is usually the
    *target* rather than the attacker.
    """
    for prefix in _KEY_PRECEDENCE:
        matches = sorted(k for k in keys if k.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(keys)[0] if keys else "unknown"


def _severity(findings: list[Finding], tactics: set[str]) -> Severity:
    """Escalate over the loudest finding by how broad the tactic spread is.

    The ladder is deliberately slower than one step per tactic. Two tactics is
    the ordinary shape of a real intrusion -- credential access into
    persistence covers most of them -- so if two reached the top rung, nearly
    every genuine incident would be CRITICAL and the label would stop
    discriminating. Escalation has to be rare to mean anything.
    """
    base = max((f.severity for f in findings), default=Severity.INFO)
    n = len(tactics)
    steps = 2 if n >= 5 else 1 if n >= 3 else 0
    ladder = list(Severity)
    idx = min(ladder.index(base) + steps, len(ladder) - 1)
    return ladder[idx]


def _collapse_fanout(group: list[Finding]) -> list[Finding]:
    """Absorb findings whose evidence is contained in a broader one.

    The engine emits a finding per entity key an event touches, and scopes each
    group to that entity -- so the copies are not merely duplicates, they are
    *different slices of one attack*. A burst against `ip:203.0.113.5` spanning
    16 failures appears under `user:root` as the 8 that targeted root. Exact
    matching leaves both, and an analyst reads the same attack twice at two
    widths.

    So: keep the widest evidence per rule, and drop anything contained in it.
    Sorting by evidence size descending means a finding can only ever be a
    subset of one already kept. Equal-sized copies are mutual subsets, and the
    tie-break keeps the highest-precedence key -- preserving the original
    behaviour for true duplicates.

    Containment is per `rule_id`. Two different rules over overlapping evidence
    are two observations of one event sequence, not one observation seen twice,
    and collapsing across rules would delete the multi-rule chain that makes an
    incident worth reading.

    Nothing is lost: entity keys are gathered onto the incident before this
    runs.
    """
    ordered = sorted(
        group,
        key=lambda f: (-len(f.evidence), _key_rank(f.entity_key), f.entity_key),
    )

    kept: list[tuple[Finding, frozenset[str]]] = []
    for finding in ordered:
        signature = frozenset(e.dedup_hash() for e in finding.evidence)
        if any(
            finding.rule_id == other.rule_id and signature <= other_signature
            for other, other_signature in kept
        ):
            continue
        kept.append((finding, signature))
    return [finding for finding, _ in kept]


def _key_rank(key: str) -> int:
    for rank, prefix in enumerate(_KEY_PRECEDENCE):
        if key.startswith(prefix):
            return rank
    return len(_KEY_PRECEDENCE)


def correlate(
    findings: list[Finding], *, max_gap: timedelta = DEFAULT_MAX_GAP
) -> list[Incident]:
    if not findings:
        return []

    noisy = _noisy_keys(findings)

    # Join on every key the *evidence* touches, not merely the key the finding
    # was filed under. The engine emits one copy of a burst per entity key, so
    # joining on `f.entity_key` alone would leave those copies unjoined -- the
    # exact fan-out this stage exists to collapse.
    by_key: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(findings):
        keys = {k for e in f.evidence for k in e.entity_keys()} | {f.entity_key}
        for key in keys - noisy:
            by_key[key].append(i)

    uf = _UnionFind(len(findings))
    for indices in by_key.values():
        ordered = sorted(
            indices, key=lambda i: findings[i].first_seen or _EPOCH
        )
        for a, b in zip(ordered, ordered[1:]):
            fa, fb = findings[a], findings[b]
            if fa.last_seen and fb.first_seen and (fb.first_seen - fa.last_seen) > max_gap:
                continue  # gap breaks the chain; b starts a new story
            uf.union(a, b)

    groups: dict[int, list[Finding]] = defaultdict(list)
    for i, f in enumerate(findings):
        groups[uf.find(i)].append(f)

    incidents: list[Incident] = []
    for n, group in enumerate(groups.values(), start=1):
        keys = {f.entity_key for f in group}
        group = _collapse_fanout(group)
        # `f.technique` only, never `f.proposed_technique`. Severity is a
        # function of this set, so reading a model-supplied technique here would
        # let the LLM escalate an incident -- re-scoring by another name.
        # Unvalidated IDs contribute nothing: `tactics_for` returns empty for
        # unknown and deprecated alike.
        tactics = {
            tactic for f in group for tactic in attack.tactics_for(f.technique)
        }
        incidents.append(
            Incident(
                incident_id=f"INC-{n:04d}",
                findings=sorted(group, key=lambda f: f.severity, reverse=True),
                entity_keys=keys,
                primary_entity=_pick_primary(keys),
                severity=_severity(group, tactics),
                tactics=tactics,
            )
        )

    incidents.sort(key=lambda i: (i.severity, i.first_seen or _EPOCH), reverse=True)
    return incidents
