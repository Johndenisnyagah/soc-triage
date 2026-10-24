"""Score detection and correlation against the labelled corpus.

Scoring runs over *persisted* events (decision 13): the corpus is uploaded
through the real ingest endpoint, read back, and only then handed to the rules.
Scoring a parser's raw output would count events dedup would have collapsed.

Two levels are scored, because they fail differently:

* **Findings.** Did each expected detection fire (hit), did any fail to (miss),
  and did benign activity produce any (false positive)? A finding matches an
  expectation when its rule matches and the expected anchor key appears in its
  evidence. Every produced finding is classified exactly once: a detection, a
  false positive (it touches benign activity and matches no expectation), or
  an extra rule firing on malicious activity.
* **Incidents.** Each finding is attributed to the scenarios whose keys its
  evidence touches. A malicious scenario is *isolated* when all its findings
  sit in one incident that contains nothing else, *split* when they spread
  over several, and *merged* when its incident also holds another scenario's
  findings. This is the level `MAX_COOCCURRING_KEYS` changes.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from dataclasses import dataclass, field

from app.detection import correlation
from app.detection.correlation import Incident, correlate
from app.detection.engine import run_rules
from app.detection.rules import Finding

from .corpus import YEAR, Expected, Scenario


def ingest(client, syslog: str, cloudtrail: str) -> None:
    """Upload the corpus through the real endpoint."""
    for name, body in (("auth.log", syslog), ("cloudtrail.json", cloudtrail)):
        response = client.post(
            "/api/ingest",
            files={"file": (name, body.encode(), "text/plain")},
            data={"default_year": str(YEAR)},
        )
        if response.status_code != 201:
            raise RuntimeError(f"ingest of {name} failed: {response.status_code} {response.text}")


def load_events(session) -> list:
    from app.models import Event

    rows = session.query(Event).order_by(Event.timestamp).all()
    return [row.to_normalized() for row in rows]


@contextlib.contextmanager
def max_cooccurring_keys(value: int) -> Iterator[None]:
    """Temporarily set the correlation noise threshold."""
    original = correlation.MAX_COOCCURRING_KEYS
    correlation.MAX_COOCCURRING_KEYS = value
    try:
        yield
    finally:
        correlation.MAX_COOCCURRING_KEYS = original


def _evidence_keys(finding: Finding) -> set[str]:
    return {key for event in finding.evidence for key in event.entity_keys()}


@dataclass
class ScenarioResult:
    scenario: Scenario
    hits: list[Expected] = field(default_factory=list)
    misses: list[Expected] = field(default_factory=list)
    incidents: set[str] = field(default_factory=set)
    merged_with: set[str] = field(default_factory=set)

    @property
    def detected(self) -> bool:
        return bool(self.hits)

    @property
    def split(self) -> bool:
        return len(self.incidents) > 1

    @property
    def merged(self) -> bool:
        return bool(self.merged_with)

    @property
    def isolated(self) -> bool:
        return self.detected and not self.split and not self.merged


@dataclass
class Classified:
    """One produced finding and what the scorer decided it was."""

    finding: Finding
    incident_id: str
    owners: set[str]
    #: "detection", "duplicate", "false_positive", "extra" or "unattributed"
    kind: str


@dataclass
class Run:
    max_cooccurring_keys: int
    incidents: list[Incident]
    results: dict[str, ScenarioResult]
    findings: list[Classified]

    def _malicious(self) -> list[ScenarioResult]:
        return [r for r in self.results.values() if r.scenario.malicious]

    def _benign(self) -> list[ScenarioResult]:
        return [r for r in self.results.values() if not r.scenario.malicious]

    def of_kind(self, kind: str) -> list[Classified]:
        return [c for c in self.findings if c.kind == kind]

    @property
    def expected_total(self) -> int:
        return sum(len(r.scenario.expected) for r in self._malicious())

    @property
    def hits(self) -> int:
        return sum(len(r.hits) for r in self._malicious())

    @property
    def detected(self) -> list[ScenarioResult]:
        return [r for r in self._malicious() if r.detected]

    @property
    def malicious_total(self) -> int:
        return len(self._malicious())

    @property
    def benign_total(self) -> int:
        return len(self._benign())

    def benign_flagged(self) -> set[str]:
        return {o for c in self.of_kind("false_positive") for o in c.owners
                if not self.results[o].scenario.malicious}

    @property
    def mixed(self) -> list[Classified]:
        """Single findings whose evidence spans more than one scenario.

        Correlation cannot separate these at any threshold: the merge happened
        inside a rule, before correlation ran.
        """
        return [c for c in self.findings if len(c.owners) > 1]

    def count(self, attr: str) -> int:
        return sum(1 for r in self.detected if getattr(r, attr))


def evaluate(events: list, scenarios: list[Scenario], *, max_keys: int) -> Run:
    with max_cooccurring_keys(max_keys):
        incidents = correlate(run_rules(events).findings)

    results = {s.name: ScenarioResult(s) for s in scenarios}
    benign = {s.name for s in scenarios if not s.malicious}
    produced = [(inc, f, _evidence_keys(f)) for inc in incidents for f in inc.findings]

    def owners_of(keys: set[str]) -> set[str]:
        return {s.name for s in scenarios if s.owns & keys}

    # A finding may satisfy several expectations: one `user:root` burst can be
    # the detection of four scanners at once. Being covered by a shared alert is
    # a correlation question, scored at incident level -- not a missed detection.
    matches: dict[int, set[str]] = {}
    for scenario in scenarios:
        for exp in scenario.expected:
            # The anchor alone is not enough: `host:web03` is touched by the
            # spray too. A hit must contain this scenario's own events.
            hit = [i for i, (_, f, keys) in enumerate(produced)
                   if f.rule_id == exp.rule_id and exp.anchor in keys
                   and scenario.owns & keys]
            if hit:
                results[scenario.name].hits.append(exp)
                for i in hit:
                    matches.setdefault(i, set()).add(scenario.name)
            else:
                results[scenario.name].misses.append(exp)

    classified: list[Classified] = []
    for i, (inc, f, keys) in enumerate(produced):
        owners = owners_of(keys) | matches.get(i, set())
        if i in matches:
            kind = "detection"
        elif not owners:
            kind = "unattributed"
        elif owners & benign:
            # Any benign activity in a finding nobody expected makes it a false
            # positive, even when an attacker's events are in it too: the alert
            # is telling the analyst something that is not true.
            kind = "false_positive"
        else:
            kind = "extra"  # an unexpected rule, but on malicious activity
        classified.append(Classified(f, inc.incident_id, owners, kind))

    by_incident: dict[str, set[str]] = {}
    for c in classified:
        by_incident.setdefault(c.incident_id, set()).update(c.owners)
        for name in c.owners:
            results[name].incidents.add(c.incident_id)
    for result in results.values():
        for incident_id in result.incidents:
            result.merged_with |= by_incident[incident_id] - {result.scenario.name}

    return Run(max_keys, incidents, results, classified)


def corpus_stats(syslog: str, cloudtrail: str) -> tuple[int, int]:
    return len(syslog.splitlines()), len(json.loads(cloudtrail)["Records"])
