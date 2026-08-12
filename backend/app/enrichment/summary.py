"""Deterministic incident summaries.

This module is the floor. It runs before any prompt exists, it runs in every
test, and it runs whenever the LLM is unavailable, slow, or produces output
that fails validation. Nothing here calls a model.

Writing it first is deliberate. If the deterministic path were a stub, an LLM
outage would not degrade output quality -- it would break the pipeline, and
"rules detect, AI explains" would be a claim the architecture could not honour.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from app.detection import attack
from app.detection.correlation import Incident

# Human-readable tactic names. The catalog stores STIX shortnames.
_TACTIC_LABELS = {
    "reconnaissance": "reconnaissance",
    "resource-development": "resource development",
    "initial-access": "initial access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege escalation",
    "defense-evasion": "defense evasion",
    "defense-impairment": "defense impairment",
    "stealth": "stealth",
    "credential-access": "credential access",
    "discovery": "discovery",
    "lateral-movement": "lateral movement",
    "collection": "collection",
    "command-and-control": "command and control",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def tactic_label(shortname: str) -> str:
    return _TACTIC_LABELS.get(shortname, shortname.replace("-", " "))


def _duration(incident: Incident) -> str:
    if not (incident.first_seen and incident.last_seen):
        return "an unknown period"
    delta: timedelta = incident.last_seen - incident.first_seen
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds} seconds"
    if seconds < 3600:
        return f"{seconds // 60} minutes"
    hours, rem = divmod(seconds, 3600)
    return f"{hours}h {rem // 60}m"


def _sources(incident: Incident) -> list[str]:
    seen: Counter[str] = Counter()
    for finding in incident.findings:
        for event in finding.evidence:
            seen[str(event.source_type)] += 1
    return [name for name, _ in seen.most_common()]


def headline(incident: Incident) -> str:
    """One line. This is what shows in a queue listing."""
    n = len(incident.findings)
    tactics = len(incident.tactics)
    return (
        f"{incident.severity.name} incident on {incident.primary_entity}: "
        f"{n} detection{'s' if n != 1 else ''} "
        f"across {tactics} ATT&CK tactic{'s' if tactics != 1 else ''}"
    )


def _span(finding) -> str:
    """`HH:MM:SS` for an instant, `HH:MM:SS-HH:MM:SS` for a run.

    A finding is a span, and rendering only its start hides the containment
    that makes a chain readable: a brute-force burst and the success that
    followed it share a start instant and differ only in where they end.
    Printing one clock also made the column look unsorted once ordering moved
    to `last_seen` -- a long finding that began early would sit below a short
    one that began later while showing the earlier time.
    """
    if not finding.first_seen:
        return "--:--:--"
    start = finding.first_seen.strftime("%H:%M:%S")
    if not finding.last_seen or finding.last_seen == finding.first_seen:
        return start
    return f"{start}-{finding.last_seen.strftime('%H:%M:%S')}"


def timeline(incident: Incident) -> list[str]:
    """One line per finding, chronological. The analyst's working view.

    Ordered by when each finding **ended**, not when it began. A sequence
    rule's evidence starts at its first leading event, so ordering by start
    puts "successful authentication after repeated failures" above the failures
    it is built on -- the effect printed before its cause. End time is what
    separates a burst from the longer chain containing it.

    Untimestamped findings sort last rather than first: a known time is more
    useful than an unknown one. The `is None` flag carries that, and it also
    keeps `None` from ever being compared against a datetime -- tuple
    comparison settles on the flag before reaching the second element, and two
    Nones compare equal there rather than being ordered.
    """
    ordered = sorted(
        incident.findings,
        key=lambda f: (f.last_seen is None, f.last_seen),
    )
    lines: list[str] = []
    for finding in ordered:
        when = _span(finding)
        # A technique that does not resolve degrades to no annotation rather
        # than to a broken one. Unknown and deprecated IDs both land here
        # (decision 8), and neither is worth showing an analyst as though the
        # catalog had confirmed it.
        info = attack.resolve(finding.technique) if finding.technique else None
        technique = f" [{finding.technique} {info.name}]" if info else ""
        n = len(finding.evidence)
        lines.append(
            f"{when}  {finding.title}{technique} "
            f"({n} event{'s' if n != 1 else ''})"
        )
    return lines


def summarize(incident: Incident) -> str:
    """Full deterministic summary. No model, no network, no randomness.

    Deliberately factual rather than interpretive: it states what fired, when,
    against what, and in which order. Explaining *why that matters* is the
    LLM's job -- and when the LLM is unavailable, an analyst reading facts is
    better served than one reading an invented narrative.
    """
    sources = _sources(incident)
    tactic_names = sorted(tactic_label(t) for t in incident.tactics)
    entities = sorted(incident.entity_keys)

    parts = [headline(incident) + "."]

    if incident.first_seen and incident.last_seen:
        parts.append(
            f"Activity ran from {incident.first_seen:%Y-%m-%d %H:%M:%S} to "
            f"{incident.last_seen:%H:%M:%S} UTC, a span of {_duration(incident)}."
        )

    if len(sources) > 1:
        parts.append(
            f"Evidence spans {len(sources)} log sources ({', '.join(sources)}), "
            "which is why these detections were correlated into one incident "
            "rather than treated separately."
        )
    elif sources:
        parts.append(f"All evidence came from {sources[0]}.")

    if tactic_names:
        parts.append(f"Tactics observed: {', '.join(tactic_names)}.")

    parts.append(f"Entities involved: {', '.join(entities)}.")

    body = " ".join(parts)
    return body + "\n\nTimeline:\n" + "\n".join(f"  {line}" for line in timeline(incident))
