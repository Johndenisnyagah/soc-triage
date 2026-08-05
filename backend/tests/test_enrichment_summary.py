"""Deterministic summary tests.

The summarizer is the floor: it is what an analyst reads whenever the LLM is
unavailable or its output fails the gate (decision 15). So these tests hold it
to the standard of a finished product rather than a placeholder -- exact
wording, exact pluralisation, and graceful degradation on the two inputs that
would otherwise crash it: an incident with no timestamps at all, and a finding
whose technique does not resolve in the catalog.

Incidents are built by running `correlate()` over hand-made findings rather
than by constructing `Incident` directly. Severity and tactic sets are derived
there, and a summary asserting a severity the correlator would never produce
would pass while describing an incident that cannot exist.
"""

from __future__ import annotations

from detection_helpers import (
    BASE,
    access_key_created,
    auth_failure,
    event,
    finding,
    logging_stopped,
)

from app.detection.correlation import Incident, correlate
from app.detection.rules import Severity
from app.enrichment.summary import headline, summarize, timeline


def sample_incident() -> Incident:
    """The reference incident: one intrusion, two sources, three rules.

    Brute force on SSH, then an access key minted from the same address, then
    the audit trail stopped. Four distinct tactics over three HIGH findings, so
    correlation escalates it one rung to CRITICAL -- the shape decision 14 is
    built to recognise, and the one the snapshot below pins.
    """
    return correlate(
        [
            finding(
                rule_id="brute_force_auth",
                title="Repeated authentication failures",
                severity=Severity.HIGH,
                entity_key="ip:203.0.113.5",
                technique="T1110",
                evidence=[auth_failure(i * 30) for i in range(6)],
            ),
            finding(
                rule_id="access_key_after_suspicious_auth",
                title="Access key created after suspicious authentication",
                severity=Severity.HIGH,
                entity_key="user:root",
                technique="T1098",
                evidence=[access_key_created(900)],
            ),
            finding(
                rule_id="cloud_logging_disabled",
                title="Cloud audit logging disabled",
                severity=Severity.HIGH,
                entity_key="host:web01",
                technique="T1685.002",
                evidence=[logging_stopped(1200)],
            ),
        ]
    )[0]


# ---------------------------------------------------------------------------
# Source phrasing
# ---------------------------------------------------------------------------


def test_single_source_incident_says_so_plainly():
    """One source is not a correlation story, so it does not get told as one."""
    incident = correlate(
        [finding(rule_id="brute_force_auth", evidence=[auth_failure(i) for i in range(5)])]
    )[0]

    summary = summarize(incident)

    assert "All evidence came from syslog_sshd." in summary
    assert "log sources" not in summary


def test_multi_source_incident_names_the_sources_and_why_they_joined():
    """Cross-source correlation is the claim the pipeline makes, so the summary
    states it rather than leaving the analyst to infer it from the evidence."""
    summary = summarize(sample_incident())

    assert (
        "Evidence spans 2 log sources (syslog_sshd, aws_cloudtrail), which is "
        "why these detections were correlated into one incident rather than "
        "treated separately." in summary
    )
    assert "All evidence came from" not in summary


def test_sources_are_ordered_by_how_much_evidence_each_contributed():
    """Most-common first: the source that carries the incident is named first,
    not whichever happened to sort alphabetically."""
    summary = summarize(sample_incident())

    assert "(syslog_sshd, aws_cloudtrail)" in summary


# ---------------------------------------------------------------------------
# Missing timestamps
# ---------------------------------------------------------------------------


def _untimestamped_incident() -> Incident:
    return correlate(
        [
            finding(rule_id="a", evidence=[event(0, timestamp=None)]),
            finding(rule_id="b", evidence=[event(1, timestamp=None)]),
        ]
    )[0]


def test_an_incident_with_no_timestamps_summarizes_without_raising():
    """Two findings with nothing to order them by, which is the input that puts
    two Nones next to each other in the chronological sort.

    Correlation's final sort needs an explicit tz-aware floor for this; the
    timeline's does not, because its key leads with an `is None` flag and tuple
    comparison never reaches the second element when both are None. That is a
    real distinction between two sorts that look alike, so it is pinned rather
    than assumed.

    Unreachable from engine output, which drops untimestamped events, and
    reachable from any hand-built Finding.
    """
    incident = _untimestamped_incident()

    summary = summarize(incident)  # must not raise

    assert incident.first_seen is None
    assert len(incident.findings) == 2


def test_a_timeless_incident_omits_the_span_sentence():
    """Better to say nothing than to print a span of zero, which would read as
    a real instantaneous event."""
    summary = summarize(_untimestamped_incident())

    assert "Activity ran from" not in summary
    assert "span of" not in summary


def test_timeless_findings_show_a_placeholder_clock():
    lines = timeline(_untimestamped_incident())

    assert len(lines) == 2
    assert all(line.startswith("--:--:--  ") for line in lines)


def test_untimestamped_findings_sort_last():
    """A known time is more useful than an unknown one, so the placed findings
    come first and the unplaceable ones trail."""
    incident = correlate(
        [
            finding(rule_id="a", evidence=[event(0, timestamp=None)]),
            finding(rule_id="b", evidence=[auth_failure(60)]),
        ]
    )[0]

    lines = timeline(incident)

    assert not lines[0].startswith("--:--:--")
    assert lines[1].startswith("--:--:--")


# ---------------------------------------------------------------------------
# Unresolvable techniques
# ---------------------------------------------------------------------------


def test_an_unknown_technique_degrades_to_no_annotation():
    """`resolve()` returns None for an ID the catalog does not carry. The
    timeline drops the annotation rather than printing a technique name it does
    not have -- and rather than raising on `info.name`."""
    incident = correlate([finding(rule_id="a", technique="T9999")])[0]

    lines = timeline(incident)  # must not raise

    assert lines[0].endswith("(1 event)")
    assert "T9999" not in lines[0]


def test_a_deprecated_technique_degrades_identically():
    """Decision 8: unknown and deprecated are the same answer downstream. A
    retired ID must not be displayed as though the catalog confirmed it.

    T1562.008 was revoked by T1685.002 in ATT&CK v19.0.
    """
    incident = correlate([finding(rule_id="a", technique="T1562.008")])[0]

    lines = timeline(incident)

    assert "T1562.008" not in lines[0]
    assert incident.tactics == set()


def test_a_resolvable_technique_is_annotated_with_its_catalog_name():
    """The control for the two above: when the ID does resolve, the analyst
    sees the name, so an absent annotation reads as 'did not resolve' rather
    than 'this summarizer never annotates'."""
    incident = correlate([finding(rule_id="a", technique="T1110")])[0]

    assert "[T1110 Brute Force]" in timeline(incident)[0]


# ---------------------------------------------------------------------------
# Pluralisation
# ---------------------------------------------------------------------------


def test_a_single_event_finding_reads_1_event():
    """'1 events' in a report an analyst hands upward is the kind of detail
    that costs the whole document its credibility."""
    incident = correlate([finding(rule_id="a", evidence=[auth_failure(0)])])[0]

    assert timeline(incident)[0].endswith("(1 event)")


def test_a_multi_event_finding_reads_n_events():
    incident = correlate(
        [finding(rule_id="a", evidence=[auth_failure(i) for i in range(6)])]
    )[0]

    assert timeline(incident)[0].endswith("(6 events)")


def test_the_headline_pluralises_detections_and_tactics_independently():
    single = correlate([finding(rule_id="a", technique="T1110")])[0]

    assert headline(single) == (
        "HIGH incident on ip:203.0.113.5: 1 detection across 1 ATT&CK tactic"
    )
    assert headline(sample_incident()) == (
        "CRITICAL incident on ip:203.0.113.5: 3 detections across 4 ATT&CK tactics"
    )


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


EXPECTED_SAMPLE_SUMMARY = """\
CRITICAL incident on ip:203.0.113.5: 3 detections across 4 ATT&CK tactics. \
Activity ran from 2026-08-02 04:41:00 to 05:01:00 UTC, a span of 20 minutes. \
Evidence spans 2 log sources (syslog_sshd, aws_cloudtrail), which is why these \
detections were correlated into one incident rather than treated separately. \
Tactics observed: credential access, defense impairment, persistence, \
privilege escalation. Entities involved: host:web01, ip:203.0.113.5, user:root.

Timeline:
  04:41:00  Repeated authentication failures [T1110 Brute Force] (6 events)
  04:56:00  Access key created after suspicious authentication \
[T1098 Account Manipulation] (1 event)
  05:01:00  Cloud audit logging disabled \
[T1685.002 Disable or Modify Cloud Log] (1 event)"""


def test_sample_incident_summary_snapshot():
    """The whole output, byte for byte.

    A snapshot rather than a set of substring assertions because the summary is
    a deliverable, not a data structure: sentence order, spacing and the join
    between prose and timeline are all part of whether it reads well, and none
    of them are covered by asserting that a phrase appears somewhere.

    Technique names are pinned deliberately. They come from the committed
    catalog, so a rename in a future ATT&CK release fails here and gets looked
    at -- which is the same posture decision 8 takes towards technique IDs.
    """
    assert summarize(sample_incident()) == EXPECTED_SAMPLE_SUMMARY


def test_the_snapshot_incident_is_the_one_correlation_actually_builds():
    """Guards the snapshot against being a description of a fixture nobody
    could produce: if the severity ladder or the tactic set moved, the snapshot
    would need updating for a real reason, and this says which."""
    incident = sample_incident()

    assert incident.severity is Severity.CRITICAL
    assert incident.tactics == {
        "credential-access",
        "defense-impairment",
        "persistence",
        "privilege-escalation",
    }
    assert incident.first_seen == BASE
