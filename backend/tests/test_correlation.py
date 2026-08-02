"""Correlation tests: findings in, incidents out.

Findings are built directly rather than run through the engine. Correlation's
contract is with `Finding`, so a rule threshold change must not be able to break
a test here -- and the noise and gap cases need shapes no sample log produces.
"""

from __future__ import annotations

from datetime import timedelta

from detection_helpers import auth_failure, event, finding

from app.detection.correlation import (
    DEFAULT_MAX_GAP,
    MAX_COOCCURRING_KEYS,
    Incident,
    correlate,
)
from app.detection.rules import Severity

GAP_SECONDS = int(DEFAULT_MAX_GAP.total_seconds())


# ---------------------------------------------------------------------------
# Fan-out collapse
# ---------------------------------------------------------------------------


def test_fanout_copies_collapse_to_one_finding():
    """The engine files one burst under `ip:`, `user:` and `host:`. Those are
    one observation, and an analyst must see it once."""
    evidence = [auth_failure(i) for i in range(5)]
    fanned = [
        finding(rule_id="brute_force_auth", entity_key=key, evidence=evidence)
        for key in ("ip:203.0.113.5", "user:root", "host:web01")
    ]

    incidents = correlate(fanned)

    assert len(incidents) == 1
    assert len(incidents[0].findings) == 1


def test_fanout_collapse_keeps_the_highest_precedence_key():
    """`ip:` outranks `host:` outranks `user:` -- a username is usually the
    target, not the attacker."""
    evidence = [auth_failure(i) for i in range(5)]
    fanned = [
        finding(rule_id="brute_force_auth", entity_key=key, evidence=evidence)
        for key in ("user:root", "host:web01", "ip:203.0.113.5")
    ]

    incident = correlate(fanned)[0]

    assert incident.findings[0].entity_key == "ip:203.0.113.5"
    assert incident.primary_entity == "ip:203.0.113.5"


def test_collapsed_keys_are_retained_on_the_incident():
    """Suppressing the duplicate finding must not discard which entities were
    involved -- that is what an analyst pivots on."""
    evidence = [auth_failure(i) for i in range(5)]
    fanned = [
        finding(rule_id="brute_force_auth", entity_key=key, evidence=evidence)
        for key in ("ip:203.0.113.5", "user:root", "host:web01")
    ]

    incident = correlate(fanned)[0]

    assert incident.entity_keys == {"ip:203.0.113.5", "user:root", "host:web01"}


def test_a_narrower_slice_of_the_same_attack_is_absorbed():
    """The engine scopes each group to its own entity, so the `user:root` copy
    of a burst holds only the failures targeting root -- a strict subset of the
    `ip:` copy. Same attack, narrower slice; showing an analyst both is noise.
    """
    wide = [auth_failure(i) for i in range(16)]
    narrow = wide[:8]

    incident = correlate(
        [
            finding(rule_id="brute_force_auth", entity_key="ip:203.0.113.5",
                    evidence=wide),
            finding(rule_id="brute_force_auth", entity_key="user:root",
                    evidence=narrow),
        ]
    )[0]

    assert len(incident.findings) == 1
    assert len(incident.findings[0].evidence) == 16
    assert incident.findings[0].entity_key == "ip:203.0.113.5"


def test_a_disjoint_finding_from_the_same_rule_survives():
    """Absorption is containment, not same-rule deduplication. Two bursts that
    share no evidence are two observations."""
    first = [auth_failure(i) for i in range(5)]
    second = [auth_failure(1000 + i) for i in range(5)]

    incident = correlate(
        [
            finding(rule_id="brute_force_auth", entity_key="ip:203.0.113.5",
                    evidence=first),
            finding(rule_id="brute_force_auth", entity_key="user:root",
                    evidence=second),
        ]
    )[0]

    assert len(incident.findings) == 2


def test_partial_overlap_is_not_absorbed():
    """Overlapping but not contained: neither is the whole of the other, so
    dropping either would lose evidence."""
    shared = [auth_failure(i) for i in range(5)]
    left = shared + [auth_failure(100)]
    right = shared + [auth_failure(200)]

    incident = correlate(
        [
            finding(rule_id="brute_force_auth", entity_key="ip:203.0.113.5",
                    evidence=left),
            finding(rule_id="brute_force_auth", entity_key="user:root",
                    evidence=right),
        ]
    )[0]

    assert len(incident.findings) == 2


def test_containment_does_not_cross_rules():
    """A subset under a different rule is a second observation of the same
    events, not a duplicate -- absorbing it would delete the multi-rule chain
    that makes an incident worth reading."""
    wide = [auth_failure(i) for i in range(16)]

    incident = correlate(
        [
            finding(rule_id="brute_force_auth", evidence=wide),
            finding(rule_id="invalid_user_enumeration", evidence=wide[:6]),
        ]
    )[0]

    assert incident.rule_ids == {"brute_force_auth", "invalid_user_enumeration"}


def test_different_rules_on_one_entity_are_not_collapsed():
    """Collapse is for copies of one observation, not for distinct rules --
    the multi-rule chain is the story."""
    evidence = [auth_failure(i) for i in range(5)]
    group = [
        finding(rule_id="brute_force_auth", evidence=evidence),
        finding(rule_id="invalid_user_enumeration", evidence=evidence),
    ]

    incident = correlate(group)[0]

    assert incident.rule_ids == {"brute_force_auth", "invalid_user_enumeration"}


# ---------------------------------------------------------------------------
# Time gap
# ---------------------------------------------------------------------------


def test_activity_within_the_gap_is_one_incident():
    early = finding(rule_id="a", evidence=[auth_failure(0)])
    late = finding(rule_id="b", evidence=[auth_failure(GAP_SECONDS)])

    assert len(correlate([early, late])) == 1


def test_gap_plus_one_second_splits_into_two_incidents():
    """Same entity, same keys -- only the silence between them differs."""
    early = finding(rule_id="a", evidence=[auth_failure(0)])
    late = finding(rule_id="b", evidence=[auth_failure(GAP_SECONDS + 1)])

    incidents = correlate([early, late])

    assert len(incidents) == 2
    assert all(len(i.findings) == 1 for i in incidents)


def test_max_gap_is_configurable():
    early = finding(rule_id="a", evidence=[auth_failure(0)])
    late = finding(rule_id="b", evidence=[auth_failure(GAP_SECONDS + 1)])

    widened = correlate([early, late], max_gap=timedelta(seconds=GAP_SECONDS + 1))

    assert len(widened) == 1


def test_a_chain_of_hops_each_within_the_gap_stays_one_incident():
    """Connected components, not pairwise proximity: the first and last
    findings are three gaps apart but the chain is unbroken."""
    chain = [
        finding(rule_id=f"r{n}", evidence=[auth_failure(n * GAP_SECONDS)])
        for n in range(4)
    ]

    assert len(correlate(chain)) == 1


# ---------------------------------------------------------------------------
# Unrelated entities
# ---------------------------------------------------------------------------


def test_unrelated_entities_stay_separate():
    """No shared key, so nothing to join on -- even at the same instant."""
    one = finding(
        entity_key="ip:203.0.113.5",
        evidence=[event(0, source_ip="203.0.113.5", actor_name="alice", host="web01")],
    )
    two = finding(
        entity_key="ip:198.51.100.9",
        evidence=[event(0, source_ip="198.51.100.9", actor_name="bob", host="web02")],
    )

    incidents = correlate([one, two])

    assert len(incidents) == 2
    assert {i.primary_entity for i in incidents} == {
        "ip:203.0.113.5",
        "ip:198.51.100.9",
    }


def test_one_shared_key_is_enough_to_join():
    """The counterpart: same host, different addresses, still one story."""
    one = finding(
        entity_key="ip:203.0.113.5",
        evidence=[event(0, source_ip="203.0.113.5", actor_name="alice", host="web01")],
    )
    two = finding(
        entity_key="ip:198.51.100.9",
        evidence=[event(60, source_ip="198.51.100.9", actor_name="bob", host="web01")],
    )

    assert len(correlate([one, two])) == 1


# ---------------------------------------------------------------------------
# Severity escalation by tactic breadth
# ---------------------------------------------------------------------------


def test_one_tactic_does_not_escalate():
    """Twenty brute-force findings are one tactic and one story."""
    evidence = [auth_failure(0)]
    group = [
        finding(rule_id=f"r{n}", severity=Severity.MEDIUM, technique="T1110",
                evidence=evidence)
        for n in range(20)
    ]

    incident = correlate(group)[0]

    assert incident.tactics == {"credential-access"}
    assert incident.severity is Severity.MEDIUM


#: One technique per tactic in TECHNIQUE_TACTIC, so a test can dial up breadth.
_BY_TACTIC = ["T1110", "T1087", "T1098", "T1562.008", "T1078"]


def _spread(count: int, severity: Severity = Severity.MEDIUM) -> list:
    """`count` findings on one entity, each contributing a distinct tactic."""
    return [
        finding(
            rule_id=f"r{n}",
            severity=severity,
            technique=_BY_TACTIC[n],
            evidence=[auth_failure(n * 60)],
        )
        for n in range(count)
    ]


def test_two_tactics_do_not_escalate():
    """The ordinary shape of a real intrusion. If two reached the top rung,
    nearly every genuine incident would be CRITICAL and the label would stop
    discriminating."""
    incident = correlate(_spread(2))[0]

    assert len(incident.tactics) == 2
    assert incident.severity is Severity.MEDIUM


def test_three_tactics_escalate_one_step():
    incident = correlate(_spread(3))[0]

    assert len(incident.tactics) == 3
    assert incident.severity is Severity.HIGH


def test_four_tactics_still_only_one_step():
    """The rung is 3-4, so four is not a second escalation."""
    incident = correlate(_spread(4))[0]

    assert len(incident.tactics) == 4
    assert incident.severity is Severity.HIGH


def test_five_tactics_escalate_two_steps():
    incident = correlate(_spread(5))[0]

    assert len(incident.tactics) == 5
    assert incident.severity is Severity.CRITICAL


def test_escalation_clamps_at_critical():
    """Five tactics on an already-CRITICAL finding cannot climb past the top."""
    incident = correlate(_spread(5, severity=Severity.CRITICAL))[0]

    assert incident.severity is Severity.CRITICAL


def test_unmapped_technique_contributes_no_tactic():
    """Documents the placeholder's blind spot: an unmapped ID is
    indistinguishable from no technique, so the incident under-escalates until
    the real catalog lands."""
    group = [
        finding(rule_id="a", severity=Severity.MEDIUM, technique="T1110",
                evidence=[auth_failure(0)]),
        finding(rule_id="b", severity=Severity.MEDIUM, technique="T9999",
                evidence=[auth_failure(60)]),
    ]

    incident = correlate(group)[0]

    assert incident.tactics == {"credential-access"}
    assert incident.severity is Severity.MEDIUM


# ---------------------------------------------------------------------------
# Noise suppression by co-occurrence breadth
# ---------------------------------------------------------------------------


def _ambient_background(count: int) -> list:
    """Findings that make `user:root` co-occur with many distinct entities.

    Each carries a unique address and host, so every one contributes two fresh
    keys to root's co-occurrence set while adding nothing to anyone else's.
    """
    return [
        finding(
            rule_id=f"bg{n}",
            entity_key=f"ip:198.51.100.{n}",
            evidence=[
                event(0, source_ip=f"198.51.100.{n}", actor_name="root",
                      host=f"bg-host-{n}")
            ],
        )
        for n in range(count)
    ]


def test_a_key_shared_with_few_entities_still_joins():
    """Control for the noise test: with root touching only these two, it is
    identifying and does the joining."""
    one = finding(
        entity_key="ip:203.0.113.5",
        evidence=[event(0, source_ip="203.0.113.5", actor_name="root", host="web01")],
    )
    two = finding(
        entity_key="ip:203.0.113.9",
        evidence=[event(60, source_ip="203.0.113.9", actor_name="root", host="web02")],
    )

    assert len(correlate([one, two])) == 1


def test_a_key_co_occurring_too_broadly_stops_joining():
    """Same two findings, now with root seen all over the estate. It becomes
    ambient, and the only thing linking them stops linking them.

    Breadth is what makes this work: root is not unusually *frequent* here --
    each background finding mentions it exactly once, same as the two targets.
    A frequency threshold would rank the attacker's own key highest and
    suppress the wrong one.
    """
    one = finding(
        entity_key="ip:203.0.113.5",
        evidence=[event(0, source_ip="203.0.113.5", actor_name="root", host="web01")],
    )
    two = finding(
        entity_key="ip:203.0.113.9",
        evidence=[event(60, source_ip="203.0.113.9", actor_name="root", host="web02")],
    )
    # Each background finding adds 2 fresh keys to root's co-occurrence set.
    background = _ambient_background(MAX_COOCCURRING_KEYS)

    incidents = correlate([one, two, *background])

    joined = [i for i in incidents if len(i.findings) > 1]
    assert joined == []
    assert len(incidents) == 2 + len(background)


def test_a_noisy_key_is_still_recorded_on_the_incident():
    """Suppressing the join is not the same as discarding the information --
    the analyst still needs to know root was involved."""
    target = finding(
        entity_key="user:root",
        evidence=[event(0, source_ip="203.0.113.5", actor_name="root", host="web01")],
    )

    incidents = correlate([target, *_ambient_background(MAX_COOCCURRING_KEYS)])

    root_incident = next(i for i in incidents if "user:root" in i.entity_keys)
    assert root_incident.primary_entity == "user:root"


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_no_findings_means_no_incidents():
    assert correlate([]) == []


def test_untimestamped_evidence_sorts_without_a_type_error():
    """`first_seen` is None when no evidence carries a timestamp, so the sort
    falls back to a floor value. That floor must be tz-aware: comparing a naive
    datetime to the aware ones decision 7 guarantees raises TypeError.

    The engine drops untimestamped events, so this is unreachable from engine
    output -- and reachable from any hand-built Finding, which is what every
    test in this file and any future caller constructs.
    """
    timeless = finding(rule_id="a", evidence=[event(0, timestamp=None)])
    normal = finding(rule_id="b", evidence=[auth_failure(0)])

    incidents = correlate([timeless, normal])  # must not raise

    assert incidents
    assert timeless.first_seen is None


def test_untimestamped_findings_sort_against_each_other():
    """Two floors compared to each other, and to a real timestamp, across
    separate incidents -- which is where the final sort does the comparing."""
    a = finding(rule_id="a", entity_key="ip:198.51.100.1",
                evidence=[event(0, timestamp=None, source_ip="198.51.100.1",
                                host="h1", actor_name="u1")])
    b = finding(rule_id="b", entity_key="ip:198.51.100.2",
                evidence=[event(0, timestamp=None, source_ip="198.51.100.2",
                                host="h2", actor_name="u2")])
    c = finding(rule_id="c", entity_key="ip:203.0.113.5",
                evidence=[event(0, source_ip="203.0.113.5", host="h3",
                                actor_name="u3")])

    incidents = correlate([a, b, c])  # must not raise

    assert len(incidents) == 3


def test_incidents_are_returned_worst_first():
    low = finding(rule_id="a", severity=Severity.LOW, technique="T1110",
                  entity_key="ip:198.51.100.1",
                  evidence=[event(0, source_ip="198.51.100.1", host="h1",
                                  actor_name="u1")])
    high = finding(rule_id="b", severity=Severity.CRITICAL, technique="T1110",
                   entity_key="ip:203.0.113.5",
                   evidence=[event(0, source_ip="203.0.113.5", host="h2",
                                   actor_name="u2")])

    incidents = correlate([low, high])

    assert [i.severity for i in incidents] == [Severity.CRITICAL, Severity.LOW]


def test_incident_ids_are_assigned():
    incidents = correlate(
        [
            finding(rule_id="a", entity_key="ip:198.51.100.1",
                    evidence=[event(0, source_ip="198.51.100.1",
                                    host="h1", actor_name="u1")]),
            finding(rule_id="b", entity_key="ip:203.0.113.5",
                    evidence=[event(0, source_ip="203.0.113.5",
                                    host="h2", actor_name="u2")]),
        ]
    )

    assert all(isinstance(i, Incident) for i in incidents)
    assert {i.incident_id for i in incidents} == {"INC-0001", "INC-0002"}


def test_incident_time_span_covers_every_finding():
    group = [
        finding(rule_id="a", evidence=[auth_failure(0)]),
        finding(rule_id="b", evidence=[auth_failure(600)]),
    ]

    incident = correlate(group)[0]

    assert (incident.last_seen - incident.first_seen).total_seconds() == 600
