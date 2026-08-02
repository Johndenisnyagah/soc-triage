"""Engine tests: grouping, ordering, prefiltering, and the timestamp drop.

These cover the guarantees `DetectionContext` documents but no individual rule
can enforce -- a rule that receives unsorted events produces wrong answers
silently, so the ordering guarantee has to be tested where it is made.
"""

from __future__ import annotations

from datetime import timedelta

from detection_helpers import (
    BASE,
    auth_failure,
    auth_success,
    event,
    logging_stopped,
)

from app.detection.engine import group_by_entity, registered_rules, run_rules
from app.detection.rules import DetectionContext, Finding, Rule, Severity
from app.ingest.schema import Category, Outcome


class _Collector(Rule):
    """Records what the engine handed it, so prefiltering is observable."""

    rule_id = "collector"
    title = "collector"
    severity = Severity.INFO
    subscribes_to = frozenset({Category.AUTHENTICATION})

    seen: list[DetectionContext] = []

    def evaluate(self, ctx):
        type(self).seen.append(ctx)
        return iter(())


def _reset_collector():
    _Collector.seen = []


# -- grouping ---------------------------------------------------------------


def test_events_are_grouped_by_every_entity_key_they_touch():
    groups, dropped = group_by_entity([auth_failure(0)])

    assert dropped == 0
    # One event, three entities: address, account, and asset.
    assert set(groups) == {"ip:203.0.113.5", "user:root", "host:web01"}


def test_groups_are_sorted_by_timestamp_regardless_of_input_order():
    events = [auth_failure(300), auth_failure(0), auth_failure(120)]

    groups, _ = group_by_entity(events)

    stamps = [e.timestamp for e in groups["ip:203.0.113.5"]]
    assert stamps == sorted(stamps)
    assert stamps[0] == BASE


def test_events_from_different_sources_share_an_entity_group():
    """The whole point of entity keys: an sshd failure and a CloudTrail key
    creation from one address land in one group."""
    from detection_helpers import access_key_created

    groups, _ = group_by_entity([auth_failure(0), access_key_created(60)])

    bucket = groups["ip:203.0.113.5"]
    assert len(bucket) == 2
    assert {e.source_type for e in bucket} == {"syslog_sshd", "aws_cloudtrail"}


# -- the timestamp drop -----------------------------------------------------


def test_events_without_a_timestamp_are_dropped_before_grouping():
    """A windowed rule cannot place them, and calling them "now" would invent
    a correlation that never happened."""
    events = [auth_failure(0), event(0, timestamp=None)]

    groups, dropped = group_by_entity(events)

    assert dropped == 1
    assert len(groups["ip:203.0.113.5"]) == 1


def test_dropped_count_is_reported_rather_than_swallowed():
    result = run_rules([event(0, timestamp=None)], rules=[])

    assert result.stats.events_in == 1
    assert result.stats.events_without_timestamp == 1
    assert result.stats.entities == 0


# -- prefiltering -----------------------------------------------------------


def test_rules_only_receive_categories_they_subscribe_to():
    _reset_collector()
    events = [auth_failure(0), logging_stopped(60, source_ip="203.0.113.5")]

    run_rules(events, rules=[_Collector])

    for ctx in _Collector.seen:
        assert all(e.category is Category.AUTHENTICATION for e in ctx.events)


def test_a_rule_is_skipped_entirely_when_nothing_survives_the_prefilter():
    _reset_collector()

    run_rules([logging_stopped(0)], rules=[_Collector])

    assert _Collector.seen == []


def test_an_empty_subscribes_to_means_everything():
    """The base-class default must not silently mean "never fires"."""

    class _All(_Collector):
        rule_id = "all"
        subscribes_to = frozenset()
        seen: list[DetectionContext] = []

    run_rules([logging_stopped(0)], rules=[_All])

    assert _All.seen != []


# -- the pass ---------------------------------------------------------------


def test_findings_are_returned_for_every_entity_the_rule_matched():
    """One burst, three entities -- the address, the targeted account, and the
    host. Collapsing these is the correlation stage's job, not the engine's."""
    from app.detection.library import BruteForceAuthentication

    result = run_rules(
        [auth_failure(i) for i in range(5)], rules=[BruteForceAuthentication]
    )

    assert {f.entity_key for f in result.findings} == {
        "ip:203.0.113.5",
        "user:root",
        "host:web01",
    }
    assert result.stats.findings == 3


def test_findings_are_ordered_deterministically():
    from app.detection.library import BruteForceAuthentication

    events = [auth_failure(i) for i in range(5)]
    first = run_rules(events, rules=[BruteForceAuthentication])
    second = run_rules(list(reversed(events)), rules=[BruteForceAuthentication])

    assert [f.entity_key for f in first.findings] == [
        f.entity_key for f in second.findings
    ]


def test_by_entity_groups_findings():
    from app.detection.library import BruteForceAuthentication

    result = run_rules(
        [auth_failure(i) for i in range(5)], rules=[BruteForceAuthentication]
    )

    grouped = result.by_entity()
    assert set(grouped) == {"ip:203.0.113.5", "user:root", "host:web01"}
    assert all(len(v) == 1 for v in grouped.values())


def test_empty_input_produces_no_findings_and_honest_stats():
    result = run_rules([])

    assert result.findings == []
    assert result.stats.entities == 0
    assert result.stats.rules_run == len(registered_rules())


def test_the_registry_holds_all_six_rules():
    assert len(registered_rules()) == 6
