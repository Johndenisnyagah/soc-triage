"""Per-rule tests: positive, negative, and boundary for each of the six.

The boundary cases are the ones that matter. A threshold rule that fires at
N-1 is a false-positive generator; one that needs N+1 silently misses the
attack it was written for. Both look fine in a positive-only test.

Every window here is expressed in seconds from BASE, so `at(600)` is exactly
on a ten-minute edge and `at(601)` is one second past it. The base classes
prune with `>`, so an event landing exactly on the window edge is *inside* it
-- each rule asserts that explicitly rather than leaving it to inference.
"""

from __future__ import annotations

from detection_helpers import (
    access_key_created,
    auth_failure,
    auth_success,
    event,
    findings,
    invalid_user_failure,
    logging_stopped,
    policy_attached,
)

from app.detection.library import (
    AccessKeyAfterSuspiciousAuth,
    AdminPolicyAttached,
    BruteForceAuthentication,
    CloudLoggingDisabled,
    InvalidUserEnumeration,
    SuccessfulLoginAfterBruteForce,
)
from app.ingest.schema import Category, Outcome

WINDOW = 600  # seconds; brute-force and enumeration both use ten minutes


# ---------------------------------------------------------------------------
# 1. Brute force -- threshold 5 / 10 min
# ---------------------------------------------------------------------------


def test_brute_force_fires_at_threshold():
    result = findings(
        BruteForceAuthentication(), [auth_failure(i) for i in range(5)]
    )

    assert len(result) == 1
    assert result[0].rule_id == "brute_force_auth"
    assert result[0].technique == "T1110"
    assert result[0].metadata["count"] == 5
    assert len(result[0].evidence) == 5


def test_brute_force_ignores_successes():
    """Volume alone is not the signal -- five clean logins are not an attack."""
    assert findings(BruteForceAuthentication(), [auth_success(i) for i in range(5)]) == []


def test_brute_force_does_not_fire_one_below_threshold():
    assert findings(BruteForceAuthentication(), [auth_failure(i) for i in range(4)]) == []


def test_brute_force_fires_exactly_on_the_window_edge():
    """Fifth failure exactly `window` after the first is still inside it."""
    events = [auth_failure(0), *(auth_failure(1 + i) for i in range(3)), auth_failure(WINDOW)]

    result = findings(BruteForceAuthentication(), events)

    assert len(result) == 1
    assert result[0].metadata["count"] == 5


def test_brute_force_misses_when_the_window_is_exceeded_by_one_second():
    """Same five failures, one second wider -- the first ages out and the
    window holds only four."""
    events = [
        auth_failure(0),
        *(auth_failure(1 + i) for i in range(3)),
        auth_failure(WINDOW + 1),
    ]

    assert findings(BruteForceAuthentication(), events) == []


def test_brute_force_suppresses_a_continuing_burst_into_one_finding():
    """Ten failures are one attack, not six overlapping ones."""
    result = findings(BruteForceAuthentication(), [auth_failure(i) for i in range(10)])

    assert len(result) == 1
    assert result[0].metadata["count"] == 10


def test_brute_force_reports_two_separate_bursts_separately():
    early = [auth_failure(i) for i in range(5)]
    late = [auth_failure(10 * WINDOW + i) for i in range(5)]

    result = findings(BruteForceAuthentication(), early + late)

    assert len(result) == 2


# ---------------------------------------------------------------------------
# 2. Successful login after brute force -- sequence, min_leading 5 / 10 min
# ---------------------------------------------------------------------------


def test_success_after_brute_force_fires():
    events = [*(auth_failure(i) for i in range(5)), auth_success(10)]

    result = findings(SuccessfulLoginAfterBruteForce(), events)

    assert len(result) == 1
    assert result[0].severity == 90  # CRITICAL
    assert result[0].technique == "T1110"
    assert result[0].metadata["leading_count"] == 5
    # Evidence is the burst *and* the success -- the pattern, not just its tail.
    assert len(result[0].evidence) == 6
    assert result[0].evidence[-1].outcome is Outcome.SUCCESS


def test_success_before_failures_is_not_the_pattern():
    """Order is the entire signal. A login then typos is somebody who is
    already in, and must not read as a compromise."""
    events = [auth_success(0), *(auth_failure(1 + i) for i in range(5))]

    assert findings(SuccessfulLoginAfterBruteForce(), events) == []


def test_success_after_too_few_failures_does_not_fire():
    events = [*(auth_failure(i) for i in range(4)), auth_success(10)]

    assert findings(SuccessfulLoginAfterBruteForce(), events) == []


def test_success_exactly_on_the_window_edge_fires():
    events = [*(auth_failure(i) for i in range(5)), auth_success(WINDOW)]

    assert len(findings(SuccessfulLoginAfterBruteForce(), events)) == 1


def test_success_one_second_past_the_window_does_not_fire():
    """The oldest failure ages out, dropping the burst below min_leading."""
    events = [*(auth_failure(i) for i in range(5)), auth_success(WINDOW + 1)]

    assert findings(SuccessfulLoginAfterBruteForce(), events) == []


# ---------------------------------------------------------------------------
# 3. Invalid user enumeration -- threshold 3 / 10 min on extra["invalid_user"]
# ---------------------------------------------------------------------------


def _probe(offset: int, username: str):
    return invalid_user_failure(offset, actor_name=username)


def test_invalid_user_enumeration_fires_on_three_distinct_accounts():
    events = [_probe(0, "admin"), _probe(1, "oracle"), _probe(2, "postgres")]

    result = findings(InvalidUserEnumeration(), events)

    assert len(result) == 1
    assert result[0].technique == "T1087"
    assert result[0].metadata["distinct_count"] == 3
    assert result[0].metadata["distinct_values"] == ["admin", "oracle", "postgres"]


def test_enumeration_counts_accounts_not_events():
    """sshd logs two lines per rejected attempt. Three accounts probed is a
    distinct_count of 3 and a raw count of 6 -- the finding must report both,
    and must fire on the former."""
    events = [
        _probe(offset, name)
        for offset, name in enumerate(
            ["admin", "admin", "oracle", "oracle", "postgres", "postgres"]
        )
    ]

    result = findings(InvalidUserEnumeration(), events)

    assert len(result) == 1
    assert result[0].metadata["distinct_count"] == 3
    assert result[0].metadata["count"] == 6


def test_many_attempts_against_one_account_is_not_enumeration():
    """Twenty retries of a single username is a brute force. An event
    threshold would call it enumeration; a distinct threshold cannot."""
    events = [_probe(i, "admin") for i in range(20)]

    assert findings(InvalidUserEnumeration(), events) == []


def test_failures_against_real_accounts_are_not_enumeration():
    """Same volume, same outcome, no invalid_user flag -- that is rule 1's
    job, not this one's."""
    assert findings(InvalidUserEnumeration(), [auth_failure(i) for i in range(5)]) == []


def test_invalid_user_enumeration_does_not_fire_one_distinct_below_threshold():
    """Two accounts, four events. Volume is above the old event threshold and
    must still not fire."""
    events = [
        _probe(0, "admin"),
        _probe(1, "admin"),
        _probe(2, "oracle"),
        _probe(3, "oracle"),
    ]

    assert findings(InvalidUserEnumeration(), events) == []


def test_invalid_user_enumeration_fires_on_the_window_edge():
    events = [_probe(0, "admin"), _probe(1, "oracle"), _probe(WINDOW, "postgres")]

    assert len(findings(InvalidUserEnumeration(), events)) == 1


def test_invalid_user_enumeration_misses_one_second_past_the_window():
    """The first account ages out, leaving two distinct inside the window."""
    events = [_probe(0, "admin"), _probe(1, "oracle"), _probe(WINDOW + 1, "postgres")]

    assert findings(InvalidUserEnumeration(), events) == []


def test_enumeration_ignores_events_with_no_username():
    """An unattributable failure contributes nothing to a count of how many
    accounts were touched."""
    events = [
        _probe(0, "admin"),
        _probe(1, "oracle"),
        invalid_user_failure(2, actor_name=None),
    ]

    assert findings(InvalidUserEnumeration(), events) == []


def test_enumeration_treats_usernames_case_insensitively():
    events = [_probe(0, "Admin"), _probe(1, "ADMIN"), _probe(2, "admin")]

    assert findings(InvalidUserEnumeration(), events) == []


def test_invalid_user_flag_absent_on_non_sshd_events_is_not_an_error():
    """CloudTrail events carry no invalid_user key. `.get()` must mean "no
    match", never an exception."""
    events = [
        event(i, category=Category.AUTHENTICATION, outcome=Outcome.FAILURE)
        for i in range(5)
    ]

    assert findings(InvalidUserEnumeration(), events) == []


# ---------------------------------------------------------------------------
# 4. Access key after suspicious auth -- sequence, min_leading 1 / 1 hour
# ---------------------------------------------------------------------------

HOUR = 3600


def test_access_key_after_failed_auth_fires():
    events = [auth_failure(0), access_key_created(60)]

    result = findings(AccessKeyAfterSuspiciousAuth(), events)

    assert len(result) == 1
    assert result[0].technique == "T1098"
    assert result[0].evidence[-1].action == "access_key_create"


def test_access_key_with_no_preceding_failure_is_routine():
    """Key creation is normal administration. The preceding failure is what
    makes it interesting."""
    assert findings(AccessKeyAfterSuspiciousAuth(), [access_key_created(60)]) == []


def test_access_key_exactly_on_the_window_edge_fires():
    events = [auth_failure(0), access_key_created(HOUR)]

    assert len(findings(AccessKeyAfterSuspiciousAuth(), events)) == 1


def test_access_key_one_second_past_the_window_does_not_fire():
    events = [auth_failure(0), access_key_created(HOUR + 1)]

    assert findings(AccessKeyAfterSuspiciousAuth(), events) == []


def test_access_key_before_the_failure_does_not_fire():
    events = [access_key_created(0), auth_failure(60)]

    assert findings(AccessKeyAfterSuspiciousAuth(), events) == []


# ---------------------------------------------------------------------------
# 5. Cloud logging disabled -- single event
# ---------------------------------------------------------------------------


def test_logging_disabled_fires_on_one_event():
    result = findings(CloudLoggingDisabled(), [logging_stopped(0)])

    assert len(result) == 1
    assert result[0].technique == "T1562.008"
    assert len(result[0].evidence) == 1
    assert result[0].metadata["outcome"] == "success"


def test_other_configuration_events_do_not_fire():
    events = [event(0, category=Category.CONFIGURATION, action="trail_delete")]

    assert findings(CloudLoggingDisabled(), events) == []


def test_denied_attempt_to_stop_logging_still_fires():
    """The boundary that matters for a single-event rule is outcome, not a
    window. An AccessDenied StopLogging is somebody aiming at the audit trail
    and missing -- suppressing it would hide the loudest part of the story."""
    result = findings(CloudLoggingDisabled(), [logging_stopped(0, outcome=Outcome.FAILURE)])

    assert len(result) == 1
    assert result[0].metadata["outcome"] == "failure"


def test_single_event_rule_emits_one_finding_per_event():
    """Unlike ThresholdRule, there is no suppression here: three attempts are
    three findings, because each is independently actionable."""
    events = [logging_stopped(0), logging_stopped(60), logging_stopped(120)]

    assert len(findings(CloudLoggingDisabled(), events)) == 3


# ---------------------------------------------------------------------------
# 6. Admin policy attached -- single event, gated on the policy ARN
# ---------------------------------------------------------------------------


def test_admin_policy_attach_fires():
    result = findings(AdminPolicyAttached(), [policy_attached(0)])

    assert len(result) == 1
    assert result[0].technique == "T1098"
    assert "AdministratorAccess" in result[0].metadata["policy_arn"]


def test_read_only_policy_attach_does_not_fire():
    """Attaching ReadOnlyAccess is housekeeping. The ARN is the whole
    difference between routine and privilege escalation."""
    events = [policy_attached(0, policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess")]

    assert findings(AdminPolicyAttached(), events) == []


def test_missing_policy_arn_does_not_fire_or_raise():
    """The boundary for this rule is a missing field, not a clock. A record
    without requestParameters must be a non-match, never a crash."""
    assert findings(AdminPolicyAttached(), [policy_attached(0, policy_arn=None)]) == []


def test_admin_policy_match_is_case_insensitive():
    events = [policy_attached(0, policy_arn="arn:aws:iam::aws:policy/ADMINISTRATORACCESS")]

    assert len(findings(AdminPolicyAttached(), events)) == 1


def test_inline_admin_policy_put_also_fires():
    """PutUserPolicy grants the same thing by a different API call."""
    events = [
        policy_attached(
            0,
            action="policy_put",
            policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
    ]

    assert len(findings(AdminPolicyAttached(), events)) == 1
