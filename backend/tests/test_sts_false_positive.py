"""Regression: a routine STS identity read must not become a compromise.

This is a **cross-layer** bug, which is why it has its own file. Neither of the
two layers involved was wrong on its own:

  * the CloudTrail parser categorised by `eventSource` when `eventName` was
    unmapped, and `sts.amazonaws.com` defaulted to `Category.AUTHENTICATION`;
  * `SuccessfulLoginAfterBruteForce` accepts any `is_auth_success()` event as
    its trailing half, and `is_auth_success()` is `category is AUTHENTICATION
    and outcome is SUCCESS` -- it never inspects `action`.

Compose them and a successful `GetCallerIdentity` -- which authenticates
nothing, and which the AWS CLI and effectively every CI job emit constantly --
satisfied the trailing condition. A burst of failed logins followed by any
routine automation raised a CRITICAL "successful authentication after repeated
failures" for an authentication that never happened.

`tests/test_detection_rules.py` states that rules are pure functions over
`NormalizedEvent` and must not go near a parser, and that is the right rule for
that file. But the defect only exists in the seam, so the regression has to
cross it: real parser output, real rule, asserted together.
"""

from __future__ import annotations

import json

from detection_helpers import auth_failure, findings

from app.detection.library import SuccessfulLoginAfterBruteForce
from app.ingest.base import ParseContext
from app.ingest.parsers.cloudtrail import CloudTrailParser
from app.ingest.schema import Category


def _cloudtrail_event(event_name: str, event_source: str):
    """One record through the real parser -- no hand-built NormalizedEvent.

    Building the event by hand would let this test pass while the parser
    carried on mislabelling the record, which is precisely the failure mode.
    """
    record = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "deploy",
            "arn": "arn:aws:iam::123456789012:user/deploy",
        },
        # Well inside the rule's ten-minute window, measured from
        # `detection_helpers.BASE` (04:41:00Z).
        "eventTime": "2026-08-02T04:42:30Z",
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0 exec-env/CLI",
        "recipientAccountId": "123456789012",
        "eventID": f"evt-{event_name}",
    }
    events = list(
        CloudTrailParser().parse(json.dumps({"Records": [record]}), ParseContext())
    )
    assert len(events) == 1
    return events[0]


def test_get_caller_identity_after_a_burst_is_not_a_successful_login():
    """The exact false positive, end to end.

    Five failures then a successful `GetCallerIdentity` -- the shape of a real
    deployment where a brute force happens to be followed by a CI job doing
    what CI jobs do.
    """
    caller_identity = _cloudtrail_event("GetCallerIdentity", "sts.amazonaws.com")

    # The parser's half of the contract.
    assert caller_identity.category is Category.IAM
    assert not caller_identity.is_auth_success()

    events = [*(auth_failure(i) for i in range(5)), caller_identity]

    # The rule's half.
    assert findings(SuccessfulLoginAfterBruteForce(), events) == []


def test_an_unmapped_sts_call_after_a_burst_is_not_a_successful_login():
    """The fallback itself, not just the one event name.

    Mapping `GetCallerIdentity` alone would leave every other unmapped STS call
    inheriting AUTHENTICATION. This asserts the service-level default is gone
    rather than special-cased.
    """
    decode = _cloudtrail_event("DecodeAuthorizationMessage", "sts.amazonaws.com")

    assert decode.category is Category.OTHER

    events = [*(auth_failure(i) for i in range(5)), decode]

    assert findings(SuccessfulLoginAfterBruteForce(), events) == []


def test_a_real_credential_issuance_after_a_burst_still_fires():
    """The fix must not have bought quiet by breaking the detection.

    `AssumeRole` genuinely authenticates, so a burst of failures followed by a
    successful role assumption is still exactly what this rule exists to catch.
    A test that only asserted silence would pass just as well against a rule
    that had been disabled.
    """
    assume_role = _cloudtrail_event("AssumeRole", "sts.amazonaws.com")

    assert assume_role.category is Category.AUTHENTICATION
    assert assume_role.is_auth_success()

    events = [*(auth_failure(i) for i in range(5)), assume_role]

    result = findings(SuccessfulLoginAfterBruteForce(), events)
    assert len(result) == 1
    assert result[0].evidence[-1] is assume_role
