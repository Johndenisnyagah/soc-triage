from __future__ import annotations

import json

from app.ingest.base import ParseContext
from app.ingest.parsers.cloudtrail import CloudTrailParser
from app.ingest.schema import ActorType, Category, Outcome, SourceType

HAPPY = json.dumps(
    {
        "Records": [
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "alice",
                    "arn": "arn:aws:iam::123456789012:user/alice",
                    "principalId": "AIDAEXAMPLE",
                },
                "eventTime": "2024-05-05T02:10:11Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.5",
                "userAgent": "Mozilla/5.0",
                "responseElements": {"ConsoleLogin": "Failure"},
                "recipientAccountId": "123456789012",
                "eventID": "evt-1",
            },
            {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::123456789012:assumed-role/deploy/i-1",
                    "principalId": "AROAEXAMPLE:i-1",
                },
                "eventTime": "2024-05-05T02:12:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.5",
                "recipientAccountId": "123456789012",
                "eventID": "evt-2",
            },
            {
                "eventVersion": "1.08",
                "userIdentity": {"type": "AWSService"},
                "eventTime": "2024-05-05T02:13:00Z",
                "eventSource": "ec2.amazonaws.com",
                "eventName": "DescribeInstances",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "ec2.amazonaws.com",
                "recipientAccountId": "123456789012",
                "eventID": "evt-3",
            },
        ]
    }
)


def test_sniff_recognises_cloudtrail():
    assert CloudTrailParser.sniff(HAPPY) == 0.95


def test_happy_path():
    ctx = ParseContext()
    events = list(CloudTrailParser().parse(HAPPY, ctx))

    assert len(events) == 3
    assert ctx.stats.events_emitted == 3
    assert ctx.stats.errors == []

    login, access_key, describe = events

    assert login.source_type is SourceType.AWS_CLOUDTRAIL
    assert login.category is Category.AUTHENTICATION
    assert login.action == "login"
    # ConsoleLogin reports its result in responseElements, not errorCode.
    assert login.outcome is Outcome.FAILURE
    assert login.actor_name == "alice"
    assert login.actor_type is ActorType.USER
    assert login.source_ip == "203.0.113.5"
    # An AWS account is a tenant, not a machine. `recipientAccountId` used to
    # land in `host`, which produced the entity key `host:123456789012` -- an
    # asset identifier naming something with no asset behind it.
    assert login.account == "123456789012"
    assert login.host is None
    assert "account:123456789012" in login.entity_keys()
    assert not any(k.startswith("host:") for k in login.entity_keys())
    assert login.target_resource == "signin.amazonaws.com:ConsoleLogin"
    assert login.source_event_id == "evt-1"
    assert len({e.source_event_id for e in events}) == 3
    assert len({e.dedup_hash() for e in events}) == 3
    assert login.timestamp is not None
    assert login.timestamp.utcoffset().total_seconds() == 0

    assert access_key.category is Category.IAM
    assert access_key.action == "access_key_create"
    assert access_key.outcome is Outcome.SUCCESS
    assert access_key.actor_type is ActorType.ASSUMED_ROLE

    # Unmapped eventName falls back to eventSource-derived category plus a
    # snake_cased action, so coverage degrades instead of disappearing.
    assert describe.category is Category.NETWORK
    assert describe.action == "describe_instances"
    # A service principal is not an address; it must not pollute entity keys.
    assert describe.source_ip is None
    assert not any(k.startswith("ip:") for k in describe.entity_keys())


def test_policy_arn_is_promoted_out_of_request_parameters():
    """The admin-policy rule needs the ARN to tell privilege escalation from
    routine housekeeping, so it cannot stay buried in `raw`."""
    content = json.dumps(
        {
            "Records": [
                {
                    "eventVersion": "1.08",
                    "userIdentity": {"type": "IAMUser", "userName": "deploy"},
                    "eventTime": "2024-05-05T02:14:00Z",
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "AttachUserPolicy",
                    "awsRegion": "us-east-1",
                    "requestParameters": {
                        "userName": "deploy",
                        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                    "recipientAccountId": "123456789012",
                    "eventID": "evt-4",
                }
            ]
        }
    )

    event = next(CloudTrailParser().parse(content, ParseContext()))

    assert event.action == "policy_attach"
    assert event.extra["policy_arn"] == "arn:aws:iam::aws:policy/AdministratorAccess"


def test_absent_or_malformed_request_parameters_yield_a_null_policy_arn():
    """requestParameters is free-form per API: null for many calls, and not
    necessarily an object in a malformed export. Neither may raise."""
    records = [
        # No requestParameters at all.
        {
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": "deploy"},
            "eventTime": "2024-05-05T02:15:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "ListUsers",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "eventID": "evt-5",
        },
        # Explicitly null, which real CloudTrail emits constantly.
        {
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": "deploy"},
            "eventTime": "2024-05-05T02:16:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "requestParameters": None,
            "recipientAccountId": "123456789012",
            "eventID": "evt-6",
        },
        # Wrong shape entirely: must be a null ARN, not a recorded error.
        {
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": "deploy"},
            "eventTime": "2024-05-05T02:17:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "requestParameters": "not-an-object",
            "recipientAccountId": "123456789012",
            "eventID": "evt-7",
        },
    ]
    ctx = ParseContext()

    events = list(CloudTrailParser().parse(json.dumps({"Records": records}), ctx))

    assert len(events) == 3
    assert ctx.stats.errors == []
    assert all(e.extra["policy_arn"] is None for e in events)


def test_json_lines_form_is_accepted():
    lines = "\n".join(
        json.dumps(r) for r in json.loads(HAPPY)["Records"]
    )
    ctx = ParseContext()
    events = list(CloudTrailParser().parse(lines, ctx))
    assert len(events) == 3
    assert ctx.stats.errors == []


MALFORMED = "\n".join(
    [
        json.dumps(
            {
                "eventVersion": "1.08",
                "userIdentity": {"type": "IAMUser", "userName": "bob"},
                "eventTime": "2024-05-05T03:00:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "awsRegion": "us-east-1",
                "recipientAccountId": "123456789012",
            }
        ),
        '{"eventVersion": "1.08", "eventName": BROKEN',
        # Valid JSON, wrong shape: userIdentity is a string, so the mapper
        # blows up on .get(). Must be recorded, not propagated.
        json.dumps(
            {
                "eventVersion": "1.08",
                "userIdentity": "not-an-object",
                "eventTime": "2024-05-05T03:01:00Z",
                "eventSource": "iam.amazonaws.com",
                "eventName": "DeleteUser",
                "awsRegion": "us-east-1",
            }
        ),
    ]
)


def test_malformed_input_does_not_raise_and_counts_skips():
    ctx = ParseContext()

    events = list(CloudTrailParser().parse(MALFORMED, ctx))  # must not raise

    assert len(events) == 1
    assert events[0].actor_name == "bob"
    assert ctx.stats.lines_skipped == 2
    assert len(ctx.stats.errors) == 2

    reasons = " ".join(e.reason for e in ctx.stats.errors)
    assert "invalid JSON" in reasons
    assert "malformed record" in reasons


# ---------------------------------------------------------------------------
# STS categorisation
# ---------------------------------------------------------------------------


def _sts(event_name: str, event_id: str = "evt-sts") -> dict:
    """A successful STS call. No errorCode, so `_outcome` returns SUCCESS."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "deploy",
            "arn": "arn:aws:iam::123456789012:user/deploy",
        },
        "eventTime": "2026-08-02T04:49:05Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "aws-cli/2.15.30",
        "recipientAccountId": "123456789012",
        "eventID": event_id,
    }


def _parse_one(record: dict):
    events = list(
        CloudTrailParser().parse(json.dumps({"Records": [record]}), ParseContext())
    )
    assert len(events) == 1
    return events[0]


def test_sts_identity_read_is_not_an_authentication_success():
    """`GetCallerIdentity` must never look like an authentication.

    It reports who the caller already is; it authenticates nothing. While
    `sts.amazonaws.com` had a service-level default of AUTHENTICATION, a
    successful call inherited AUTHENTICATION/success and satisfied
    `is_auth_success()` -- making it a valid trailing event for
    `brute_force_success`. The AWS CLI and effectively every CI job call it
    constantly, so that fired on routine automation.
    """
    event = _parse_one(_sts("GetCallerIdentity"))

    assert event.category is Category.IAM
    assert event.action == "caller_identity_get"
    assert not event.is_auth_success()
    assert not event.is_auth_failure()


def test_unmapped_sts_events_fall_to_other_not_authentication():
    """The fallback is gone, not redirected.

    An STS call nobody has classified must land somewhere no rule subscribes
    to. OTHER is that place; inheriting AUTHENTICATION is the bug this guards.
    """
    event = _parse_one(_sts("DecodeAuthorizationMessage"))

    assert event.category is Category.OTHER
    assert not event.is_auth_success()


def test_credential_issuing_sts_events_are_still_authentication():
    """Removing the fallback must not quietly drop real credential issuance.

    These are the STS calls that genuinely authenticate something, so they are
    named individually in `_EVENT_MAP`. If this regressed, the false-positive
    fix would have silently taken detection coverage with it.
    """
    for name, action in [
        ("AssumeRole", "assume_role"),
        ("AssumeRoleWithSAML", "assume_role"),
        ("AssumeRoleWithWebIdentity", "assume_role"),
        ("GetSessionToken", "session_token_issue"),
        ("GetFederationToken", "session_token_issue"),
    ]:
        event = _parse_one(_sts(name))
        assert event.category is Category.AUTHENTICATION, name
        assert event.action == action, name
        assert event.is_auth_success(), name


def test_no_service_default_maps_to_authentication():
    """The structural rule behind the STS fix, pinned.

    AUTHENTICATION is the only category whose rules fire on `category` +
    `outcome` alone -- `is_auth_success()`/`is_auth_failure()` never inspect
    `action`. Every other category is safe under a coarse service default
    because its rules match a specific action (`access_key_create`,
    `policy_attach`, `logging_stop`), which an unmapped `_snake(eventName)`
    will not collide with.

    So a service-level default that lands in AUTHENTICATION turns every
    unmapped event from that service into a real authentication event. Adding
    one is the mistake; this test is what says so.
    """
    from app.ingest.parsers.cloudtrail import _SOURCE_CATEGORY

    assert Category.AUTHENTICATION not in _SOURCE_CATEGORY.values()
