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
    assert login.host == "123456789012"
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
