"""Synthetic event builders for detection tests.

Rules are pure functions over `NormalizedEvent`, so their tests must not go
anywhere near a parser. Building events by hand keeps a rule test honest in two
ways: a regex change in the sshd parser cannot break a detection test, and a
window boundary can be expressed as `at(600)` instead of by hand-crafting a
syslog line with the right clock time in it.

Offsets are seconds from `BASE`, which makes the boundary cases readable:
`window` is 600s, so `at(600)` is exactly on the edge and `at(601)` is one
second past it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.detection.rules import DetectionContext, Finding, Rule
from app.ingest.schema import (
    ActorType,
    Category,
    NormalizedEvent,
    Outcome,
    SourceType,
)

BASE = datetime(2026, 8, 2, 4, 41, 0, tzinfo=timezone.utc)

DEFAULT_IP = "203.0.113.5"
DEFAULT_ENTITY = f"ip:{DEFAULT_IP}"


def at(offset_seconds: int) -> datetime:
    return BASE + timedelta(seconds=offset_seconds)


def event(
    offset_seconds: int = 0,
    *,
    category: Category = Category.AUTHENTICATION,
    action: str = "login",
    outcome: Outcome = Outcome.FAILURE,
    actor_name: str | None = "root",
    source_ip: str | None = DEFAULT_IP,
    host: str | None = "web01",
    source_type: SourceType = SourceType.SYSLOG_SSHD,
    target_resource: str | None = None,
    timestamp: datetime | None | object = ...,
    extra: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """One synthetic event. Every field a rule reads is overridable.

    `timestamp` defaults to `BASE + offset_seconds`; pass None explicitly to
    build the unplaceable event the engine is supposed to drop.
    """
    return NormalizedEvent(
        source_type=source_type,
        raw=f"synthetic event at +{offset_seconds}s",
        source_event_id=f"synthetic:{offset_seconds}",
        timestamp=at(offset_seconds) if timestamp is ... else timestamp,
        category=category,
        action=action,
        outcome=outcome,
        actor_name=actor_name,
        actor_type=ActorType.USER,
        source_ip=source_ip,
        host=host,
        target_resource=target_resource,
        extra=extra or {},
    )


# -- shorthands for the shapes the rules actually key on --------------------


def auth_failure(offset_seconds: int, **kwargs) -> NormalizedEvent:
    return event(offset_seconds, outcome=Outcome.FAILURE, **kwargs)


def auth_success(offset_seconds: int, **kwargs) -> NormalizedEvent:
    return event(offset_seconds, outcome=Outcome.SUCCESS, **kwargs)


def invalid_user_failure(offset_seconds: int, **kwargs) -> NormalizedEvent:
    kwargs.setdefault("extra", {"invalid_user": True})
    return event(offset_seconds, outcome=Outcome.FAILURE, **kwargs)


def access_key_created(offset_seconds: int, **kwargs) -> NormalizedEvent:
    return event(
        offset_seconds,
        category=Category.IAM,
        action="access_key_create",
        outcome=Outcome.SUCCESS,
        source_type=SourceType.AWS_CLOUDTRAIL,
        **kwargs,
    )


def logging_stopped(
    offset_seconds: int, *, outcome: Outcome = Outcome.SUCCESS, **kwargs
) -> NormalizedEvent:
    kwargs.setdefault("target_resource", "cloudtrail.amazonaws.com:StopLogging")
    return event(
        offset_seconds,
        category=Category.CONFIGURATION,
        action="logging_stop",
        outcome=outcome,
        source_type=SourceType.AWS_CLOUDTRAIL,
        **kwargs,
    )


def policy_attached(
    offset_seconds: int,
    *,
    policy_arn: str | None = "arn:aws:iam::aws:policy/AdministratorAccess",
    action: str = "policy_attach",
    **kwargs,
) -> NormalizedEvent:
    kwargs.setdefault("extra", {"policy_arn": policy_arn})
    return event(
        offset_seconds,
        category=Category.IAM,
        action=action,
        outcome=Outcome.SUCCESS,
        source_type=SourceType.AWS_CLOUDTRAIL,
        **kwargs,
    )


# -- running a rule in isolation --------------------------------------------


def findings(
    rule: Rule,
    events: list[NormalizedEvent],
    entity_key: str = DEFAULT_ENTITY,
) -> list[Finding]:
    """Evaluate one rule directly, bypassing the engine and the registry.

    Sorting here mirrors the ordering guarantee `DetectionContext` documents,
    so a test can list events in whatever order reads clearest.
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    return list(rule.evaluate(DetectionContext(entity_key, ordered)))
