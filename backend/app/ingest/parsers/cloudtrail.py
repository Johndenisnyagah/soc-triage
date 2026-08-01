"""AWS CloudTrail records.

Included deliberately as the second parser: it is JSON rather than
line-oriented text, has a principal model instead of a bare username, and
signals failure via an error field rather than message wording. If the
NormalizedEvent schema survives both sshd and CloudTrail, it will survive
Windows Security too.

Accepts either the bundled form ({"Records": [...]}) or JSON Lines.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterator

from ..base import BaseParser, ParseContext, register
from ..schema import ActorType, Category, NormalizedEvent, Outcome, SourceType

_ACTOR_TYPES = {
    "IAMUser": ActorType.USER,
    "Root": ActorType.USER,
    "AssumedRole": ActorType.ASSUMED_ROLE,
    "AWSService": ActorType.SERVICE,
    "AWSAccount": ActorType.SERVICE,
}

# eventName -> (category, action). Anything unmapped falls back to
# eventSource-derived categorisation, so coverage degrades gracefully.
_EVENT_MAP: dict[str, tuple[Category, str]] = {
    "ConsoleLogin": (Category.AUTHENTICATION, "login"),
    "AssumeRole": (Category.AUTHENTICATION, "assume_role"),
    "GetSessionToken": (Category.AUTHENTICATION, "session_token_issue"),
    "CreateUser": (Category.IAM, "user_create"),
    "DeleteUser": (Category.IAM, "user_delete"),
    "CreateAccessKey": (Category.IAM, "access_key_create"),
    "AttachUserPolicy": (Category.IAM, "policy_attach"),
    "AttachRolePolicy": (Category.IAM, "policy_attach"),
    "PutUserPolicy": (Category.IAM, "policy_put"),
    "DeleteTrail": (Category.CONFIGURATION, "trail_delete"),
    "StopLogging": (Category.CONFIGURATION, "logging_stop"),
    "PutBucketPolicy": (Category.STORAGE, "bucket_policy_put"),
    "PutBucketAcl": (Category.STORAGE, "bucket_acl_put"),
    "AuthorizeSecurityGroupIngress": (Category.NETWORK, "sg_ingress_authorize"),
}

_SOURCE_CATEGORY = {
    "iam.amazonaws.com": Category.IAM,
    "sts.amazonaws.com": Category.AUTHENTICATION,
    "s3.amazonaws.com": Category.STORAGE,
    "ec2.amazonaws.com": Category.NETWORK,
    "cloudtrail.amazonaws.com": Category.CONFIGURATION,
}


@register
class CloudTrailParser(BaseParser):
    source_type = SourceType.AWS_CLOUDTRAIL

    @classmethod
    def sniff(cls, sample: str) -> float:
        stripped = sample.lstrip()
        if not stripped.startswith(("{", "[")):
            return 0.0
        markers = sum(
            marker in sample
            for marker in ('"eventVersion"', '"userIdentity"', '"eventSource"', '"awsRegion"')
        )
        if markers == 0:
            return 0.0
        # 4/4 markers -> 0.95; a lone marker stays below the registry floor
        # unless nothing else claims the file.
        return min(0.95, 0.25 * markers)

    def parse(
        self, content: str, ctx: ParseContext
    ) -> Iterator[NormalizedEvent]:
        for index, record in self._iter_records(content, ctx):
            ctx.stats.lines_read += 1
            try:
                event = self._to_event(record)
            except Exception as exc:  # noqa: BLE001 - one bad record must not abort ingest
                ctx.stats.record_error(index, f"malformed record: {exc}", str(record))
                continue
            ctx.stats.events_emitted += 1
            yield event

    # -- input shapes ---------------------------------------------------

    def _iter_records(
        self, content: str, ctx: ParseContext
    ) -> Iterator[tuple[int, dict[str, Any]]]:
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            yield from self._iter_json_lines(content, ctx)
            return

        if isinstance(payload, dict) and "Records" in payload:
            records = payload["Records"]
        elif isinstance(payload, list):
            records = payload
        else:
            records = [payload]

        for index, record in enumerate(records, start=1):
            if isinstance(record, dict):
                yield index, record
            else:
                ctx.stats.record_error(index, "record is not an object", str(record))

    def _iter_json_lines(
        self, content: str, ctx: ParseContext
    ) -> Iterator[tuple[int, dict[str, Any]]]:
        for index, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                ctx.stats.record_error(index, f"invalid JSON: {exc.msg}", line)
                continue
            if isinstance(record, dict):
                yield index, record

    # -- mapping --------------------------------------------------------

    def _to_event(self, record: dict[str, Any]) -> NormalizedEvent:
        identity = record.get("userIdentity") or {}
        event_name = record.get("eventName", "unknown")
        event_source = record.get("eventSource", "")

        category, action = _EVENT_MAP.get(
            event_name,
            (_SOURCE_CATEGORY.get(event_source, Category.OTHER), _snake(event_name)),
        )

        return NormalizedEvent(
            source_type=self.source_type,
            raw=json.dumps(record, separators=(",", ":"), sort_keys=True),
            source_event_id=record.get("eventID"),
            timestamp=_parse_time(record.get("eventTime")),
            category=category,
            action=action,
            outcome=self._outcome(record),
            actor_name=identity.get("userName") or identity.get("arn"),
            actor_id=identity.get("arn") or identity.get("principalId"),
            actor_type=_ACTOR_TYPES.get(identity.get("type", ""), ActorType.UNKNOWN),
            source_ip=_clean_ip(record.get("sourceIPAddress")),
            user_agent=record.get("userAgent"),
            host=record.get("recipientAccountId"),
            target_resource=f"{event_source}:{event_name}" if event_source else event_name,
            extra={
                "aws_region": record.get("awsRegion"),
                "event_id": record.get("eventID"),
                "error_code": record.get("errorCode"),
                "error_message": record.get("errorMessage"),
                "mfa_authenticated": (
                    identity.get("sessionContext", {})
                    .get("attributes", {})
                    .get("mfaAuthenticated")
                ),
            },
        )

    def _outcome(self, record: dict[str, Any]) -> Outcome:
        if record.get("errorCode") or record.get("errorMessage"):
            return Outcome.FAILURE
        # ConsoleLogin reports its result in responseElements, not errorCode.
        console = (record.get("responseElements") or {}).get("ConsoleLogin")
        if console:
            return Outcome.SUCCESS if console == "Success" else Outcome.FAILURE
        return Outcome.SUCCESS


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _clean_ip(value: str | None) -> str | None:
    """CloudTrail puts service principals in sourceIPAddress for AWS-initiated
    calls (e.g. "ec2.amazonaws.com"). Those are not addresses; dropping them
    keeps entity keys from collecting junk."""
    if not value or value.endswith(".amazonaws.com"):
        return None
    return value


def _snake(name: str) -> str:
    out: list[str] = []
    for i, ch in enumerate(name):
        if ch.isupper() and i and not name[i - 1].isupper():
            out.append("_")
        out.append(ch.lower())
    return "".join(out)
