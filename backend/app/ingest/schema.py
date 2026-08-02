"""Normalized event schema.

Every parser, regardless of source, emits NormalizedEvent. Detection rules,
correlation, and enrichment only ever see this shape -- they never touch
source-specific formats.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def to_utc(value: datetime | None) -> datetime | None:
    """Normalize a timestamp to UTC.

    Lives here rather than in `models` because `dedup_hash()` needs it and
    `models` already imports this module -- the dependency only runs one way.

    Two callers, one definition, deliberately:

    * `dedup_hash()`, so the same instant written `04:41:07+00:00` and
      `06:41:07+02:00` produces one fingerprint instead of two rows.
    * `Event.from_normalized` / `to_normalized`, because SQLite's
      `DateTime(timezone=True)` stores wall-clock time and discards the offset.

    Naive input is treated as already-UTC: `ParseContext.assume_tz` defaults to
    UTC and parsers attach it, so a naive value reaching here means the zone was
    never known. Guessing anything else would move the event.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class SourceType(StrEnum):
    SYSLOG_SSHD = "syslog_sshd"
    WINDOWS_SECURITY = "windows_security"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    UNKNOWN = "unknown"


class Category(StrEnum):
    """Coarse bucket. Detection rules subscribe to categories, not sources."""

    AUTHENTICATION = "authentication"
    IAM = "iam"
    PROCESS = "process"
    NETWORK = "network"
    STORAGE = "storage"
    CONFIGURATION = "configuration"
    OTHER = "other"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ActorType(StrEnum):
    USER = "user"
    SERVICE = "service"
    ROLE = "role"
    ASSUMED_ROLE = "assumed_role"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class NormalizedEvent:
    """A single security-relevant event, source-agnostic.

    Field groups: provenance / when / what / who / from where / to what.
    Anything that doesn't fit goes in `extra` -- but if you find yourself
    reaching into `extra` inside a detection rule, that field probably
    deserves promotion to a real column.
    """

    # -- provenance -----------------------------------------------------
    source_type: SourceType
    raw: str  # original line or JSON record, kept verbatim for evidence

    # Source-assigned discriminator for events that are otherwise identical.
    # Four SSH connections in the same second share timestamp, user, IP and
    # host; without this they collapse to one row and a brute-force burst
    # undercounts. sshd: "pid:port". CloudTrail: eventID.
    source_event_id: str | None = None

    # -- when -----------------------------------------------------------
    timestamp: datetime | None = None  # MUST be tz-aware UTC

    # -- what -----------------------------------------------------------
    category: Category = Category.OTHER
    action: str = "unknown"  # "login", "user_create", "policy_attach"
    outcome: Outcome = Outcome.UNKNOWN

    # -- who ------------------------------------------------------------
    actor_name: str | None = None  # username, IAM user name
    actor_id: str | None = None  # SID, AWS principalId/ARN, uid
    actor_type: ActorType = ActorType.UNKNOWN

    # -- from where -----------------------------------------------------
    source_ip: str | None = None
    source_port: int | None = None
    user_agent: str | None = None  # attacker-controlled: treat as untrusted

    # -- to what --------------------------------------------------------
    host: str | None = None  # asset the event occurred on
    target_resource: str | None = None  # file path, ARN, service name

    # -- source-specific ------------------------------------------------
    extra: dict[str, Any] = field(default_factory=dict)

    # -------------------------------------------------------------------

    def entity_keys(self) -> list[str]:
        """Namespaced identifiers this event touches.

        This is what makes cross-source correlation possible: a failed SSH
        login and a failed CloudTrail ConsoleLogin from the same address both
        yield "ip:203.0.113.5", so they can land in one incident instead of two.
        """
        keys: list[str] = []
        if self.source_ip:
            keys.append(f"ip:{self.source_ip}")
        if self.actor_name:
            keys.append(f"user:{self.actor_name.casefold()}")
        if self.actor_id:
            keys.append(f"principal:{self.actor_id}")
        if self.host:
            keys.append(f"host:{self.host.casefold()}")
        return keys

    def dedup_hash(self) -> str:
        """Stable fingerprint for suppressing re-ingested duplicates.

        Deliberately excludes `raw` so that cosmetic differences (trailing
        whitespace, re-serialized JSON key order) don't defeat dedup.

        Includes `source_event_id` so that genuinely distinct events sharing a
        one-second timestamp stay distinct. Re-ingesting the same file still
        produces the same hashes, so idempotence is preserved.

        The timestamp is normalized to UTC first. Without that, one instant
        expressed in two offsets -- the same event exported from a host whose
        `ParseContext.assume_tz` differs from a previous run's -- fingerprints
        differently and lands as a second row, which is precisely the silent
        duplicate the global unique index exists to prevent. Every parser emits
        UTC today, so this changes no existing hash; it closes the gap
        `assume_tz` would eventually open.
        """
        timestamp = to_utc(self.timestamp)
        parts = [
            self.source_type,
            self.source_event_id or "",
            timestamp.isoformat() if timestamp else "",
            self.category,
            self.action,
            self.outcome,
            self.actor_name or "",
            self.source_ip or "",
            self.host or "",
            self.target_resource or "",
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

    def is_auth_failure(self) -> bool:
        return (
            self.category is Category.AUTHENTICATION
            and self.outcome is Outcome.FAILURE
        )

    def is_auth_success(self) -> bool:
        return (
            self.category is Category.AUTHENTICATION
            and self.outcome is Outcome.SUCCESS
        )
