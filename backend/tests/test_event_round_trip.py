"""Persisted rows must come back as events the rules can actually run over.

This is the seam decision 13 rests on: detection reads the database, so if
`to_normalized()` loses or mistypes a field, every rule downstream is quietly
wrong rather than broken loudly.
"""

from __future__ import annotations

from sqlalchemy import select

from app.detection.engine import run_rules
from app.detection.library import BruteForceAuthentication, InvalidUserEnumeration
from app.ingest.schema import ActorType, Category, NormalizedEvent, Outcome, SourceType
from app.models import Event, EventEntity

SSHD_LOG = """\
May  5 02:10:11 webserver01 sshd[1001]: Failed password for root from 203.0.113.5 port 54321 ssh2
May  5 02:10:12 webserver01 sshd[1002]: Failed password for root from 203.0.113.5 port 54322 ssh2
May  5 02:10:13 webserver01 sshd[1003]: Failed password for root from 203.0.113.5 port 54323 ssh2
May  5 02:10:14 webserver01 sshd[1004]: Failed password for root from 203.0.113.5 port 54324 ssh2
May  5 02:10:15 webserver01 sshd[1005]: Failed password for root from 203.0.113.5 port 54325 ssh2
"""

ENUMERATION_LOG = """\
May  5 02:20:01 webserver01 sshd[2001]: Invalid user admin from 203.0.113.9 port 40001
May  5 02:20:01 webserver01 sshd[2001]: Failed password for invalid user admin from 203.0.113.9 port 40001 ssh2
May  5 02:20:05 webserver01 sshd[2002]: Invalid user oracle from 203.0.113.9 port 40002
May  5 02:20:06 webserver01 sshd[2002]: Failed password for invalid user oracle from 203.0.113.9 port 40002 ssh2
May  5 02:20:09 webserver01 sshd[2003]: Invalid user postgres from 203.0.113.9 port 40003
May  5 02:20:10 webserver01 sshd[2003]: Failed password for invalid user postgres from 203.0.113.9 port 40003 ssh2
"""


def _upload(client, content: str, filename: str = "auth.log", **data):
    return client.post(
        "/api/ingest",
        files={"file": (filename, content, "text/plain")},
        data=data or None,
    )


def _persisted(db) -> list[NormalizedEvent]:
    rows = db.scalars(select(Event).order_by(Event.timestamp)).all()
    return [row.to_normalized() for row in rows]


def test_round_trip_preserves_the_fields_rules_read(client, db):
    _upload(client, SSHD_LOG, default_year="2024")

    events = _persisted(db)

    assert len(events) == 5
    first = events[0]
    # Enums come back as enums, not the strings the columns hold -- rules
    # compare with `is`, which would silently never match on a bare str.
    assert first.source_type is SourceType.SYSLOG_SSHD
    assert first.category is Category.AUTHENTICATION
    assert first.outcome is Outcome.FAILURE
    assert first.actor_type is ActorType.USER
    assert first.action == "login"
    assert first.actor_name == "root"
    assert first.source_ip == "203.0.113.5"
    assert first.source_port == 54321
    assert first.host == "webserver01"
    assert first.raw.startswith("May  5 02:10:11")


def test_round_tripped_timestamps_are_timezone_aware(client, db):
    """SQLite has no timezone type and hands back naive datetimes. A rule
    subtracting an aware from a naive datetime raises TypeError, so the
    re-stamp is what keeps the suite honest about decision 7."""
    _upload(client, SSHD_LOG, default_year="2024")

    for event in _persisted(db):
        assert event.timestamp is not None
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.utcoffset().total_seconds() == 0


def test_extra_survives_the_json_column(client, db):
    _upload(client, ENUMERATION_LOG, default_year="2024")

    events = _persisted(db)

    assert all(e.extra.get("invalid_user") is True for e in events)


def test_entity_keys_are_recomputed_identically(client, db):
    """Correlation indexes `event_entities` at write time but rules recompute
    keys from the round-tripped event. If the two ever disagree, a finding
    would point at an entity the index cannot find."""
    _upload(client, SSHD_LOG, default_year="2024")

    recomputed = {k for e in _persisted(db) for k in e.entity_keys()}
    stored = set(db.scalars(select(EventEntity.entity_key)).all())

    assert recomputed == stored
    assert recomputed == {"ip:203.0.113.5", "user:root", "host:webserver01"}


def test_detection_runs_over_persisted_events(client, db):
    """The whole point: rules operate on what the database kept."""
    _upload(client, SSHD_LOG, default_year="2024")

    result = run_rules(_persisted(db), rules=[BruteForceAuthentication])

    by_entity = result.by_entity()
    assert "ip:203.0.113.5" in by_entity
    assert by_entity["ip:203.0.113.5"][0].metadata["count"] == 5


def test_enumeration_over_persisted_events_counts_surviving_rows(client, db):
    """Two sshd lines per attempt, three accounts. Whatever dedup keeps, the
    distinct count is 3 -- which is exactly why the rule counts accounts
    rather than events."""
    _upload(client, ENUMERATION_LOG, default_year="2024")

    result = run_rules(_persisted(db), rules=[InvalidUserEnumeration])
    finding = result.by_entity()["ip:203.0.113.9"][0]

    assert finding.metadata["distinct_count"] == 3
    assert finding.metadata["distinct_values"] == ["admin", "oracle", "postgres"]


def test_same_second_pair_collapses_to_one_row(client, db):
    """The dedup case that makes decision 13 matter: sshd logging both lines
    inside one second is one connection attempt, and only one row survives.
    A tool running rules over parser output would see two."""
    same_second = (
        "May  5 02:30:00 webserver01 sshd[3001]: "
        "Invalid user admin from 203.0.113.9 port 41000\n"
        "May  5 02:30:00 webserver01 sshd[3001]: "
        "Failed password for invalid user admin from 203.0.113.9 port 41000 ssh2\n"
    )

    body = _upload(client, same_second, default_year="2024").json()

    assert body["stats"]["events_emitted"] == 2
    assert body["events_persisted"] == 1
    assert body["duplicates_skipped"] == 1
    assert len(_persisted(db)) == 1
