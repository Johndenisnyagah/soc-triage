from __future__ import annotations

from app.ingest.base import ParseContext
from app.ingest.parsers.sshd import SshdSyslogParser
from app.ingest.schema import ActorType, Category, Outcome, SourceType

HAPPY = """\
May  5 02:10:11 webserver01 sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2
May  5 02:10:14 webserver01 sshd[1235]: Failed password for invalid user admin from 203.0.113.5 port 54330 ssh2
May  5 02:11:02 webserver01 sshd[1240]: Accepted password for deploy from 198.51.100.7 port 51000 ssh2
"""


def test_sniff_recognises_sshd_syslog():
    assert SshdSyslogParser.sniff(HAPPY) > 0.9


def test_happy_path():
    ctx = ParseContext(default_year=2024)
    events = list(SshdSyslogParser().parse(HAPPY, ctx))

    assert len(events) == 3
    assert ctx.stats.events_emitted == 3
    assert ctx.stats.lines_skipped == 0
    assert ctx.stats.errors == []

    failed, invalid, accepted = events

    assert failed.source_type is SourceType.SYSLOG_SSHD
    assert failed.category is Category.AUTHENTICATION
    assert failed.action == "login"
    assert failed.outcome is Outcome.FAILURE
    assert failed.actor_name == "root"
    assert failed.actor_type is ActorType.USER
    assert failed.source_ip == "203.0.113.5"
    assert failed.source_port == 54321
    assert failed.host == "webserver01"
    assert failed.extra["invalid_user"] is False
    assert failed.extra["pid"] == "1234"
    assert failed.source_event_id == "1234:54321"

    # The "invalid user" pattern must win over the generic one, otherwise the
    # username is captured as the literal string "invalid".
    assert invalid.actor_name == "admin"
    assert invalid.extra["invalid_user"] is True

    assert accepted.outcome is Outcome.SUCCESS
    assert accepted.actor_name == "deploy"
    assert accepted.extra["auth_method"] == "password"

    # Syslog carries no year or zone; both come from ParseContext.
    assert failed.timestamp is not None
    assert failed.timestamp.year == 2024
    assert failed.timestamp.tzinfo is not None
    assert failed.timestamp.utcoffset().total_seconds() == 0


def test_entity_keys_are_namespaced():
    events = list(SshdSyslogParser().parse(HAPPY, ParseContext(default_year=2024)))
    keys = events[0].entity_keys()
    assert "ip:203.0.113.5" in keys
    assert "user:root" in keys
    assert "host:webserver01" in keys


BURST = """\
May  5 02:10:11 webserver01 sshd[1001]: Failed password for root from 203.0.113.5 port 54321 ssh2
May  5 02:10:11 webserver01 sshd[1002]: Failed password for root from 203.0.113.5 port 54322 ssh2
May  5 02:10:11 webserver01 sshd[1003]: Failed password for root from 203.0.113.5 port 54323 ssh2
May  5 02:10:11 webserver01 sshd[1004]: Failed password for root from 203.0.113.5 port 54324 ssh2
"""


def test_same_second_burst_produces_distinct_hashes():
    """Four connections in one second differ only by pid and port. Without
    source_event_id in the hash they collapse to one event and the brute-force
    rule undercounts by 4x."""
    events = list(SshdSyslogParser().parse(BURST, ParseContext(default_year=2024)))

    assert len(events) == 4
    assert {e.timestamp for e in events} == {events[0].timestamp}  # same second
    assert len({e.source_event_id for e in events}) == 4
    assert len({e.dedup_hash() for e in events}) == 4


def test_dedup_hash_is_stable_across_reparse():
    """Idempotent re-ingest depends on this: same input, same hashes."""
    first = list(SshdSyslogParser().parse(BURST, ParseContext(default_year=2024)))
    second = list(SshdSyslogParser().parse(BURST, ParseContext(default_year=2024)))

    assert [e.dedup_hash() for e in first] == [e.dedup_hash() for e in second]


MALFORMED = """\
this is not a syslog line at all
Feb 30 12:00:00 host01 sshd[9]: Failed password for root from 203.0.113.9 port 22 ssh2
May  5 02:10:11 webserver01 CRON[999]: pam_unix(cron:session): session opened for user root

"""


def test_malformed_input_does_not_raise_and_counts_skips():
    ctx = ParseContext(default_year=2024)

    events = list(SshdSyslogParser().parse(MALFORMED, ctx))  # must not raise

    # 1: no syslog header. 2: valid header, impossible date. 3: syslog line
    # that isn't an auth event we model.
    assert ctx.stats.lines_skipped == 3
    assert len(ctx.stats.errors) == 1
    assert "bad timestamp" in ctx.stats.errors[0].reason

    # The Feb 30 line still yields an event -- a broken timestamp loses the
    # correlation window, not the evidence.
    assert len(events) == 1
    assert events[0].timestamp is None
    assert events[0].actor_name == "root"


def test_error_excerpts_are_truncated():
    ctx = ParseContext(default_year=2024)
    long_tail = "A" * 5000
    line = f"Feb 30 12:00:00 host01 sshd[9]: Failed password for root from 203.0.113.9 port 22 {long_tail}"

    list(SshdSyslogParser().parse(line, ctx))

    assert len(ctx.stats.errors) == 1
    assert len(ctx.stats.errors[0].excerpt) <= 200
