"""Dedup identity: what counts as "the same event".

Decision 11 makes `dedup_hash` globally unique, so getting this wrong is not a
cosmetic bug -- too coarse and a brute-force burst collapses to one row, too
fine and re-ingesting a file duplicates every event. Both destroy the signal
detection depends on, and neither raises.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.ingest.schema import (
    ActorType,
    Category,
    NormalizedEvent,
    Outcome,
    SourceType,
    to_utc,
)

UTC_INSTANT = datetime(2026, 8, 2, 4, 41, 7, tzinfo=timezone.utc)


def _event(**overrides) -> NormalizedEvent:
    fields = dict(
        source_type=SourceType.SYSLOG_SSHD,
        raw="golden",
        source_event_id="1234:54321",
        timestamp=UTC_INSTANT,
        category=Category.AUTHENTICATION,
        action="login",
        outcome=Outcome.FAILURE,
        actor_name="root",
        actor_type=ActorType.USER,
        source_ip="203.0.113.5",
        host="webserver01",
        target_resource="sshd",
    )
    fields.update(overrides)
    return NormalizedEvent(**fields)


# -- timezone representation is not identity ---------------------------------


def test_same_instant_in_different_offsets_hashes_identically():
    """04:41:07+00:00 and 06:41:07+02:00 are one moment.

    Without normalization they fingerprint differently, so the same event
    re-ingested after an operator corrects `ParseContext.assume_tz` lands as a
    second row -- a silent duplicate the global unique index cannot catch,
    because the two hashes genuinely differ.
    """
    plus_two = timezone(timedelta(hours=2))
    shifted = UTC_INSTANT.astimezone(plus_two)

    # Same moment, different wall clock -- the premise of the test.
    assert shifted.hour == 6
    assert shifted == UTC_INSTANT

    assert _event().dedup_hash() == _event(timestamp=shifted).dedup_hash()


def test_three_representations_of_one_instant_collapse_to_one_hash():
    offsets = [timezone(timedelta(hours=h)) for h in (-8, 0, 5)]
    hashes = {
        _event(timestamp=UTC_INSTANT.astimezone(tz)).dedup_hash() for tz in offsets
    }

    assert len(hashes) == 1


def test_naive_timestamp_is_treated_as_utc():
    """A naive value means the zone was never known, and `assume_tz` defaults
    to UTC -- so it must hash as the UTC instant, not as a fourth thing."""
    naive = UTC_INSTANT.replace(tzinfo=None)

    assert _event(timestamp=naive).dedup_hash() == _event().dedup_hash()


def test_genuinely_different_instants_still_differ():
    """The normalization must not flatten real time differences -- otherwise
    a burst would collapse, which is the failure decision 11 exists to stop."""
    later = UTC_INSTANT + timedelta(seconds=1)

    assert _event(timestamp=later).dedup_hash() != _event().dedup_hash()


def test_missing_timestamp_does_not_raise():
    assert _event(timestamp=None).dedup_hash()


# -- the rest of the identity is unchanged -----------------------------------


def test_source_event_id_still_separates_same_second_connections():
    """Decision 11's core case: four connections in one second are four
    events, told apart only by pid:port."""
    hashes = {
        _event(source_event_id=f"100{i}:5432{i}").dedup_hash() for i in range(4)
    }

    assert len(hashes) == 4


def test_raw_is_still_excluded():
    """Whitespace and re-serialized JSON key order must not defeat dedup."""
    assert _event(raw="  golden  \n").dedup_hash() == _event().dedup_hash()


def test_dedup_hash_is_stable_across_releases():
    """Pinned deliberately. `dedup_hash` is a stored, globally unique column,
    so changing how it is computed silently invalidates every row already
    written -- previously-ingested events stop matching and re-ingest as
    duplicates. If this value must change, that is a migration, not an edit.

    It has changed exactly once, from `2738864502a2b52f48b672c081eca36b`, when
    `account` joined the hashed fields. That was a knowing break: CloudTrail's
    `recipientAccountId` moved out of `host`, so cloud hashes were changing
    regardless, and adding the field for every source keeps one definition of
    identity rather than a conditional one. It cost nothing because the schema
    is still on `create_all` with no migration path and no data worth keeping
    -- which will not be true the next time this line needs editing.
    """
    assert _event().dedup_hash() == "ad3a374f906f519a4796da7a22a697e1"
    assert len(_event().dedup_hash()) == 32


def test_account_is_part_of_identity():
    """Two identical API calls in two AWS accounts are two events. Without
    `account` in the hash, moving it out of `host` would have made them one."""
    assert (
        _event(host=None, account="123456789012").dedup_hash()
        != _event(host=None, account="210987654321").dedup_hash()
    )


# -- the helper itself -------------------------------------------------------


def test_to_utc_preserves_the_instant():
    plus_two = timezone(timedelta(hours=2))
    converted = to_utc(UTC_INSTANT.astimezone(plus_two))

    assert converted == UTC_INSTANT
    assert converted.utcoffset().total_seconds() == 0


def test_to_utc_passes_none_through():
    assert to_utc(None) is None
