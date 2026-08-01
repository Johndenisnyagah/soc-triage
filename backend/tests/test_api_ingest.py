from __future__ import annotations

from sqlalchemy import func, select

from app.models import Event, EventEntity, Ingest

SSHD_LOG = """\
May  5 02:10:11 webserver01 sshd[1234]: Failed password for root from 203.0.113.5 port 54321 ssh2
May  5 02:10:14 webserver01 sshd[1235]: Failed password for invalid user admin from 203.0.113.5 port 54330 ssh2
May  5 02:11:02 webserver01 sshd[1240]: Accepted password for deploy from 198.51.100.7 port 51000 ssh2
not a log line at all
"""


def _upload(client, content: str, filename: str = "auth.log", **data):
    return client.post(
        "/api/ingest",
        files={"file": (filename, content, "text/plain")},
        data=data or None,
    )


def test_ingest_returns_id_and_stats(client):
    response = _upload(client, SSHD_LOG, default_year="2024")

    assert response.status_code == 201
    body = response.json()

    assert isinstance(body["ingest_id"], int)
    assert body["source_type"] == "syslog_sshd"
    assert body["detected_confidence"] > 0.3
    assert body["events_persisted"] == 3
    assert body["filename"] == "auth.log"

    # The caller must be able to see what was thrown away.
    assert body["stats"]["events_emitted"] == 3
    assert body["stats"]["lines_skipped"] == 1
    assert body["stats"]["lines_read"] == 4


def test_events_and_entities_are_persisted(client, db):
    body = _upload(client, SSHD_LOG, default_year="2024").json()
    ingest_id = body["ingest_id"]

    events = db.scalars(select(Event).where(Event.ingest_id == ingest_id)).all()
    assert len(events) == 3

    # The reason add_all() is mandatory: bulk_save_objects() would bypass the
    # ORM cascade and leave this table empty with no error raised.
    entity_count = db.scalar(select(func.count()).select_from(EventEntity))
    assert entity_count > 0

    keys = set(db.scalars(select(EventEntity.entity_key)).all())
    assert "ip:203.0.113.5" in keys
    assert "user:root" in keys
    assert "host:webserver01" in keys

    # Every persisted event links to at least one entity.
    for event in events:
        assert event.entity_links


def test_ingest_row_records_parse_stats(client, db):
    body = _upload(client, SSHD_LOG, default_year="2024").json()

    ingest = db.get(Ingest, body["ingest_id"])
    assert ingest.filename == "auth.log"
    assert ingest.source_type == "syslog_sshd"
    assert ingest.lines_read == 4
    assert ingest.events_emitted == 3
    assert ingest.lines_skipped == 1
    assert ingest.uploaded_at is not None


def test_duplicate_lines_are_skipped_not_crashed(client):
    """Byte-identical lines -- same pid, same port -- really are one event.
    Without in-run dedup the flush raises IntegrityError and loses the batch."""
    line = (
        "May  5 02:10:11 webserver01 sshd[1234]: "
        "Failed password for root from 203.0.113.5 port 54321 ssh2"
    )
    body = _upload(client, "\n".join([line] * 4), default_year="2024").json()

    assert body["events_persisted"] == 1
    assert body["duplicates_skipped"] == 3


BURST = """\
May  5 02:10:11 webserver01 sshd[1001]: Failed password for root from 203.0.113.5 port 54321 ssh2
May  5 02:10:11 webserver01 sshd[1002]: Failed password for root from 203.0.113.5 port 54322 ssh2
May  5 02:10:11 webserver01 sshd[1003]: Failed password for root from 203.0.113.5 port 54323 ssh2
May  5 02:10:11 webserver01 sshd[1004]: Failed password for root from 203.0.113.5 port 54324 ssh2
"""


def test_brute_force_burst_in_one_second_persists_every_attempt(client, db):
    """Four distinct connections sharing a one-second timestamp must survive
    as four rows. Collapsing them to one makes the brute-force rule undercount
    by 4x -- the failure mode dedup was supposed to prevent, inverted."""
    body = _upload(client, BURST, default_year="2024").json()

    assert body["events_persisted"] == 4
    assert body["duplicates_skipped"] == 0

    events = db.scalars(select(Event)).all()
    assert len(events) == 4
    assert len({e.dedup_hash for e in events}) == 4
    # All four really are the same second -- the test would be vacuous if the
    # timestamps differed.
    assert len({e.timestamp for e in events}) == 1
    assert {e.source_port for e in events} == {54321, 54322, 54323, 54324}


def test_reingesting_the_same_file_is_idempotent(client, db):
    """uq_event_dedup is global, so the second upload must recognise events
    the first one already wrote rather than duplicating them or 500ing."""
    first = _upload(client, BURST, default_year="2024").json()
    second = _upload(client, BURST, default_year="2024").json()

    assert first["events_persisted"] == 4
    assert second["events_persisted"] == 0
    assert second["duplicates_skipped"] == 4

    # Two ingest rows (the upload attempts are real), four events (the
    # evidence is not duplicated).
    assert db.scalar(select(func.count()).select_from(Ingest)) == 2
    assert db.scalar(select(func.count()).select_from(Event)) == 4


def test_upload_over_the_size_limit_returns_413(client, monkeypatch):
    from app import api_ingest

    monkeypatch.setattr(api_ingest, "MAX_UPLOAD_BYTES", 64)

    response = _upload(client, SSHD_LOG, default_year="2024")

    assert response.status_code == 413
    detail = response.json()["detail"]
    assert detail["error"] == "upload too large"
    assert detail["max_upload_bytes"] == 64
    assert detail["received_bytes"] > 64


def test_upload_under_the_size_limit_is_accepted(client, monkeypatch):
    from app import api_ingest

    monkeypatch.setattr(api_ingest, "MAX_UPLOAD_BYTES", len(SSHD_LOG) + 1)

    assert _upload(client, SSHD_LOG, default_year="2024").status_code == 201


def test_oversized_upload_persists_nothing(client, db, monkeypatch):
    from app import api_ingest

    monkeypatch.setattr(api_ingest, "MAX_UPLOAD_BYTES", 64)
    _upload(client, SSHD_LOG, default_year="2024")

    assert db.scalar(select(func.count()).select_from(Ingest)) == 0
    assert db.scalar(select(func.count()).select_from(Event)) == 0


def test_cloudtrail_upload(client, db):
    content = (
        '{"Records":[{"eventVersion":"1.08",'
        '"userIdentity":{"type":"IAMUser","userName":"alice",'
        '"arn":"arn:aws:iam::123456789012:user/alice"},'
        '"eventTime":"2024-05-05T02:10:11Z","eventSource":"iam.amazonaws.com",'
        '"eventName":"CreateAccessKey","awsRegion":"us-east-1",'
        '"sourceIPAddress":"203.0.113.5","recipientAccountId":"123456789012"}]}'
    )
    response = _upload(client, content, filename="trail.json")

    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "aws_cloudtrail"
    assert body["events_persisted"] == 1

    keys = set(db.scalars(select(EventEntity.entity_key)).all())
    assert "ip:203.0.113.5" in keys
    assert "user:alice" in keys


def test_unrecognised_format_returns_422(client):
    response = _upload(client, "the quick brown fox\njumped over\n", filename="x.txt")

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "unrecognised log format"
    assert detail["best_confidence"] == 0.0
    assert set(detail["supported_formats"]) == {"syslog_sshd", "aws_cloudtrail"}


def test_unrecognised_format_persists_nothing(client, db):
    _upload(client, "the quick brown fox\n", filename="x.txt")

    assert db.scalar(select(func.count()).select_from(Ingest)) == 0
    assert db.scalar(select(func.count()).select_from(Event)) == 0


def test_batching_handles_more_than_one_batch(client, db):
    """BATCH_SIZE is 500; push past it so the flush-and-clear path runs more
    than once and the final partial batch is not dropped."""
    lines = [
        f"May  5 02:{minute:02d}:{second:02d} webserver01 sshd[{i}]: "
        f"Failed password for root from 203.0.113.{i % 251 + 1} port {10000 + i} ssh2"
        for i, (minute, second) in enumerate(
            ((i // 60) % 60, i % 60) for i in range(600)
        )
    ]
    body = _upload(client, "\n".join(lines), default_year="2024").json()

    assert body["events_persisted"] == 600
    assert db.scalar(select(func.count()).select_from(Event)) == 600
