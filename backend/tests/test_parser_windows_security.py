"""Windows Security (Event XML) parser.

The sample in `sample_logs/windows_security.xml` is an RDP intrusion on one
workstation surrounded by the background every Windows host produces: service
logons, machine-account logons, privilege-assignment events. Most of what this
file pins down is what the parser *declines* to call authentication, because
that is where a Windows source quietly ruins the brute-force-success rule.
"""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime

from app.detection.correlation import correlate
from app.detection.engine import run_rules
from app.ingest.base import ParseContext, select_parser
from app.ingest.parsers.windows_security import WindowsSecurityXmlParser
from app.ingest.schema import Category, Outcome, SourceType

SAMPLES = pathlib.Path(__file__).resolve().parents[2] / "sample_logs"
SAMPLE = (SAMPLES / "windows_security.xml").read_text(encoding="utf-8")
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def record(event_id: int, data: dict[str, str], *, record_id: int = 1, channel: str = "Security",
           when: str = "2026-08-02T13:05:02.1234567Z", user_data: str | None = None) -> str:
    body = (f"<UserData>{user_data}</UserData>" if user_data is not None else
            "<EventData>" + "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
            + "</EventData>")
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f"<EventID>{event_id}</EventID><TimeCreated SystemTime=\"{when}\"/>"
        f"<EventRecordID>{record_id}</EventRecordID><Channel>{channel}</Channel>"
        f"<Computer>WKS-01</Computer></System>{body}</Event>"
    )


def logon(event_id: int, **overrides) -> str:
    data = {"TargetUserName": "alice", "TargetUserSid": "S-1-0-0", "LogonType": "10",
            "IpAddress": "203.0.113.9", "IpPort": "50123", "SubStatus": "0xc000006a"}
    data.update(overrides)
    return record(event_id, data)


def parse(content: str):
    ctx = ParseContext()
    events = list(WindowsSecurityXmlParser().parse(content, ctx))
    return events, ctx.stats


# ---------------------------------------------------------------------------
# Format selection
# ---------------------------------------------------------------------------


def test_selected_for_event_xml_and_not_for_other_sources():
    parser, confidence = select_parser(SAMPLE)
    assert parser is WindowsSecurityXmlParser
    assert confidence >= 0.9
    for other in ("auth.log", "cloudtrail.json"):
        assert WindowsSecurityXmlParser.sniff((SAMPLES / other).read_text()) == 0.0


# ---------------------------------------------------------------------------
# The sample
# ---------------------------------------------------------------------------


def test_sample_counts():
    events, stats = parse(SAMPLE)
    assert (stats.lines_read, stats.events_emitted, stats.lines_skipped) == (20, 16, 4)
    assert stats.errors == []
    assert {e.source_type for e in events} == {SourceType.WINDOWS_SECURITY}


def test_failed_logon_fields():
    (event,), _ = parse(logon(4625))
    assert event.category is Category.AUTHENTICATION
    assert event.outcome is Outcome.FAILURE
    assert (event.actor_name, event.source_ip, event.source_port) == ("alice", "203.0.113.9", 50123)
    assert event.extra["logon_type"] == 10
    assert event.extra["invalid_user"] is False
    # Decision 11: the record id is per channel, so the channel is in the hash.
    assert (event.source_event_id, event.target_resource) == ("1", "Security")
    # Seven fractional digits on the wire; datetime keeps six.
    assert event.timestamp == datetime(2026, 8, 2, 13, 5, 2, 123456, tzinfo=UTC)


def test_unknown_account_is_the_windows_invalid_user():
    (event,), _ = parse(logon(4625, SubStatus="0xC0000064"))
    assert event.extra["invalid_user"] is True


def test_sids_never_become_principal_keys():
    """Every failed logon for a nonexistent account carries the NULL SID; as a
    principal key it would join every unrelated failure into one incident."""
    events, _ = parse(SAMPLE)
    assert not any(key.startswith("principal:") for e in events for key in e.entity_keys())


# ---------------------------------------------------------------------------
# What is deliberately not authentication
# ---------------------------------------------------------------------------


def test_service_batch_and_system_logons_are_skipped():
    for logon_type in ("0", "4", "5"):
        events, stats = parse(logon(4624, LogonType=logon_type, TargetUserName="SYSTEM"))
        assert events == [] and stats.lines_skipped == 1


def test_machine_account_logons_are_skipped():
    events, stats = parse(logon(4624, LogonType="3", TargetUserName="WKS-01$"))
    assert events == [] and stats.lines_skipped == 1


def test_interactive_and_network_logons_are_kept():
    for logon_type in ("2", "3", "10"):
        (event,), _ = parse(logon(4624, LogonType=logon_type))
        assert event.outcome is Outcome.SUCCESS


def test_unmodelled_event_ids_are_skipped_not_errors():
    events, stats = parse(record(4672, {"SubjectUserName": "SYSTEM"}))
    assert events == [] and stats.lines_skipped == 1 and stats.errors == []


# ---------------------------------------------------------------------------
# Account and log changes
# ---------------------------------------------------------------------------


def test_group_membership_names_the_group_and_the_actor():
    content = record(4732, {"MemberSid": "S-1-5-21-1-2-3-1013", "TargetUserName": "Administrators",
                            "TargetSid": "S-1-5-32-544", "SubjectUserName": "Administrator"})
    (event,), _ = parse(content)
    assert (event.category, event.action) == (Category.IAM, "group_member_add")
    assert event.actor_name == "Administrator"
    assert event.extra["group"] == "Administrators"
    assert event.extra["member_sid"] == "S-1-5-21-1-2-3-1013"
    assert event.target_resource == "Security", "the group belongs in extra, not here"


def test_log_cleared_reads_its_subject_from_user_data():
    user_data = ('<LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/'
                 'eventlog"><SubjectUserName>Administrator</SubjectUserName></LogFileCleared>')
    (event,), _ = parse(record(1102, {}, user_data=user_data))
    assert (event.category, event.action) == (Category.CONFIGURATION, "audit_log_clear")
    assert event.actor_name == "Administrator"


def test_ipv4_mapped_addresses_join_with_other_sources():
    (event,), _ = parse(logon(4625, IpAddress="::ffff:203.0.113.5"))
    assert event.source_ip == "203.0.113.5"


def test_dash_means_no_address():
    (event,), _ = parse(logon(4625, IpAddress="-", IpPort="0"))
    assert event.source_ip is None and event.source_port is None


# ---------------------------------------------------------------------------
# Malformed and hostile input (decision 4: never raise)
# ---------------------------------------------------------------------------


def test_a_malformed_record_costs_only_itself():
    good = logon(4625)
    broken = logon(4625).replace("</System>", "")  # unbalanced
    events, stats = parse(f"<Events>{good}{broken}{logon(4624)}</Events>")
    assert len(events) == 2
    assert len(stats.errors) == 1
    assert stats.errors[0].reason.startswith("malformed XML")


def test_entity_declarations_are_rejected_before_parsing():
    bomb = (
        '<Event xmlns="' + NS + '"><!DOCTYPE x [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><System>&b;</System></Event>'
    )
    events, stats = parse(bomb + logon(4625))
    assert len(events) == 1
    assert stats.errors[0].reason == "DTD or entity declaration rejected"


def test_a_record_without_a_usable_timestamp_is_reported():
    events, stats = parse(record(4625, {"TargetUserName": "x"}, when="yesterday"))
    assert events == []
    assert "TimeCreated" in stats.errors[0].reason


def test_record_ids_from_different_channels_are_different_events():
    (a,), _ = parse(record(4720, {"SubjectUserName": "x"}, record_id=7, channel="Security"))
    (b,), _ = parse(record(4720, {"SubjectUserName": "x"}, record_id=7, channel="ForwardedEvents"))
    assert a.dedup_hash() != b.dedup_hash()


# ---------------------------------------------------------------------------
# Decision 5: the existing rules work on a third source unchanged
# ---------------------------------------------------------------------------


def test_existing_rules_detect_the_rdp_intrusion(client, db):
    from app.models import Event

    response = client.post(
        "/api/ingest",
        files={"file": ("windows_security.xml", SAMPLE.encode(), "text/plain")},
    )
    assert response.status_code == 201, response.text
    assert response.json()["source_type"] == "windows_security"

    # Through persistence, as production does (decision 13).
    events = [row.to_normalized() for row in db.query(Event).all()]
    (incident,) = correlate(run_rules(events).findings)

    assert incident.rule_ids == {
        "brute_force_auth", "brute_force_success", "invalid_user_enumeration",
    }
    assert incident.primary_entity == "ip:203.0.113.200"
    assert incident.severity.name == "CRITICAL"

    again = client.post(
        "/api/ingest",
        files={"file": ("windows_security.xml", SAMPLE.encode(), "text/plain")},
    ).json()
    assert (again["events_persisted"], again["duplicates_skipped"]) == (0, 16)
