"""Read API tests: the queue listing and the incident detail view.

These go through the real ingest endpoint with the committed sample logs rather
than hand-building findings. Correlation's own contract is covered in
`test_correlation.py`; what this file is for is the layer above it -- that the
pipeline runs on read, that the JSON says what the UI expects it to say, and
that an id from the listing resolves in the detail route.

Decision 13 is why the fixture uploads instead of parsing: rules must see what
survived dedup, and an endpoint tested over freshly parsed events would agree
with nothing in production.
"""

from __future__ import annotations

import pathlib

import pytest

SAMPLE_LOGS = pathlib.Path(__file__).resolve().parents[2] / "sample_logs"

# A second, unrelated intrusion: different address, different host, different
# account, four hours after the sample logs end. Nothing joins it to them, so
# the queue holds two incidents and `?severity=` has something to discriminate
# between. Synthetic on purpose -- the committed samples are one story, and a
# filter test that cannot fail is not a test.
UNRELATED_BRUTE_FORCE = "\n".join(
    f"Aug  2 09:1{n // 6}:{n % 6 * 10:02d} db02 sshd[{7000 + n}]: "
    f"Failed password for backup from 198.51.100.77 port {50000 + n} ssh2"
    for n in range(8)
)


def _upload(client, content: str, filename: str) -> dict:
    response = client.post(
        "/api/ingest",
        files={"file": (filename, content, "text/plain")},
        data={"default_year": "2026"},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture()
def ingested(client):
    """The committed sample logs, through the real endpoint."""
    for name in ("auth.log", "cloudtrail.json"):
        _upload(client, (SAMPLE_LOGS / name).read_text(encoding="utf-8"), name)
    return client


@pytest.fixture()
def two_incidents(ingested):
    _upload(ingested, UNRELATED_BRUTE_FORCE, "db02.log")
    return ingested


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------


def test_listing_returns_incidents_for_ingested_samples(ingested):
    body = ingested.get("/api/incidents").json()

    assert len(body) == 1
    row = body[0]
    assert row["severity"] == "CRITICAL"
    assert row["severity_score"] == 90
    assert row["primary_entity"].startswith("principal:")
    assert row["finding_count"] == 6
    assert row["tactic_count"] == len(row["tactics"]) == 5
    assert row["tactics"] == sorted(row["tactics"])
    assert row["first_seen"] < row["last_seen"]


def test_listing_is_empty_before_anything_is_ingested(client):
    assert client.get("/api/incidents").json() == []


def test_source_counts_are_per_source_and_count_each_event_once(ingested):
    """Findings overlap -- the fan-out of one burst and two rules over the same
    events -- so summing evidence lengths would report more log records than the
    incident rests on."""
    row = ingested.get("/api/incidents").json()[0]

    counts = {s["source_type"]: s["event_count"] for s in row["sources"]}
    assert set(counts) == {"syslog_sshd", "aws_cloudtrail"}
    assert all(n > 0 for n in counts.values())

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()
    total_evidence = sum(e["evidence_count"] for e in detail["timeline"])
    assert sum(counts.values()) < total_evidence


def test_listing_is_sorted_worst_first(two_incidents):
    body = two_incidents.get("/api/incidents").json()

    scores = [row["severity_score"] for row in body]
    assert scores == sorted(scores, reverse=True)


def test_severity_filter_selects_one_incident(two_incidents):
    everything = two_incidents.get("/api/incidents").json()
    assert len(everything) == 2
    assert {row["severity"] for row in everything} == {"CRITICAL", "HIGH"}

    critical = two_incidents.get("/api/incidents?severity=CRITICAL").json()
    high = two_incidents.get("/api/incidents?severity=HIGH").json()

    assert [row["severity"] for row in critical] == ["CRITICAL"]
    assert [row["severity"] for row in high] == ["HIGH"]
    assert critical[0]["incident_id"] != high[0]["incident_id"]


def test_severity_filter_matching_nothing_returns_an_empty_list(two_incidents):
    assert two_incidents.get("/api/incidents?severity=INFO").json() == []


def test_an_unknown_severity_is_rejected_rather_than_silently_empty(ingested):
    """An empty queue reads as 'nothing is wrong'. A typo must not say that."""
    assert ingested.get("/api/incidents?severity=urgent").status_code == 422


# ---------------------------------------------------------------------------
# Detail
# ---------------------------------------------------------------------------


def test_detail_resolves_an_id_from_the_listing(ingested):
    row = ingested.get("/api/incidents").json()[0]

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()

    assert detail["incident_id"] == row["incident_id"]
    # The detail view is a superset of the queue row, and must agree with it.
    assert {k: detail[k] for k in row} == row


def test_detail_carries_the_deterministic_summary(ingested):
    row = ingested.get("/api/incidents").json()[0]

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()

    assert detail["enrichment_source"] == "deterministic"
    assert detail["summary"].startswith("CRITICAL incident on ")
    assert "Timeline:" in detail["summary"]


def test_detail_lists_every_entity_key_including_suppressed_ones(ingested):
    row = ingested.get("/api/incidents").json()[0]

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()

    assert detail["entity_keys"] == sorted(detail["entity_keys"])
    assert "ip:203.0.113.5" in detail["entity_keys"]
    assert "user:root" in detail["entity_keys"]
    assert detail["primary_entity"] in detail["entity_keys"]


def test_detail_resolves_techniques_against_the_catalog(ingested):
    row = ingested.get("/api/incidents").json()[0]

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()

    by_id = {t["technique_id"]: t for t in detail["techniques"]}
    assert "T1110" in by_id
    assert by_id["T1110"]["name"] == "Brute Force"
    assert by_id["T1110"]["tactics"] == ["credential-access"]

    # Every tactic on the queue row is accounted for by a resolved technique.
    covered = {t for entry in detail["techniques"] for t in entry["tactics"]}
    assert covered == set(row["tactics"])


def test_timeline_is_chronological_and_shows_its_evidence(ingested):
    row = ingested.get("/api/incidents").json()[0]

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()
    timeline = detail["timeline"]

    assert len(timeline) == row["finding_count"]
    ends = [entry["last_seen"] for entry in timeline]
    assert ends == sorted(ends)
    assert all(e["first_seen"] <= e["last_seen"] for e in timeline)

    for entry in timeline:
        assert entry["rule_id"] and entry["title"]
        assert entry["source_type"] in {"syslog_sshd", "aws_cloudtrail"}
        # The raw lines, not a count of them: a finding that cannot show its
        # work is not auditable.
        assert len(entry["evidence"]) == entry["evidence_count"]
        assert all(isinstance(line, str) and line for line in entry["evidence"])

    brute = next(e for e in timeline if e["rule_id"] == "brute_force_auth")
    assert brute["technique_id"] == "T1110"
    assert brute["technique_name"] == "Brute Force"
    assert any("Failed password for root" in line for line in brute["evidence"])


def test_a_sequence_finding_sorts_after_the_threshold_finding_it_builds_on(ingested):
    """Effects must not sort above their causes.

    `brute_force_success` covers the failure burst *plus* the success that
    followed, so its evidence begins at the same instant as `brute_force_auth`
    and a sort on start time put it first -- the incident read as though the
    login preceded the failures it followed. Ordering is by `last_seen`, which
    is the field that distinguishes a burst from the chain containing it.
    """
    row = ingested.get("/api/incidents").json()[0]
    timeline = ingested.get(f"/api/incidents/{row['incident_id']}").json()["timeline"]

    order = [entry["rule_id"] for entry in timeline]
    burst = next(e for e in timeline if e["rule_id"] == "brute_force_auth")
    success = next(e for e in timeline if e["rule_id"] == "brute_force_success")

    # The premise: identical starts, so only the end can order them.
    assert burst["first_seen"] == success["first_seen"]
    assert burst["last_seen"] < success["last_seen"]
    assert order.index("brute_force_auth") < order.index("brute_force_success")


def test_a_timeline_entry_is_a_span_not_a_point(ingested):
    """A UI drawing one point per finding cannot show that one contains
    another; both would land on the same tick."""
    row = ingested.get("/api/incidents").json()[0]
    timeline = ingested.get(f"/api/incidents/{row['incident_id']}").json()["timeline"]

    multi = next(e for e in timeline if e["evidence_count"] > 1)
    single = next(e for e in timeline if e["evidence_count"] == 1)

    assert multi["first_seen"] < multi["last_seen"]
    assert single["first_seen"] == single["last_seen"]


def test_unknown_incident_id_returns_404(ingested):
    response = ingested.get("/api/incidents/INC-deadbeef")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "unknown incident"
    assert detail["incident_id"] == "INC-deadbeef"


def test_unknown_incident_id_is_404_on_an_empty_database(client):
    assert client.get("/api/incidents/INC-deadbeef").status_code == 404


# ---------------------------------------------------------------------------
# Stable ids across runs
# ---------------------------------------------------------------------------


def test_incident_ids_are_stable_across_two_requests(ingested):
    """Incidents are recomputed per request, so a detail URL is only usable if
    two runs over the same events agree on the id."""
    first = [row["incident_id"] for row in ingested.get("/api/incidents").json()]
    second = [row["incident_id"] for row in ingested.get("/api/incidents").json()]

    assert first == second
    assert all(row.startswith("INC-") for row in first)


def test_an_id_survives_a_later_unrelated_ingest(two_incidents):
    """The failure positional ids had: ingesting anything renumbered every
    incident, so yesterday's link pointed at somebody else's intrusion."""
    critical = two_incidents.get("/api/incidents?severity=CRITICAL").json()[0]

    _upload(
        two_incidents,
        "Aug  2 11:00:00 web03 sshd[9100]: "
        "Failed password for alice from 192.0.2.44 port 60001 ssh2",
        "web03.log",
    )

    after = two_incidents.get("/api/incidents?severity=CRITICAL").json()[0]
    assert after["incident_id"] == critical["incident_id"]
    assert two_incidents.get(
        f"/api/incidents/{critical['incident_id']}"
    ).status_code == 200


# ---------------------------------------------------------------------------
# Schema snapshot
# ---------------------------------------------------------------------------


def _shape(value):
    """Recursive key structure of a JSON value, with leaves as type names.

    A field rename, removal, or type change breaks the assertion below rather
    than the frontend. Lists collapse to their first element's shape -- the
    models are homogeneous, and snapshotting every row would make the fixture
    a copy of the sample logs.
    """
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_shape(value[0])] if value else []
    return type(value).__name__


LISTING_SHAPE = {
    "first_seen": "str",
    "finding_count": "int",
    "incident_id": "str",
    "last_seen": "str",
    "primary_entity": "str",
    "severity": "str",
    "severity_score": "int",
    "sources": [{"event_count": "int", "source_type": "str"}],
    "tactic_count": "int",
    "tactics": ["str"],
}

DETAIL_SHAPE = {
    **LISTING_SHAPE,
    "enrichment_source": "str",
    "entity_keys": ["str"],
    "summary": "str",
    "techniques": [{"name": "str", "tactics": ["str"], "technique_id": "str"}],
    "timeline": [
        {
            "evidence": ["str"],
            "evidence_count": "int",
            "first_seen": "str",
            "last_seen": "str",
            "rule_id": "str",
            "source_type": "str",
            "technique_id": "str",
            "technique_name": "str",
            "title": "str",
        }
    ],
}


def test_listing_schema_snapshot(ingested):
    body = ingested.get("/api/incidents").json()

    assert _shape(body[0]) == LISTING_SHAPE


def test_detail_schema_snapshot(ingested):
    row = ingested.get("/api/incidents").json()[0]

    detail = ingested.get(f"/api/incidents/{row['incident_id']}").json()

    assert _shape(detail) == DETAIL_SHAPE


def test_the_detail_shape_is_a_superset_of_the_listing_shape():
    """`IncidentDetail` inherits `IncidentSummary` so the two cannot drift.
    Pinned here as well, so dropping the inheritance is caught by a test rather
    than by a UI reading a field the detail route stopped returning."""
    assert {k: DETAIL_SHAPE.get(k) for k in LISTING_SHAPE} == LISTING_SHAPE
