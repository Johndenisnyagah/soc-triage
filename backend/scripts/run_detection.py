"""Ingest the sample logs, then run detection over what the database kept.

Deliberately *not* a shortcut around persistence. Decision 13: dedup is part of
the semantics, so a tool that runs rules over freshly parsed events reports
counts production will never produce. Two sshd lines describing one connection
attempt can share a `dedup_hash` and collapse to a single row; rules must see
the survivor, not both halves.

So this uploads through the real `POST /api/ingest` -- routing, format sniffing,
dedup and all -- then reads `events` back out and converts each row with
`Event.to_normalized()`.

    python scripts/run_detection.py ../sample_logs

By default it ingests into a throwaway SQLite file so repeated runs are
comparable; dedup is global, so reusing a database would make the second run
report zero new events. Pass --database-url to point at an existing database
and --no-ingest to skip straight to detection over whatever is already there.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import tempfile

_BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND))

SAMPLE_FILES = ("auth.log", "cloudtrail.json")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "samples",
        nargs="?",
        default=str(_BACKEND.parent / "sample_logs"),
        type=pathlib.Path,
        help="directory holding the sample log files",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="target database; defaults to a throwaway SQLite file",
    )
    parser.add_argument(
        "--no-ingest",
        action="store_true",
        help="skip ingest and detect over events already stored",
    )
    return parser.parse_args()


args = _parse_args()

# Must be set before app.database is imported, exactly as conftest does it.
if args.database_url:
    os.environ["DATABASE_URL"] = args.database_url
elif not args.no_ingest:
    _tmp = pathlib.Path(tempfile.mkdtemp(prefix="soc-triage-detect-"))
    os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'detect.db').as_posix()}"

from fastapi.testclient import TestClient  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.detection.correlation import correlate  # noqa: E402
from app.detection.engine import run_rules  # noqa: E402
from app.enrichment.summary import summarize  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Event  # noqa: E402


def ingest(samples: pathlib.Path) -> None:
    """Upload each sample file through the real endpoint."""
    print(f"{'file':<18} {'source':<16} {'conf':>5} {'kept':>5} {'dupes':>6}  parse stats")
    with TestClient(app) as client:
        for name in SAMPLE_FILES:
            path = samples / name
            if not path.exists():
                sys.exit(f"missing sample file: {path}")
            response = client.post(
                "/api/ingest",
                files={"file": (name, path.read_bytes(), "text/plain")},
            )
            if response.status_code != 201:
                sys.exit(f"ingest of {name} failed: {response.status_code} {response.text}")
            body = response.json()
            stats = body["stats"]
            print(
                f"{name:<18} {body['source_type']:<16} {body['detected_confidence']:>5.2f} "
                f"{body['events_persisted']:>5} {body['duplicates_skipped']:>6}  "
                f"read={stats['lines_read']} emitted={stats['events_emitted']} "
                f"skipped={stats['lines_skipped']}"
            )


def load_events() -> list:
    """Read persisted rows back as the schema objects rules operate on."""
    with SessionLocal() as session:
        rows = session.query(Event).order_by(Event.timestamp).all()
        return [row.to_normalized() for row in rows]


def report(events: list) -> None:
    result = run_rules(events)
    incidents = correlate(result.findings)

    s = result.stats
    print(
        f"\nstats: events_in={s.events_in} no_timestamp={s.events_without_timestamp} "
        f"entities={s.entities} rules={s.rules_run} findings={s.findings} "
        f"incidents={len(incidents)}\n"
    )

    for incident in incidents:
        span = ""
        if incident.first_seen and incident.last_seen:
            span = f"{incident.first_seen:%H:%M:%S}-{incident.last_seen:%H:%M:%S}"
        sources = sorted(
            {str(e.source_type) for f in incident.findings for e in f.evidence}
        )
        print("=" * 78)
        print(f"{incident.incident_id}  [{incident.severity.name}]  {incident.primary_entity}")
        print("=" * 78)
        print(f"  when      {span}")
        print(f"  sources   {'+'.join(sources)}")
        print(f"  tactics   {', '.join(sorted(incident.tactics)) or '-'}")
        # Every key the incident touched, including any suppressed for joining.
        print(f"  entities  {', '.join(sorted(incident.entity_keys))}")
        print(f"  findings  {len(incident.findings)}")
        for finding in incident.findings:
            fspan = ""
            if finding.first_seen and finding.last_seen:
                fspan = f"  {finding.first_seen:%H:%M:%S}-{finding.last_seen:%H:%M:%S}"
            print(
                f"    [{finding.severity.name:8}] {finding.technique or '-':10} "
                f"{finding.title}"
            )
            print(
                f"               rule={finding.rule_id}  "
                f"evidence={len(finding.evidence)}{fspan}"
            )
            meta = ", ".join(
                f"{k}={v}" for k, v in finding.metadata.items() if v is not None
            )
            if meta:
                print(f"               {meta}")
        # The deterministic summary, unconditionally. No LLM is wired in yet and
        # this block must still read as a finished product when one is: it is
        # what ships whenever the model is unavailable or its output fails the
        # gate, so seeing it on every run is how it stays honest rather than
        # becoming a stub nobody looks at.
        print("\n  summary")
        for line in summarize(incident).splitlines():
            print(f"    {line}" if line else "")
        print()


if not args.no_ingest:
    ingest(args.samples)

events = load_events()
print(f"\nevents read back from the database: {len(events)}")
report(events)
