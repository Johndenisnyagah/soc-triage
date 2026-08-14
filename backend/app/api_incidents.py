"""GET /api/incidents and /api/incidents/{id} -- the read side the UI renders.

Incidents are **computed at request time**, not stored. There is no incidents
table and this module does not add one: the pipeline is
`events -> run_rules -> correlate`, and running it on read means the queue can
never disagree with the rules that are actually in the tree. Persisting
incidents would mean a stored row from before a threshold change sitting next
to a freshly computed one, with nothing in the response saying which is which.

The cost is honest and known: every request replays detection over every
persisted event. That is fine at sample-log scale and it is the reason the
incident ID had to stop being positional -- a recomputed queue reorders, and a
detail URL has to survive that (see `correlation.incident_id_for`).

Detection reads persisted rows, never parser output (decision 13), so
`compute_incidents` goes through `Event.to_normalized()` exactly as
`scripts/run_detection.py` does.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from enum import StrEnum

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.detection import attack
from app.detection.correlation import Incident, correlate
from app.detection.engine import run_rules
from app.detection.rules import Finding, Severity
from app.enrichment.llm import enrich
from app.ingest.schema import NormalizedEvent
from app.models import Event

router = APIRouter(prefix="/api", tags=["incidents"])


class SeverityName(StrEnum):
    """Query-param spelling of `Severity`.

    A StrEnum rather than a bare string so FastAPI rejects `?severity=urgent`
    with a 422 listing the real values, instead of silently returning an empty
    queue that reads as "nothing is wrong".
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class SourceCount(BaseModel):
    source_type: str
    event_count: int


class TechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]


class TimelineEntry(BaseModel):
    """One finding, as a row in the analyst's working view.

    A span, not a point. A threshold rule covering sixteen failures and a
    sequence rule covering those failures plus the success that followed both
    *begin* at the same instant, so a single timestamp cannot express that one
    contains the other -- and a UI given one point per finding can only draw
    them stacked at the same tick.
    """

    first_seen: datetime | None
    last_seen: datetime | None
    rule_id: str
    title: str
    technique_id: str | None
    # None when the ID does not resolve -- unknown or deprecated, which decision
    # 8 treats identically. The ID is still shown so a stale static mapping is
    # visible rather than quietly absent; it just contributes no name, no
    # tactic, and no entry in `IncidentDetail.techniques`.
    technique_name: str | None
    source_type: str
    evidence_count: int
    evidence: list[str]


class IncidentSummary(BaseModel):
    """Queue row. Everything needed to triage without opening the incident.

    `entity_keys` and `rule_ids` are carried here, not just on the detail, so
    the queue can be searched on them. Without them the only searchable
    identifier is `primary_entity` -- one key out of the several an incident
    actually touches -- so an analyst pivoting on an address that appears in the
    evidence but did not win `_KEY_PRECEDENCE` gets no hit, and the queue looks
    like it has nothing on an entity it is in fact reporting.

    This grows the listing payload: both fields are per-incident sets, so a
    response is roughly the sum of every incident's entity fan-out rather than
    one key each. That is fine at sample-log scale and is the same bet as
    recomputing incidents per request (above) -- and it is bounded by
    `MAX_COOCCURRING_KEYS`, which already caps how wide an incident's key set
    can get. If the queue ever needs to page, these are the two fields to drop
    behind a `?fields=` projection first.
    """

    incident_id: str
    severity: str = Field(description="Severity name, e.g. HIGH")
    severity_score: int = Field(description="Numeric severity, for sorting")
    primary_entity: str
    finding_count: int
    tactic_count: int
    tactics: list[str]
    sources: list[SourceCount]
    entity_keys: list[str]
    rule_ids: list[str] = Field(
        description="Distinct rule ids that fired, sorted. Searchable in the queue."
    )
    first_seen: datetime | None
    last_seen: datetime | None


class IncidentDetail(IncidentSummary):
    """The detail view. Inherits the queue row rather than restating it, so the
    two shapes cannot drift into disagreeing about the same incident."""

    summary: str
    enrichment_source: str = Field(
        description="'llm' or 'deterministic' -- the UI labels the latter"
    )
    techniques: list[TechniqueOut]
    timeline: list[TimelineEntry]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def compute_incidents(db: Session) -> list[Incident]:
    """Replay the pipeline over everything persisted. Order is `correlate()`'s."""
    rows = db.scalars(select(Event).order_by(Event.timestamp)).all()
    events = [row.to_normalized() for row in rows]
    return correlate(run_rules(events).findings)


def _event_key(event: NormalizedEvent) -> tuple[str, str]:
    """Identity for counting an event once per incident.

    Findings overlap by design -- the fan-out of one burst and the two rules
    that both saw it put the same log record in several evidence lists -- so
    summing `len(f.evidence)` would report far more records than the incident
    actually rests on.

    `dedup_hash()` alone is not enough here: a round-tripped event has lost
    `source_event_id`, so four connections sharing a second collapse to one
    hash. Pairing it with `raw` splits them again, and two events agreeing on
    both really are one record -- ingest dedup would never have stored them
    twice.
    """
    return (event.dedup_hash(), event.raw)


def _sources(incident: Incident) -> list[SourceCount]:
    counts: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for finding in incident.findings:
        for event in finding.evidence:
            key = _event_key(event)
            if key in seen:
                continue
            seen.add(key)
            counts[str(event.source_type)] += 1
    # Busiest source first, name as the tie-break: a stable order matters more
    # to a UI diffing two renders than the ordering itself does.
    return [
        SourceCount(source_type=name, event_count=n)
        for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def _finding_source(finding: Finding) -> str:
    """The source type behind a finding.

    Rules are source-agnostic (decision 5), so a finding's evidence *can* span
    sources -- `access_key_after_suspicious_auth` chains sshd failures into a
    CloudTrail key creation. Reporting the busiest one keeps the column
    single-valued for the UI; nothing is hidden, because `evidence` on the same
    row carries every line.
    """
    counts = Counter(str(e.source_type) for e in finding.evidence)
    if not counts:
        return "unknown"
    return min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]


def _timeline(incident: Incident) -> list[TimelineEntry]:
    # Ordered by `last_seen`, matching the deterministic summary. Sorting by
    # start time reads as effects before causes: a sequence rule's evidence
    # begins at its first *leading* event, so "successful authentication after
    # repeated failures" starts at the same instant as the burst it builds on
    # and sorted above it. What distinguishes them is where they end.
    #
    # Untimestamped findings still sort last -- a known time beats an unknown
    # one -- and the `is None` flag keeps None from being compared against a
    # datetime.
    ordered = sorted(
        incident.findings, key=lambda f: (f.last_seen is None, f.last_seen)
    )
    entries: list[TimelineEntry] = []
    for finding in ordered:
        info = attack.resolve(finding.technique)
        entries.append(
            TimelineEntry(
                first_seen=finding.first_seen,
                last_seen=finding.last_seen,
                rule_id=finding.rule_id,
                title=finding.title,
                technique_id=finding.technique,
                technique_name=info.name if info else None,
                source_type=_finding_source(finding),
                evidence_count=len(finding.evidence),
                evidence=[e.raw for e in finding.evidence],
            )
        )
    return entries


def _techniques(incident: Incident) -> list[TechniqueOut]:
    """Resolved techniques, from `Finding.technique` only.

    Not `proposed_technique`: nothing populates it yet, and when the LLM
    proposal path lands it belongs in its own field rather than mixed in with
    the statically mapped IDs the tactic count is built from (decision 8).
    """
    resolved = {}
    for finding in incident.findings:
        info = attack.resolve(finding.technique)
        if info:
            resolved[info.technique_id] = info
    return [
        TechniqueOut(
            technique_id=info.technique_id,
            name=info.name,
            tactics=sorted(info.tactics),
        )
        for _, info in sorted(resolved.items())
    ]


def to_summary(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        incident_id=incident.incident_id,
        severity=incident.severity.name,
        severity_score=int(incident.severity),
        primary_entity=incident.primary_entity,
        finding_count=len(incident.findings),
        tactic_count=len(incident.tactics),
        tactics=sorted(incident.tactics),
        sources=_sources(incident),
        entity_keys=sorted(incident.entity_keys),
        rule_ids=sorted(incident.rule_ids),
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
    )


def to_detail(incident: Incident) -> IncidentDetail:
    # `enrich` with no client is the deterministic path by construction, and
    # returns the same `summarize()` text this endpoint would otherwise call
    # directly. Going through it means `enrichment_source` is reported by the
    # stage that decides it rather than hardcoded here -- so wiring a provider
    # client in later changes one argument, not this response.
    enrichment = enrich(incident, None)
    return IncidentDetail(
        **to_summary(incident).model_dump(),
        summary=enrichment.summary,
        enrichment_source=str(enrichment.source),
        techniques=_techniques(incident),
        timeline=_timeline(incident),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/incidents", response_model=list[IncidentSummary])
def list_incidents(
    severity: SeverityName | None = Query(
        None, description="Return only incidents at exactly this severity"
    ),
    db: Session = Depends(get_db),
) -> list[IncidentSummary]:
    incidents = compute_incidents(db)
    if severity is not None:
        wanted = Severity[severity.value]
        incidents = [i for i in incidents if i.severity is wanted]
    # No re-sort: correlate() already returns worst-first, and the queue order
    # is part of its contract.
    return [to_summary(i) for i in incidents]


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> IncidentDetail:
    for incident in compute_incidents(db):
        if incident.incident_id == incident_id:
            return to_detail(incident)

    raise HTTPException(
        status_code=404,
        detail={
            "error": "unknown incident",
            "message": (
                f"No incident with id '{incident_id}'. Incidents are computed "
                "from the events currently stored, so an id stops resolving if "
                "the evidence behind it is no longer present."
            ),
            "incident_id": incident_id,
        },
    )
