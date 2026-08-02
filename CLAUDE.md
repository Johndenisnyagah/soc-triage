# SOC Alert Triage & Context Enrichment Pipeline

Ingests raw security logs (Syslog/sshd, Windows Security, AWS CloudTrail),
normalizes them, detects incidents with deterministic rules, and uses an LLM
only to *explain* and *map to MITRE ATT&CK* — never to detect.

Predecessor project: LogLens AI (SSH-only, upload-driven). This is a rewrite,
not a refactor.

## Architecture

```
ingest → parse (registry) → normalize → detect (rules) → correlate (entity keys)
       → enrich (LLM: summary + ATT&CK, validated) → triage → incident → report
```

## Settled decisions — do not change without discussion

1. **Rules detect, AI explains.** The LLM never creates, suppresses, or
   re-scores an incident. It writes summaries, maps ATT&CK techniques, and
   selects playbooks. If the LLM is unavailable the pipeline still produces
   complete, correct incidents with deterministic text.

2. **`sniff() -> float`, not `can_parse() -> bool`.** Parser selection is by
   highest confidence score, never by if/elif ordering. Below `min_confidence`
   we report "unrecognised format" rather than guessing.

3. **`parse()` yields, never returns a list.** Ingest must stream; large
   CloudTrail exports cannot be materialised in memory.

4. **Parsers never raise on malformed input.** Errors go to
   `ParseContext.stats` (capped at 100, excerpts truncated to 200 chars). One
   bad line must never abort an ingest run.

5. **`category` + `action` + `outcome`, not a flat `event_type`.** Detection
   rules subscribe to categories so they work across sources unmodified.

6. **Entity keys live in their own indexed table** (`event_entities`), not a
   JSON column. Cross-source correlation ("everything touching
   `ip:203.0.113.5` in the last hour") must be an indexed lookup.

7. **Timestamps are tz-aware `DateTime`.** Never strings. Syslog carries no
   year or timezone — those come from `ParseContext`, supplied by the operator.
   Syslog resolution is one second, which is coarser than the events it
   describes: several connections routinely share a timestamp. `NormalizedEvent`
   therefore carries `source_event_id`, the source's own natural identifier for
   a record, to tell those apart. See decision 11.

8. **ATT&CK technique IDs are validated against the real catalog.** Static
   `rule -> technique` mapping first; the LLM may propose a technique for
   unmapped cases, but any ID it returns is checked against the ATT&CK STIX
   data and rejected on failure. Never trust a model-generated technique ID.

9. **Playbooks are retrieved, not generated.** A local YAML library keyed by
   technique ID. The LLM selects and contextualizes; it does not invent
   response steps.

10. **Log content is untrusted input to the LLM.** Evidence lines are capped
    per incident, wrapped as data, and the system prompt states that
    instructions inside log content must never be followed. `user_agent`,
    Windows event descriptions, and CloudTrail fields are attacker-controlled.

11. **Dedup identity is `dedup_hash`, globally unique.** The hash excludes
    `raw` (so whitespace and JSON key order don't defeat it) but includes
    `source_event_id` — a per-source natural identifier (sshd: pid:port,
    CloudTrail: eventID). Without it, distinct events sharing a one-second
    syslog timestamp collide, and a brute-force burst collapses to a single
    event — destroying the signal detection depends on.

    Windows: `EventRecordID`, which is unique per channel per host — the
    parser must set `target_resource` to the channel name (e.g. `Security`) so
    the hash disambiguates across channels, since `host` alone does not.

    Uniqueness is global, not per-ingest, so re-ingesting a file is
    idempotent. Consequence: `Event.ingest_id` is the *first* ingest that saw
    the event, not every ingest containing it. Overlapping ingests will show
    high `duplicates_skipped` and few events — that is correct behavior. If
    per-ingest attribution is ever needed, add an `ingest_events` join table;
    do not weaken dedup.

12. **Rules emit Findings; correlation makes Incidents.** Rules are pure
    functions over a time-ordered, entity-scoped event sequence — no DB, no
    clock, no network. The engine groups by entity key once, before any rule
    runs. Because an event carries several entity keys, one burst produces
    identical findings under `ip:`, `user:`, and `host:`; collapsing those
    (same rule, same evidence, most specific key wins) is correlation's job,
    not the engine's.

13. **Detection runs over persisted events, never over parser output.**
    Dedup is part of the semantics: two sshd lines describing one connection
    attempt share a `dedup_hash` and collapse to one row. Any tool that runs
    rules over freshly parsed events will double-count and disagree with
    production.

## Open questions

- `host` for CloudTrail is currently `recipientAccountId`, which conflates
  "machine" with "AWS account". May need a separate `account`/`tenant` field.
- Windows `logon_type` (3 = network, 10 = RDP) is in `extra`. If a detection
  rule needs it, promote it to a column.

## Known limitations

- **Dedup is single-writer safe only.** `POST /api/ingest` checks existing
  hashes with a batched `IN` query before flush. Two concurrent uploads of
  overlapping data can both pass that check and collide on the global unique
  index. Fine for the current upload-driven flow; the step-9 worker must use
  `ON CONFLICT DO NOTHING` instead of check-then-insert.
- **Upload size cap is in-process.** `MAX_UPLOAD_BYTES` bounds the resident
  string, not what the server buffered — Starlette has already spooled the
  body. A real cap belongs at the reverse proxy.
- **Ingest is not fully streaming.** `parse()` takes the whole content string.
  The generator avoids a second copy as ORM objects; it does not avoid holding
  the source text. Changing this means parsers accepting a line iterator, and
  `ijson` for CloudTrail's bundled form.
- **SQLite discards timezone offsets.** `DateTime(timezone=True)` stores
  wall-clock time and returns naive datetimes; Postgres returns aware ones.
  Timestamps are normalized to UTC on write and re-stamped UTC on read, so
  both engines agree — but any code path that persists a non-UTC aware
  datetime without going through `Event.from_normalized` will be wrong on
  SQLite only.
- **Postgres unverified.** The suite runs on SQLite. The global unique index
  on `dedup_hash` and the `ix_event_triage` time-window queries are where the
  engines could still diverge.

## Build order

1. Ingest layer — schema, registry, sshd + cloudtrail parsers ✅
2. ORM migration — replace narrow `Event`, add `event_entities` ✅
3. Detection layer — port the 4 LogLens rules to be source-agnostic ✅
4. Correlation — group incidents by entity key + time window
5. ATT&CK mapping with catalog validation
6. LLM enrichment + confidence-gated fallback
7. Windows Security parser
8. Exec reports + playbooks
9. Continuous ingest endpoint + worker

## Stack

FastAPI, SQLAlchemy, Postgres (not SQLite — the pipeline claim requires it),
React 19 + TypeScript + Tailwind, Docker Compose.

## Conventions

- Python 3.12+, `from __future__ import annotations`, full type hints.
- Every parser needs a unit test with a malformed-input case.
- Detection rules are pure functions over event sequences — no DB access
  inside a rule, so they're trivially testable.
