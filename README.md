# SOC Alert Triage & Context Enrichment Pipeline

Security operations teams drown in alerts. A single mid-sized environment produces
tens of thousands of log lines an hour across Linux hosts, cloud control planes, and
Windows domain controllers, and an analyst has to decide which handful of them matter.
Most of that time goes to mechanical work: reading raw log formats, pivoting between
sources to check whether the same address appears twice, and writing up what happened.

This pipeline automates that. It ingests raw logs from multiple sources, normalizes
them into a single event schema, detects incidents with deterministic rules, and uses
a language model to explain what it found — MITRE ATT&CK mapping, executive summaries,
and response playbooks.

The architectural constraint the whole project is built around: **rules detect, AI
explains.** The model never creates, suppresses, or re-scores an incident. If the LLM
is unavailable, the pipeline still produces complete and correct incidents with
deterministic text. Detection you can't reproduce and audit isn't detection.

This project builds on [LogLens AI](https://github.com/Johndenisnyagah/loglens_AI),
which applied the same rules-detect/AI-explains architecture to single-source SSH
authentication logs. Working on it made the structural limits clear: a schema built
around one log format can't normalize a CloudTrail record, and incidents scoped to a
single uploaded file can't correlate an attacker who appears in two places. This is a
rewrite that addresses both.

## Status

In progress. Ingest and persistence are complete and tested; detection and enrichment
are next.

- [x] **Ingest layer** — normalized event schema, confidence-based parser registry, sshd and CloudTrail parsers
- [x] **Persistence** — event/entity models, ingest endpoint, global deduplication
- [ ] **Detection** — source-agnostic rules over event windows
- [ ] **Correlation** — incident grouping by entity key and time window
- [ ] **MITRE ATT&CK mapping** — static rule mapping, LLM proposal, catalog validation
- [ ] **LLM enrichment** — summaries with confidence-gated deterministic fallback
- [ ] **Windows Security parser**
- [ ] **Executive reports and response playbooks**
- [ ] **Continuous ingest endpoint and worker**

## Architecture

```
ingest → parse (registry) → normalize → detect (rules) → correlate (entity keys)
       → enrich (LLM: summary + ATT&CK, validated) → triage → incident → report
```

Two design choices carry most of the weight.

**Parser selection is confidence-scored, not ordered.** Each parser implements
`sniff(sample) -> float` rather than a boolean `can_parse`. The registry runs every
parser's sniff against the first 200 lines and picks the highest scorer, falling back
to an explicit "unrecognised format" response below a confidence floor. An if/elif
chain would mean that adding a parser could silently capture files belonging to
another one; scoring makes that impossible, and it gives an honest failure path
instead of guessing.

**Correlation runs on entity keys, not source fields.** Every normalized event emits
namespaced identifiers for the things it touches — `ip:203.0.113.5`, `user:root`,
`host:web01` — stored in their own indexed table. A failed SSH login and a failed
CloudTrail console login from the same address produce the same key, so they can land
in one incident rather than two unrelated ones. Storing these in a JSON column would
have made cross-source lookup a full table scan; the separate table keeps it a single
indexed query.

## Quick start

```bash
git clone https://github.com/Johndenisnyagah/soc-triage-.git
cd soc-triage-/backend

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest -q
uvicorn app.main:app --reload
```

Defaults to SQLite for local development. Set `DATABASE_URL` for Postgres.

Ingest a sample file:

```bash
curl -F "file=@../sample_logs/auth.log" http://localhost:8000/api/ingest
```

The response includes the ingest id and parse statistics — lines read, events
emitted, lines skipped, and duplicates skipped — so a partially malformed upload
reports exactly what was dropped rather than failing silently.

```json
{
  "ingest_id": 1,
  "filename": "auth.log",
  "source_type": "syslog_sshd",
  "detected_confidence": 0.86,
  "events_persisted": 18,
  "duplicates_skipped": 0,
  "stats": { "lines_read": 30, "events_emitted": 18, "lines_skipped": 12, "errors": [] }
}
```

The twelve skipped lines are the CRON, systemd, and sshd session lines the sshd
parser recognises as syslog but does not model as authentication events. Running
the same command a second time returns `events_persisted: 0` and
`duplicates_skipped: 18` — deduplication is global, so re-ingesting a file is
idempotent.

`sample_logs/cloudtrail.json` covers the second parser, and deliberately shares a
source IP and username with `auth.log`:

```bash
curl -F "file=@../sample_logs/cloudtrail.json" http://localhost:8000/api/ingest
```

Both files together produce a single entity key `ip:203.0.113.5` spanning 27
events across both sources — an SSH brute-force burst, a successful SSH login,
then AWS console logins and IAM changes from that same address. That is the
cross-source correlation the detection and incident layers are being built on.

## Design decisions

**Rules detect, AI explains.** The LLM writes summaries, proposes ATT&CK techniques,
and selects playbooks. It never decides whether something is an incident.

**ATT&CK technique IDs are validated against the real catalog.** Detection rules map
to techniques statically where the mapping is known. For unmapped cases the model may
propose a technique, but any ID it returns is checked against the ATT&CK STIX data and
rejected on failure. A plausible-looking technique ID is exactly the kind of error a
language model produces confidently.

**Playbooks are retrieved, not generated.** Response steps come from a local YAML
library keyed by technique ID. The model selects and contextualizes; it does not
invent incident response procedures.

**Log content is untrusted input.** User agents, Windows event descriptions, and
CloudTrail fields are attacker-controllable. Evidence passed to the model is capped
per incident, wrapped as data, and the system prompt states that instructions found
inside log content must never be followed.

**Parsers never raise on malformed input.** Bad lines increment a skip counter and
record a truncated excerpt, capped at 100 errors per run. One malformed line aborting
a 500,000-line ingest is the classic pipeline failure.

**Deduplication is global and identity-aware.** The event fingerprint excludes the raw
text, so whitespace and JSON key ordering don't defeat it, but includes a per-source
natural identifier — pid and port for sshd, `eventID` for CloudTrail. Without that
identifier, distinct events sharing a one-second syslog timestamp collide, and a
brute-force burst collapses into a single event. Since a brute-force burst is
precisely what the detection layer needs to see, that collision would destroy the
signal the project exists to find.

## Known limitations

- **Dedup is single-writer safe only.** The ingest endpoint checks existing hashes
  with a batched query before flush. Two concurrent uploads of overlapping data can
  both pass that check and collide on the unique index. The continuous-ingest worker
  will need an upsert rather than check-then-insert.
- **Upload size cap is in-process.** `MAX_UPLOAD_BYTES` bounds the resident string,
  not what the server buffered — the ASGI layer has already spooled the body. A real
  cap belongs at the reverse proxy.
- **Ingest is not fully streaming.** Parsers take the whole content string. The
  generator interface avoids a second copy as ORM objects; it does not avoid holding
  the source text. Full streaming means parsers accepting a line iterator, and
  incremental JSON parsing for CloudTrail's bundled form.
- **Postgres unverified.** The test suite runs on SQLite. The global unique index and
  the time-window query index are where the two engines could diverge.

## Stack

FastAPI, SQLAlchemy 2.0, Postgres (SQLite for local development), pytest. React and
TypeScript frontend to follow.
