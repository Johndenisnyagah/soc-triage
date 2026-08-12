# SOC Alert Triage & Context Enrichment Pipeline

Security operations teams drown in alerts. A single mid-sized environment produces
tens of thousands of log lines an hour across Linux hosts, cloud control planes, and
Windows domain controllers, and an analyst has to decide which handful of them matter.
Most of that time goes to mechanical work: reading raw log formats, pivoting between
sources to check whether the same address appears twice, and writing up what happened.

This pipeline automates that. It ingests raw logs — Linux `sshd` over syslog and AWS
CloudTrail today, with Windows Security event logs planned — normalizes them into a
single event schema, detects incidents with deterministic rules, and uses a language
model to explain what it found: MITRE ATT&CK mapping, executive summaries, and
response playbooks.

The source list is the part worth reading carefully. Two sources are implemented and
tested; Windows is designed for but not built. Nothing in the detection layer is
source-specific, so adding it is a parser rather than a rewrite — but "planned" and
"present" are different claims, and the checklist below is the authoritative one.

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

In progress. Ingest, persistence, detection, correlation and ATT&CK mapping are
complete and tested. Enrichment is built and exercised end to end against a fake
client — deterministic summaries, the validation gate, candidate shortlists and
orchestration — with only the provider client behind the `LLMClient` protocol left to
write. The Windows parser, reports and playbooks, and the continuous-ingest worker
come after that.

- [x] **Ingest layer** — normalized event schema, confidence-based parser registry, sshd and CloudTrail parsers
- [x] **Persistence** — event/entity models, ingest endpoint, global deduplication
- [x] **Detection** — source-agnostic rules over event windows
- [x] **Correlation** — incident grouping by entity key and time window
- [x] **MITRE ATT&CK mapping** — static rule mapping and catalog validation (LLM proposal path not yet built)
- [ ] **LLM enrichment** — summaries with structurally-validated deterministic fallback
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
git clone https://github.com/Johndenisnyagah/soc-triage.git
cd soc-triage/backend

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

## What it produces

`scripts/run_detection.py` ingests both sample files through the real endpoint, reads
the persisted events back out, and runs detection and correlation over them. It goes
through persistence deliberately: deduplication is part of the semantics, so a tool
that ran rules over freshly parsed events would double-count and disagree with what
the API produces.

This is verbatim output, not a mock-up:

```
$ python scripts/run_detection.py ../sample_logs
# parse-stats table trimmed for length — it is the same per-file counts shown in
# Quick start above. Everything from here down is unedited.

stats: events_in=28 no_timestamp=0 entities=11 rules=6 findings=19 incidents=1

==============================================================================
INC-ab9590ae  [CRITICAL]  principal:arn:aws:iam::123456789012:user/deploy
==============================================================================
  when      04:41:07-04:56:02
  sources   aws_cloudtrail+syslog_sshd
  tactics   credential-access, defense-impairment, discovery, persistence, privilege-escalation
  entities  account:123456789012, host:webserver01, ip:203.0.113.5, principal:arn:aws:iam::123456789012:user/deploy, user:deploy, user:root
  findings  6
    [CRITICAL] T1110      Successful authentication after repeated failures
               rule=brute_force_success  evidence=17  04:41:07-04:41:29
               leading_count=16, window=0:10:00
    [HIGH    ] T1098      Access key created after suspicious authentication
               rule=access_key_after_suspicious_auth  evidence=19  04:41:07-04:55:10
               leading_count=18, window=1:00:00
    [HIGH    ] T1110      Repeated authentication failures
               rule=brute_force_auth  evidence=16  04:41:07-04:41:24
               count=16, window=0:10:00
    [HIGH    ] T1685.002  Cloud audit logging disabled
               rule=cloud_logging_disabled  evidence=1  04:56:02-04:56:02
               outcome=failure, target=cloudtrail.amazonaws.com:StopLogging
    [HIGH    ] T1098      Administrator policy attached to principal
               rule=admin_policy_attached  evidence=1  04:55:33-04:55:33
               policy_arn=arn:aws:iam::aws:policy/AdministratorAccess
    [MEDIUM  ] T1087      Authentication attempts against non-existent accounts
               rule=invalid_user_enumeration  evidence=6  04:41:14-04:41:21
               count=6, distinct_count=3, distinct_values=['admin', 'oracle', 'postgres'], window=0:10:00

  summary
    CRITICAL incident on principal:arn:aws:iam::123456789012:user/deploy: 6 detections across 5 ATT&CK tactics. Activity ran from 2026-08-02 04:41:07 to 04:56:02 UTC, a span of 14 minutes. Evidence spans 2 log sources (syslog_sshd, aws_cloudtrail), which is why these detections were correlated into one incident rather than treated separately. Tactics observed: credential access, defense impairment, discovery, persistence, privilege escalation. Entities involved: account:123456789012, host:webserver01, ip:203.0.113.5, principal:arn:aws:iam::123456789012:user/deploy, user:deploy, user:root.

    Timeline:
      04:41:14-04:41:21  Authentication attempts against non-existent accounts [T1087 Account Discovery] (6 events)
      04:41:07-04:41:24  Repeated authentication failures [T1110 Brute Force] (16 events)
      04:41:07-04:41:29  Successful authentication after repeated failures [T1110 Brute Force] (17 events)
      04:41:07-04:55:10  Access key created after suspicious authentication [T1098 Account Manipulation] (19 events)
      04:55:33  Administrator policy attached to principal [T1098 Account Manipulation] (1 event)
      04:56:02  Cloud audit logging disabled [T1685.002 Disable or Modify Cloud Log] (1 event)
```

Nineteen findings became **one incident**, and that collapse is the whole point.

Six of those nineteen survive as distinct observations; the other thirteen were
duplicate views of the same activity, because the engine files a burst separately
under every entity key its evidence touches — `ip:`, `user:`, and `host:` — and
correlation absorbs the narrower copies.

What is left reads as one story spanning both log sources. An SSH brute-force burst
against `webserver01` (16 failures) lands a successful login, three non-existent
accounts are probed along the way, and then — from the same `ip:203.0.113.5`, now as
an AWS principal — an access key is minted, `AdministratorAccess` is attached, and
something tries to stop CloudTrail logging. The two halves never share a log format
or a field name. They share an entity key, which is what joins them.

Severity is `CRITICAL` because five distinct ATT&CK tactics are represented, not
because six rules fired. Twenty brute-force findings would still be one tactic and one
story; credential access → discovery → persistence → privilege escalation → defense
impairment is a kill chain.

The `summary` block is generated with no model involved. It is what ships when the LLM
is unavailable or its output fails validation, which is why it is written and tested
before any prompt exists.

## Read API

Two endpoints serve the same pipeline over HTTP. Incidents are **computed at request
time**, not stored: there is no incidents table, so the queue can never disagree with
the rules currently in the tree.

```bash
curl http://localhost:8000/api/incidents
curl http://localhost:8000/api/incidents/INC-ab9590ae
```

The listing is one row per incident, worst first, with `?severity=CRITICAL` to filter:

```json
[
  {
    "incident_id": "INC-ab9590ae",
    "severity": "CRITICAL",
    "severity_score": 90,
    "primary_entity": "principal:arn:aws:iam::123456789012:user/deploy",
    "finding_count": 6,
    "tactic_count": 5,
    "tactics": ["credential-access", "defense-impairment", "discovery", "persistence", "privilege-escalation"],
    "sources": [
      { "source_type": "syslog_sshd", "event_count": 17 },
      { "source_type": "aws_cloudtrail", "event_count": 5 }
    ],
    "first_seen": "2026-08-02T04:41:07Z",
    "last_seen": "2026-08-02T04:56:02Z"
  }
]
```

The detail route adds the deterministic summary, every entity key, the resolved ATT&CK
techniques, and a timeline carrying the raw log lines behind each finding. It also
reports `"enrichment_source": "deterministic"`, so the UI can label output produced
without a model rather than presenting it as though one had run.

**Timeline entries are spans ordered by end time.** A sequence rule's evidence begins
at its first *leading* event, so "successful authentication after repeated failures"
starts at the same instant as the burst it is built on — ordering by start time printed
the effect above its cause. Each entry carries both `first_seen` and `last_seen`, which
is also what lets a UI draw a finding as a bar rather than stacking every rule on one
tick.

**Incident IDs are derived from evidence, not from position in the result.** `INC-0001`
was assigned by enumeration order, which meant the same incident was renamed whenever a
later ingest reordered the components — and a detail URL pasted into a ticket silently
pointed somewhere else. The ID is now a short hash of the sorted set of evidence dedup
hashes, so the same activity produces `INC-ab9590ae` on any machine, in any upload
order, on a database that has never seen it before.

## Design decisions

**Rules detect, AI explains.** The LLM writes summaries, proposes ATT&CK techniques,
and selects playbooks. It never decides whether something is an incident.

**ATT&CK technique IDs are validated against the real catalog, and constrained to a
shortlist.** Detection rules map to techniques statically where the mapping is known.
For unmapped cases the model may propose a technique, but any ID it returns is checked
against the ATT&CK STIX data and rejected on failure. A plausible-looking technique ID
is exactly the kind of error a language model produces confidently.

The catalog rejects IDs that do not exist; it cannot reject one that does. T1078 Valid
Accounts is real, current, and resolves cleanly, and is still simply wrong for most
evidence — so the prompt offers a short list of candidates drawn from the incident's
event categories, and validation rejects any technique that was never on it. That is
what converts mapping from generation into selection: the wrong answers are bounded,
"none of these" is a listed choice, and a selection outside the list is a validation
failure rather than a plausible answer nobody can check.

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
