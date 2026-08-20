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
  "detected_confidence": 0.932,
  "events_persisted": 31,
  "duplicates_skipped": 0,
  "stats": { "lines_read": 44, "events_emitted": 31, "lines_skipped": 13, "errors": [] }
}
```

The thirteen skipped lines are the CRON, systemd, and sshd session lines the sshd
parser recognises as syslog but does not model as authentication events. Running
the same command a second time returns `events_persisted: 0` and
`duplicates_skipped: 31` — deduplication is global, so re-ingesting a file is
idempotent.

`sample_logs/cloudtrail.json` covers the second parser, and deliberately shares a
source IP and username with `auth.log`:

```bash
curl -F "file=@../sample_logs/cloudtrail.json" http://localhost:8000/api/ingest
```

The two files describe **two unrelated intrusions**, which is what makes them
useful as a fixture rather than a demo.

The first is one attacker at `ip:203.0.113.5` moving between a Linux host and an
AWS account over eighteen minutes: SSH brute force, username enumeration, a pivot
to failed console logins, a successful SSH login as `deploy`, IAM recon, a policy
attach, an access key, a return to SSH for more enumeration, and finally an attempt
to stop CloudTrail logging. Host and cloud activity **alternate**, which is the
cross-source chronology the detection and incident layers exist to reassemble.

The second is a plain SSH brute force against `backup` on `db02` from
`198.51.100.77`, hours later. It shares no entity key with the first, so
correlation must leave the two apart — the sample exercises separation as well as
joining.

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

stats: events_in=43 no_timestamp=0 entities=17 rules=6 findings=34 incidents=2

==============================================================================
INC-fe9ac9b7  [CRITICAL]  principal:arn:aws:iam::123456789012:user/deploy
==============================================================================
  when      04:41:07-04:59:20
  sources   aws_cloudtrail+syslog_sshd
  tactics   credential-access, defense-impairment, discovery, persistence, privilege-escalation
  entities  account:123456789012, host:webserver01, ip:203.0.113.5, principal:arn:aws:iam::123456789012:user/deploy, user:deploy, user:root
  findings  9
    [CRITICAL] T1110      Successful authentication after repeated failures
               rule=brute_force_success  evidence=21  04:41:07-04:48:41
               leading_count=20, window=0:10:00
    [HIGH    ] T1098      Access key created after suspicious authentication
               rule=access_key_after_suspicious_auth  evidence=21  04:41:07-04:52:11
               leading_count=20, window=1:00:00
    [HIGH    ] T1110      Repeated authentication failures
               rule=brute_force_auth  evidence=20  04:41:07-04:47:10
               count=20, window=0:10:00
    [HIGH    ] T1110      Repeated authentication failures
               rule=brute_force_auth  evidence=6  04:57:30-04:58:40
               count=6, window=0:10:00
    [HIGH    ] T1685.002  Cloud audit logging disabled
               rule=cloud_logging_disabled  evidence=1  04:59:20-04:59:20
               outcome=failure, target=cloudtrail.amazonaws.com:StopLogging
    [HIGH    ] T1098      Administrator policy attached to principal
               rule=admin_policy_attached  evidence=1  04:50:20-04:50:20
               policy_arn=arn:aws:iam::aws:policy/IAMFullAccess
    [HIGH    ] T1098      Administrator policy attached to principal
               rule=admin_policy_attached  evidence=1  04:56:33-04:56:33
               policy_arn=arn:aws:iam::aws:policy/AdministratorAccess
    [MEDIUM  ] T1087      Authentication attempts against non-existent accounts
               rule=invalid_user_enumeration  evidence=6  04:43:12-04:44:27
               count=6, distinct_count=3, distinct_values=['admin', 'oracle', 'postgres'], window=0:10:00
    [MEDIUM  ] T1087      Authentication attempts against non-existent accounts
               rule=invalid_user_enumeration  evidence=6  04:57:30-04:58:40
               count=6, distinct_count=3, distinct_values=['jenkins', 'gitlab', 'ansible'], window=0:10:00

  summary
    CRITICAL incident on principal:arn:aws:iam::123456789012:user/deploy: 9 detections across 5 ATT&CK tactics. Activity ran from 2026-08-02 04:41:07 to 04:59:20 UTC, a span of 18 minutes. Evidence spans 2 log sources (syslog_sshd, aws_cloudtrail), which is why these detections were correlated into one incident rather than treated separately. Tactics observed: credential access, defense impairment, discovery, persistence, privilege escalation. Entities involved: account:123456789012, host:webserver01, ip:203.0.113.5, principal:arn:aws:iam::123456789012:user/deploy, user:deploy, user:root.

    Timeline:
      04:43:12-04:44:27  Authentication attempts against non-existent accounts [T1087 Account Discovery] (6 events)
      04:41:07-04:47:10  Repeated authentication failures [T1110 Brute Force] (20 events)
      04:41:07-04:48:41  Successful authentication after repeated failures [T1110 Brute Force] (21 events)
      04:50:20  Administrator policy attached to principal [T1098 Account Manipulation] (1 event)
      04:41:07-04:52:11  Access key created after suspicious authentication [T1098 Account Manipulation] (21 events)
      04:56:33  Administrator policy attached to principal [T1098 Account Manipulation] (1 event)
      04:57:30-04:58:40  Repeated authentication failures [T1110 Brute Force] (6 events)
      04:57:30-04:58:40  Authentication attempts against non-existent accounts [T1087 Account Discovery] (6 events)
      04:59:20  Cloud audit logging disabled [T1685.002 Disable or Modify Cloud Log] (1 event)

==============================================================================
INC-27359b57  [HIGH]  ip:198.51.100.77
==============================================================================
  when      08:12:03-08:14:41
  sources   syslog_sshd
  tactics   credential-access
  entities  host:db02, ip:198.51.100.77, user:backup
  findings  1
    [HIGH    ] T1110      Repeated authentication failures
               rule=brute_force_auth  evidence=7  08:12:03-08:14:41
               count=7, window=0:10:00

  summary
    HIGH incident on ip:198.51.100.77: 1 detection across 1 ATT&CK tactic. Activity ran from 2026-08-02 08:12:03 to 08:14:41 UTC, a span of 2 minutes. All evidence came from syslog_sshd. Tactics observed: credential access. Entities involved: host:db02, ip:198.51.100.77, user:backup.

    Timeline:
      08:12:03-08:14:41  Repeated authentication failures [T1110 Brute Force] (7 events)
```

Thirty-four findings became **two incidents**, and both halves of that are the point:
the collapse *and* the split.

Nine of the thirty-four survive as distinct observations in the first incident; the
rest were duplicate views of the same activity, because the engine files a burst
separately under every entity key its evidence touches — `ip:`, `user:`, `host:`,
`principal:` — and correlation absorbs the narrower copies.

The first incident reads as one story woven from both log sources. An SSH brute-force
burst against `webserver01` lands a successful login as `deploy`; three non-existent
accounts are probed along the way; the same address then appears as an AWS principal
failing console logins, attaches `IAMFullAccess`, mints an access key, escalates to
`AdministratorAccess`, comes *back* to SSH to probe three more accounts, and finally
tries to stop CloudTrail logging. Host and cloud activity alternate through the middle
of that timeline. The two halves never share a log format or a field name. They share
an entity key, which is what joins them.

The second incident is the harder claim. A brute force against `backup` on `db02` from
`198.51.100.77`, hours later, shares **no** entity key with the first — so correlation
leaves it alone rather than absorbing it into the loudest story in the batch. Joining
is the easy half; knowing when not to join is what keeps an incident queue readable.

Severity is `CRITICAL` for the first because five distinct ATT&CK tactics are
represented, not because nine rules fired. The second stays `HIGH`: seven failures is
one tactic and one story, and a single tactic never reaches the escalation rung.
Credential access → discovery → persistence → privilege escalation → defense impairment
is a kill chain; a password guess is not.

The `summary` block is generated with no model involved. It is what ships when the LLM
is unavailable or its output fails validation, which is why it is written and tested
before any prompt exists.

## Read API

Two endpoints serve the same pipeline over HTTP. Incidents are **computed at request
time**, not stored: there is no incidents table, so the queue can never disagree with
the rules currently in the tree.

```bash
curl http://localhost:8000/api/incidents
curl http://localhost:8000/api/incidents/INC-fe9ac9b7
```

The listing is one row per incident, worst first, with `?severity=CRITICAL` to filter:

```json
[
  {
    "incident_id": "INC-fe9ac9b7",
    "severity": "CRITICAL",
    "severity_score": 90,
    "primary_entity": "principal:arn:aws:iam::123456789012:user/deploy",
    "finding_count": 9,
    "tactic_count": 5,
    "tactics": ["credential-access", "defense-impairment", "discovery", "persistence", "privilege-escalation"],
    "sources": [
      { "source_type": "syslog_sshd", "event_count": 21 },
      { "source_type": "aws_cloudtrail", "event_count": 10 }
    ],
    "entity_keys": [
      "account:123456789012",
      "host:webserver01",
      "ip:203.0.113.5",
      "principal:arn:aws:iam::123456789012:user/deploy",
      "user:deploy",
      "user:root"
    ],
    "rule_ids": [
      "access_key_after_suspicious_auth",
      "admin_policy_attached",
      "brute_force_auth",
      "brute_force_success",
      "cloud_logging_disabled",
      "invalid_user_enumeration"
    ],
    "first_seen": "2026-08-02T04:41:07Z",
    "last_seen": "2026-08-02T04:59:20Z"
  }
]
```

`entity_keys` and `rule_ids` ride on the queue row rather than only on the detail so
the queue can be searched by them: an analyst pivoting on an address that appears in
an incident's evidence but did not win `_KEY_PRECEDENCE` would otherwise get no hit,
and the queue would look empty on an entity it is in fact reporting.

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
hashes, so the same activity produces `INC-fe9ac9b7` on any machine, in any upload
order, on a database that has never seen it before.

## Testing

302 tests, all passing, running offline in about three seconds:

```bash
cd backend && pytest -q
```

Coverage is not evenly spread, and deliberately so. The heaviest files are the ones
where being subtly wrong is survivable long enough to reach production:
`test_enrichment_validation.py` (50), `test_correlation.py` (42),
`test_detection_rules.py` (36), `test_enrichment_llm.py` (32).

Six categories are worth calling out, because they test things a conventional unit
test does not reach:

**Golden-hash pins** force a change to be deliberate.
[`test_dedup_hash_is_stable_across_releases`](backend/tests/test_dedup_identity.py:112)
asserts one literal digest. `dedup_hash` is a stored, globally unique column, so
changing how it is computed silently invalidates every row already written —
previously-ingested events stop matching and re-ingest as duplicates. The docstring
records the one time the value legitimately changed and why. Editing that line is a
migration, not an edit.

**Snapshot tests over deliverables.**
[`test_sample_incident_summary_snapshot`](backend/tests/test_enrichment_summary.py:324)
asserts the deterministic summary byte for byte, ATT&CK technique names included, so a
rename in a future catalog release fails loudly rather than reading oddly.
[`test_generated_types_are_current`](backend/tests/test_frontend_types.py:22) does the
same across the language boundary: `frontend/src/api/schema.ts` is generated from the
OpenAPI document, and nothing otherwise forces a developer who renames a Pydantic field
to regenerate it. TypeScript would keep compiling happily against the stale interface
and the mismatch would surface as `undefined` in the browser.

**Subprocess bootstrap probes** catch import-time failures the suite structurally
cannot see. [`test_registry_bootstrap.py`](backend/tests/test_registry_bootstrap.py:53)
spawns a fresh interpreter that imports only `app.main` — exactly what uvicorn imports,
nothing more — and asserts the parser registry is populated. Within a single pytest
session, collection imports every test module, which registers the parsers as a side
effect and hides the bug entirely.

**Invariant guards** pin a structural rule rather than a case.
[`test_no_service_default_maps_to_authentication`](backend/tests/test_parser_cloudtrail.py:328)
asserts `Category.AUTHENTICATION not in _SOURCE_CATEGORY.values()`. Authentication is
the only category whose rules fire on `category` + `outcome` alone —
`is_auth_success()` never inspects `action` — so every other category is safe under a
coarse service-level default and this one is not. The test exists to fail when somebody
adds the next one.

**The offline ATT&CK check.**
[`test_attack_catalog.py`](backend/tests/test_attack_catalog.py) reads the committed
catalog and never the network; a suite that fetched ATT&CK would fail on a plane and,
worse, would pass or fail depending on what MITRE published that morning.
[`test_every_rule_technique_resolves`](backend/tests/test_attack_catalog.py:246) and
[`test_every_candidate_technique_resolves`](backend/tests/test_attack_catalog.py:284)
assert that every hand-written technique ID still resolves *and* still yields at least
one tactic — resolving alone is not enough, since a technique with no tactics validates
and contributes nothing to severity.

**Boundary tests for the AI seam.**
[`test_a_proposed_technique_cannot_change_incident_severity`](backend/tests/test_correlation.py:405)
is the executable form of the dashed red edge in
[ARCHITECTURE.md](ARCHITECTURE.md#the-ai-boundary).

### Three defects the suite caught

**A routine STS identity read became a CRITICAL compromise.** Neither layer was wrong
alone. The CloudTrail parser categorised by `eventSource` when `eventName` was
unmapped, and `sts.amazonaws.com` defaulted to `AUTHENTICATION`; separately,
`SuccessfulLoginAfterBruteForce` accepts any `is_auth_success()` event as its trailing
half. Compose them and a successful `GetCallerIdentity` — which authenticates nothing,
and which the AWS CLI and effectively every CI job emit constantly — satisfied the
trailing condition. A burst of failed logins followed by any routine automation raised
"successful authentication after repeated failures" for an authentication that never
happened. Pinned by
[`test_get_caller_identity_after_a_burst_is_not_a_successful_login`](backend/tests/test_sts_false_positive.py:67),
with
[`test_a_real_credential_issuance_after_a_burst_still_fires`](backend/tests/test_sts_false_positive.py:102)
asserting the fix did not buy quiet by disabling the detection — `AssumeRole` genuinely
authenticates, and a burst followed by one still fires.

**The parser registry was empty under uvicorn.** `app/ingest/parsers/__init__.py` runs
the `@register` decorators, but nothing in the app's import chain reached it. Every
upload returned 422 "unrecognised log format" with an empty `supported_formats` list —
while the test suite was green, because pytest imports the parser test modules during
collection and registers everything as a side effect before any request test runs. The
suite was structurally incapable of catching it, which is why the fix shipped with a
subprocess probe rather than another in-process assertion. Guarded by
[`test_registry_is_populated`](backend/tests/test_select_parser.py:9) and
[`test_importing_the_app_registers_every_parser`](backend/tests/test_registry_bootstrap.py:53).

**A statically-mapped technique had been retired.** `cloud_logging_disabled` pointed at
`T1562.008`, which ATT&CK v19.0 revoked along with the entire `T1562 Impair Defenses`
family in favour of `T1685`. The mapping still looked correct in the source; at runtime
it resolved to `None`, contributed no tactic, and silently under-escalated every
incident containing it. Caught by
[`test_every_rule_technique_resolves`](backend/tests/test_attack_catalog.py:246).

### What is not measured

There is **no false-positive rate and no performance benchmark here**, because neither
is honestly measurable yet. A false-positive rate requires a labeled corpus — real logs
with an analyst's ground truth attached — and this project has two synthetic sample
files written to exercise specific code paths. A rate computed against fixtures
authored to produce known output would measure the fixtures. Likewise, throughput
numbers taken against a 43-event SQLite database would say nothing about the Postgres
deployment the pipeline is designed for.

What *is* measurable and stated elsewhere: parse statistics per file — lines read,
events emitted, lines skipped, duplicates skipped, in [Quick start](#quick-start) — and
verbatim end-to-end output over the sample logs, in
[What it produces](#what-it-produces).

## Safety controls

The pipeline treats a language model as an untrusted component that is useful anyway.
Each control below answers a specific way that assumption gets violated. The structure
is drawn in [ARCHITECTURE.md](ARCHITECTURE.md#the-ai-boundary); the reasoning behind
each is decision 15 in [CLAUDE.md](CLAUDE.md).

**No self-reported confidence is ever read.** Asking a model how sure it is produces a
fluent number roughly uncorrelated with correctness, and highest exactly when the model
is confidently wrong — the case a gate exists to catch. A threshold over that number
therefore admits the worst output most reliably. `confidence` sits in
`FORBIDDEN_FIELDS` alongside `severity`, `priority` and `risk_score`: its presence is
itself a failure, not a value to weigh
([test](backend/tests/test_enrichment_validation.py:145)).

**Validation is structural instead.** Every check is against something verifiable
outside the model: does the output parse, do its technique IDs resolve in the catalog,
does every event it cites exist in this incident's evidence, did it stay inside the
allowed fields and length limits, is the playbook ID even shaped like a lookup key.
Evidence grounding is the load-bearing one — catalog validation catches a technique that
does not exist, but only grounding catches a fluent sentence resting on a log line that
was never there.

**Candidate shortlists convert technique mapping from generation to selection.** Catalog
validation cannot catch a real-but-wrong ID: T1078 Valid Accounts exists, is current,
resolves cleanly, and is simply not what the evidence shows. So the prompt offers at
most eight candidates drawn breadth-first across the incident's event categories, with
"none of these" as a listed choice. The enforcement is the load-bearing half:
`validate()` takes `allowed_techniques` and `enrich()` passes it the same shortlist it
just rendered into the prompt — one derivation, `shortlist_for()`, feeding both, so the
list shown and the list checked cannot diverge. Without that parameter the constraint is
advice in a prompt, and a model ignoring it is indistinguishable from one obeying it
([test](backend/tests/test_enrichment_validation.py:260)).

**Any failure discards the entire payload**, not the offending field. Partial acceptance
ships prose whose support was removed for being wrong, and it reads exactly as confident
as prose that was right. All failures are still reported rather than short-circuited at
the first, because an operator debugging a prompt needs the whole list
([test](backend/tests/test_enrichment_validation.py:513)).

**Retry is selective.** Formatting failures — unparseable, wrong shape, wrong type,
unknown field — retry once with the rejection fed back. Content failures never retry. An
ungrounded citation means the model invented a detail, and re-asking invites a
better-disguised invention. An off-list technique is the same class, not a typo: the
list was in the prompt and the model went around it.

**The deterministic summary is the floor, and it is complete on its own.**
`app/enrichment/summary.py` was written and tested before any prompt existed, and it is
what ships whenever the LLM is unavailable, slow, or rejected. Enrichment is off by
default (`SOC_ENRICHMENT_ENABLED`), so a fresh clone with no API key produces complete
incidents rather than empty ones. Every path returns an `Enrichment` with the reason
recorded, and the API reports `enrichment_source` so a reader can tell which produced
what ([test](backend/tests/test_enrichment_validation.py:556)).

**Log content is untrusted input, and is framed rather than filtered.** Evidence is
wrapped in `<evidence>` delimiters behind a standing instruction that the contents are
data, and the system prompt says an injection attempt should be reported as an
observation rather than obeyed. Injected text passes through verbatim
([test](backend/tests/test_enrichment_validation.py:632)) — filtering cannot enumerate
how an instruction can be phrased, and a stripped line is evidence the analyst no longer
sees, which would let an attacker delete their own tracks by writing something that
trips the filter.

One structural exception, which is not filtering: newlines inside a raw record are
flattened to spaces. A multi-line CloudTrail record could otherwise carry a
`</evidence>` line of its own and push the rest of its content outside the framing.
Flattening removes the forged *delimiter* while preserving every character of the
content — the literal text still appears inline, where it is inert
([test](backend/tests/test_enrichment_validation.py:658)).

**ATT&CK IDs are validated against a committed catalog.**
`backend/data/attack_catalog.json` is built from the `ATT&CK-v19.1` release tag — 858
techniques, of which 697 are active and 161 deprecated — pinned by both the tag and the
40-character commit SHA, and read offline. The validator rejects unknown and deprecated
IDs identically, because both mean "attribute no tactic". Candidate shortlists are
checked against the catalog at import, so an ATT&CK release that retires one fails the
build rather than quietly offering the model a dead ID it would be *right* to pick given
the list it was shown ([test](backend/tests/test_attack_catalog.py:56)).

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

**Backend.** FastAPI, SQLAlchemy 2.0, Postgres (SQLite for local development), pytest.

**Frontend.** Vite, React 19, TypeScript and Tailwind v4, with react-router for two
views: the incident queue at `/` and the detail view at `/incidents/:incidentId`. The
queue filters by severity server-side and searches entity keys, rule IDs and tactics on
the client; the detail view centres on the timeline, which distinguishes host from
cloud activity on three redundant channels so a greyscale render still reads.

Types are not hand-written. `frontend/src/api/schema.ts` is generated from the FastAPI
OpenAPI document by `backend/scripts/generate_frontend_types.py`, and
[`test_generated_types_are_current`](backend/tests/test_frontend_types.py:22) fails if
the checked-in file has drifted from the response models — a renamed Pydantic field
would otherwise reach the browser as a silent `undefined`. That check runs in the
pytest suite; there is no CI pipeline in this repo yet, so it is only enforced when
someone runs the tests.

```bash
cd frontend && npm install && npm run dev    # expects the backend on :8000
```
