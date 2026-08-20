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

   Validation alone is not enough, because a *valid* proposed technique would
   still be dangerous: severity counts distinct tactics (decision 14), so a
   model-supplied technique reaching the tactic set escalates the incident —
   the LLM re-scoring without ever writing a score, and decision 1 broken
   indirectly. Proposals therefore live in `Finding.proposed_technique`, and
   `correlate()` reads `Finding.technique` only. Displayed and enriched from,
   never counted.

   The validator rejects unknown *and* deprecated IDs identically, because
   both mean "attribute no tactic". This is not theoretical: ATT&CK retired
   the entire `T1562 Impair Defenses` family in favour of `T1685`, and the
   `cloud_logging_disabled` rule was still statically mapped to `T1562.008`.
   A stale mapping looks correct in the source and silently under-escalates
   every incident containing it, so `test_attack_catalog.py` asserts every
   registered rule's technique still resolves and still yields a tactic.

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
    overlapping findings under `ip:`, `user:`, and `host:` — nested slices of
    one attack rather than exact copies, since each group is scoped to its own
    entity. Collapsing those (same rule, evidence contained in a broader copy,
    most specific key wins) is correlation's job, not the engine's.

13. **Detection runs over persisted events, never over parser output.**
    Dedup is part of the semantics: two sshd lines describing one connection
    attempt share a `dedup_hash` and collapse to one row. Any tool that runs
    rules over freshly parsed events will double-count and disagree with
    production.

14. **Correlation is connected components over evidence keys within a time
    gap.** One mechanism, not three. Findings join when they share any entity
    key their *evidence* touches — not merely the key they were filed under —
    and a silence longer than `max_gap` breaks the chain. Fan-out collapse
    (decision 12) and cross-source chaining fall out of the same union-find
    pass; special-casing them would be two algorithms disagreeing at the edges.
    Joining is transitive, so an incident can span entities that never appear
    together in one event.

    **Noise is measured by co-occurrence breadth, never frequency.** A key
    seen alongside more than `MAX_COOCCURRING_KEYS` distinct other entities is
    ambient and is excluded from joining. Frequency is the intuitive metric and
    is exactly wrong: in any batch dominated by one intrusion the attacker's IP
    is the most frequent key, so a frequency threshold suppresses the key that
    should do the joining. Breadth splits the cases correctly — `user:root`
    across forty hosts is ambient, `ip:203.0.113.5` across one host and one
    account is identifying however often it appears. Suppressed keys are still
    recorded on the incident: not joining on a key is not the same as
    discarding it. `MAX_COOCCURRING_KEYS = 12` is an unvalidated guess and the
    first knob to turn against real data.

    **Severity comes from distinct ATT&CK tactic breadth, not finding count.**
    One step up at three distinct tactics, two at five, over the highest
    finding severity. Summing would let the decision-12 fan-out inflate an
    incident by counting the same burst three times; taking the max alone would
    rank a full kill chain level with its loudest step. Twenty brute-force
    findings are one tactic and one story; brute force → persistence → defense
    evasion is three and a real intrusion.

    The ladder is deliberately slower than one step per tactic. Two tactics is
    the ordinary shape of a real intrusion — credential access into persistence
    covers most of them — so if two reached the top rung nearly every genuine
    incident would be CRITICAL and the label would stop discriminating.
    Escalation has to be rare to mean anything.

    **A technique contributes all of its tactics, and multi-mapping is the
    known weakness.** Breadth works as a severity proxy only while tactics are
    roughly independent, and ATT&CK maps many techniques to several — T1098
    Account Manipulation covers persistence and privilege-escalation, and 53
    other techniques carry *exactly* that pair and nothing else (54 including
    T1098 itself; 65 if you count every technique carrying both tactics among
    others, such as T1078). The strict count is the one quoted here, because
    those are the techniques that behave identically to T1098 for severity
    purposes. So one technique can move an
    incident two-fifths of the way up the ladder, and two rules can reach the
    three-tactic rung where three would otherwise be needed. Counting one
    tactic per technique was rejected as worse: it undercounts genuine breadth
    and picks arbitrarily which tactic to honour. What keeps this tolerable is
    that the rung sits at three, so no single technique can escalate alone.
    The v19 Defense Evasion split is the case to watch — it moved techniques
    into `stealth` and `defense-impairment`, and nothing lands in both today;
    a release that starts dual-mapping across that pair would escalate the
    defence-related rules a rung without detecting anything new.

    **Collapse plus busiest-source labelling means a multi-source rule always
    renders as its host half.** Two mechanisms compose into a constraint that
    is invisible in either one alone. `_collapse_fanout` keeps the *widest*
    evidence set per `rule_id` and drops the copies contained in it; the API's
    `_finding_source` then labels a finding by whichever source contributed
    most of its evidence. So when one attacker touches two sources under a
    shared key (decision 12's fan-out), the `ip:`-scoped copy of a rule
    subsumes the `principal:`-scoped cloud-only copy, and the survivor is
    labelled `syslog_sshd` because sshd is chattier per unit of activity.

    The consequence: **only naturally single-source rules can produce a
    cloud-labelled row.** `admin_policy_attached` and `cloud_logging_disabled`
    are cloud-only by construction and always show as cloud;
    `brute_force_auth`, `brute_force_success` and
    `access_key_after_suspicious_auth` span both and always show as host,
    however much CloudTrail evidence they rest on.

    This is a **display consequence, not a correlation bug**. The evidence is
    intact and the incident is right — `sources` on the incident reports both
    sources with honest per-source counts, and the finding's own evidence list
    carries every line. What is lossy is the single-valued `source_type` on a
    timeline row, which cannot describe a finding that genuinely spans sources.

    It shapes what sample data can demonstrate, which is the practical bite.
    A UI that distinguishes host from cloud activity per timeline row can only
    show alternation where the alternating findings are single-source, so
    `sample_logs/` has to stage the intrusion around the cloud-only rules
    rather than simply narrating a host-to-cloud escalation. Worth
    remembering before reading a timeline as evidence that correlation is
    mis-grouping: it is the label that is coarse, not the grouping. If a row
    ever needs to say "both", the fix is a multi-valued source on
    `TimelineEntry`, not a change to `_collapse_fanout`.

15. **Enrichment never reads a self-reported confidence score.** Asking a model
    how sure it is produces a fluent number that is roughly uncorrelated with
    correctness, and is highest exactly when the model is confidently wrong —
    the case a gate exists to catch. A threshold over that number therefore
    admits the worst output most reliably. `confidence` is in
    `FORBIDDEN_FIELDS` alongside `severity`: its presence is itself a failure,
    not a value to weigh.

    **Validation is structural instead.** Every check is against something
    verifiable outside the model: does the output parse, do its technique IDs
    resolve in the ATT&CK catalog (decision 8), does every event it cites
    exist in this incident's evidence, did it stay inside the allowed fields
    and the length limits. Evidence grounding is the load-bearing one —
    catalog validation catches a technique that does not exist, but only
    grounding catches a fluent sentence resting on a log line that was never
    there.

    **Any failure discards the entire payload.** Not the offending field —
    the payload. Partial acceptance ships prose whose support was removed for
    being wrong, and it reads exactly as confident as prose that was right.
    All failures are still *reported* rather than short-circuited at the
    first, because an operator debugging a prompt needs the whole list.

    **The deterministic summary is the floor and must be complete on its
    own.** `app/enrichment/summary.py` is written and tested before any prompt
    exists, and it is what ships whenever the LLM is unavailable, slow, or
    rejected. If it were a stub, an LLM outage would not degrade output — it
    would break the pipeline, and "rules detect, AI explains" would be a claim
    the architecture could not honour. It is deliberately factual rather than
    interpretive: what fired, when, against what, in what order. Interpretation
    is what the LLM adds; an invented narrative is worse than none.

    **Candidate shortlists convert technique mapping from generation to
    selection.** Catalog validation cannot catch a real-but-wrong ID: T1078
    Valid Accounts exists, is current, resolves cleanly, and is simply not
    what the evidence shows. Asking "which ATT&CK technique describes this?"
    is open generation and the only reachable check is existence. Asking
    "which of these six, or none?" bounds the wrong answers, makes "none" a
    listed choice rather than something the model must resist producing, and
    makes a selection outside the list a validation failure in its own right
    (`off_list_technique`).

    The enforcement is the load-bearing half. `validate()` takes
    `allowed_techniques` and `enrich()` passes the shortlist it just rendered
    into the prompt — one derivation, `shortlist_for()`, feeding both, so the
    list shown and the list checked cannot diverge. Without that parameter the
    constraint is advice in a prompt, and a model ignoring it is
    indistinguishable from one obeying it.

    Shortlists are keyed by event category, bounded at eight, and drawn
    breadth-first across the categories present — a cross-source incident
    (decision 14) would otherwise spend every slot on its noisiest category
    and offer no candidate for the finding that matters. Candidates are
    validated against the catalog at import, so an ATT&CK release that retires
    one fails the build rather than quietly offering the model a dead ID that
    it would be *right* to pick given the list it was shown.

    **Retry is selective.** Formatting failures — unparseable, wrong shape,
    wrong type, unknown field — retry once with the rejection fed back. Content
    failures never retry: an ungrounded citation means the model invented a
    detail, and re-asking invites a better-disguised invention rather than a
    correction. An off-list technique is the same class, not a typo — the list
    was in the prompt and the model went around it, so a second ask most likely
    yields a different real technique that is also wrong. A forbidden field is
    a boundary violation, and asking again only teaches it to score more
    plausibly.

    **Untrusted evidence is framed, never filtered** (decision 10). Injected
    instruction-like text in a log line is passed through verbatim inside the
    delimiters. Filtering would fail twice: it cannot enumerate how an
    instruction can be phrased, and a stripped line is evidence the analyst no
    longer sees — an attacker would delete their own tracks by writing
    something that trips the filter. Truncation exists to bound prompt
    occupancy, not to sanitize.

16. **Incidents are computed on read, and their IDs are derived from content.**
    There is no incidents table. `GET /api/incidents` and
    `GET /api/incidents/{id}` run `events -> run_rules -> correlate` per
    request, so the queue cannot disagree with the rules in the tree — a
    stored incident from before a threshold change would sit next to a fresh
    one with nothing in the response distinguishing them.

    That forces the ID question. `INC-0001` was assigned by enumeration order,
    which is a property of the run rather than of the incident: any later
    ingest that reordered the connected components renamed every incident, and
    a detail URL an analyst saved pointed at somebody else's intrusion.
    `incident_id_for()` hashes the sorted **set** of evidence dedup hashes, so
    the ID is order-independent, stable across machines and databases, and
    unchanged by the fan-out copies correlation collapses (their evidence is
    contained in what survives, so the union is the same either side of the
    collapse).

    Two known edges. The ID names evidence, not rules, so two incidents over an
    identical evidence set would collide — unreachable today, since findings
    sharing evidence share entity keys and would have joined. And
    `Event.to_normalized()` does not restore `source_event_id` (see decision
    11), so a round-tripped event recomputes a coarser hash than the stored
    column: same-second siblings fold together, shrinking the hashed set
    without destabilising it. That coarser hash is the one `_collapse_fanout`
    and evidence grounding already use, so all three agree with each other.

    Recomputing per request means replaying detection over every persisted
    event on every call. Fine at sample-log scale; it is the first thing that
    breaks under real volume, and the fix is a cache keyed on the event set
    rather than a stored incident.

17. **A tenant is not a machine: `account:`, not `host:`.** CloudTrail's
    `recipientAccountId` was mapped to `host`, which was an open question from
    the ingest design and became visible the moment the API rendered entity
    keys — `host:123456789012` is an asset identifier for something that has
    no asset behind it. `NormalizedEvent.account` is now its own field and its
    own namespace, cloud records carry no `host` at all, and `account:` sits
    just below `principal:` in `_KEY_PRECEDENCE`: it names the tenant an actor
    operated in, so it is worth pivoting on only when no principal named the
    actor, and still beats an address that names a source but not what was
    reached. Grouping is unaffected — the key that gathered every CloudTrail
    event under one bucket changed its prefix, not its cardinality.

    `account` is in `dedup_hash`, which broke the pin in
    `test_dedup_hash_is_stable_across_releases` knowingly: cloud hashes were
    changing anyway now that `host` no longer carries the account, and one
    unconditional definition of identity beats a per-source one. Free only
    while the schema is on `create_all` with no data worth keeping.

18. **Timeline order is by `last_seen`, and an entry is a span.** A sequence
    rule's evidence begins at its first *leading* event, so `brute_force_success`
    and the `brute_force_auth` burst it is built on start at the same instant.
    Ordering by start time therefore printed the effect above its cause. End
    time is the field that distinguishes a burst from the longer chain
    containing it. Both the API timeline and the deterministic summary sort
    this way — they ship in the same response, and two orderings inside one
    payload is a defect an analyst has to reconcile by hand.

## Open questions

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
4. Correlation — group incidents by entity key + time window ✅
5. ATT&CK mapping with catalog validation ✅ (catalog + validator; LLM
   proposal path deliberately not built yet)
6. LLM enrichment + structurally-validated fallback 🚧 (deterministic summary,
   validation gate, evidence framing, candidate shortlists, prompt and
   orchestration done — `enrich()` is off by default and fully exercised
   through a fake client. Only the provider client behind the `LLMClient`
   Protocol is left. Not "confidence-gated" — see decision 15)
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
