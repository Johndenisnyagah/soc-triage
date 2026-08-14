# SOC Triage — frontend design spec

The authoritative record of what the frontend actually looks like. Values here
are transcribed from the shipped implementation, not from intent — every colour,
size and width below is either a token in `src/index.css` under `@theme` or a
value measured off the running app.

**Status.** Both views are built: the queue (`/`) and incident detail
(`/incidents/:incidentId`).

**On the palette:** this spec has always been light — warm off-white paper,
hairline rules, single orange accent. Nothing was translated from a dark theme.
What did change is the severity ramp, which is rebuilt below and is the one
colour decision in this document with hard acceptance criteria.

Mockups live in `screens/`. They were drawn before the read API existed and show
data the backend does not model; see *Divergences* at the end.

## Direction

Light, utilitarian, editorial. Warm off-white paper, hairline rules instead of
heavy cards, monospace for anything machine-generated (IDs, entity keys,
timestamps, technique IDs, counts, log lines) and a humanist sans for anything a
person wrote (titles, labels, prose). Single orange accent, used only for
selected/active state and for entity + technique references. No gradients, no
coloured surfaces beyond the accent tint and the severity chips.

## Type

Both families are loaded from Google Fonts in `index.html`, with a system
fallback stack so the layout survives an offline load.

```
--font-sans: "Instrument Sans", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif
--font-mono: "JetBrains Mono", ui-monospace, "SFMono-Regular", "Cascadia Mono", Consolas, monospace
```

`Instrument Sans` 400/500/600 · `JetBrains Mono` 400/500.

| Token | Size | Line height | Tracking | Used for |
| --- | --- | --- | --- | --- |
| `text-label` | 10px | 1.2 | 0.1em | Mono section + column headers, uppercase, `--color-ink-faintest` |
| `text-meta` | 11.5px | 1.35 | — | Secondary row values: tactics, sources, window, span |
| `text-body` | 12.5px | 1.45 | — | Primary row values: incident id, entity, counts |
| `text-prose` | 12.5px | 1.6 | — | Paragraph copy (summary, empty/error states) |
| `text-h-detail` | 21px | 1.15 | −0.01em | Detail heading |
| `text-h-ledger` | 30px | 1.1 | −0.02em | Ledger heading |
| `text-stat` | 24px | 1.1 | — | Mono stat value |
| `text-score` | 18px | 1.1 | — | Severity score |

Mono numerals are `tabular-nums` globally, so counts and timestamps do not
reflow between renders.

## Color

| Role | Token | Hex |
| --- | --- | --- |
| Desk background | `desk` | `#EFEEEB` (hatch `#EAE8E4`, 135°, 1px on 9px) |
| Panel / page | `panel` | `#FCFBFA` |
| Surface raised (rows on hover, inputs) | `raised` | `#FFFFFF` |
| Surface sunken | `sunken` / `sunken-deep` | `#F7F5F3` / `#F5F3F0` |
| Rail & toolbar | `rail` | `#F7F5F3` |
| Queue column | `queue` | `#F9F8F6` |
| Border strong | `edge` | `#E2DFDA` |
| Hairlines | `hair-1` … `hair-4` | `#EAE7E2` · `#EDEAE5` · `#F0EDE8` · `#F4F1EC` |
| Ink | `ink` | `#1A1A18` |
| Ink secondary | `ink-2` | `#4A4843` |
| Ink muted | `ink-muted` | `#6B6862` |
| Ink faint | `ink-faint` | `#8A8781` |
| Ink faintest | `ink-faintest` | `#A8A49D` |
| Accent | `accent` | `#E0620D` (hover `#C4520A`, link hover `#B84B06`) |
| Accent tint | `accent-tint` / `accent-hair` | `#FBEDE1` / `#F2CBAB` |
| Positive delta | `positive` | `#2F7D53` |

Row dividers are `hair-4`; the header rule under a section title is `edge`.

## Severity ramp

Severity is the primary scanning dimension of the queue, so it is the one place
in this design where colour carries information rather than decoration.

**The ramp spans temperature as well as value.** Red → orange → yellow → **blue**
→ neutral. The cold rung at LOW is load-bearing: an all-warm ramp puts MEDIUM,
LOW and INFO within a few degrees of hue and they collapse into a single
warm-neutral smear — precisely on the three levels an analyst most needs to
separate at a glance.

**Fills are explicit colours, never the ink at low opacity.** Tinting one hue
family at 8–10% is what produced the smear in the first place.

| Level | Ink | Fill |
| --- | --- | --- |
| CRITICAL | `#A61B1B` | `#FBE3E1` |
| HIGH | `#8A4B08` | `#FBEBDA` |
| MEDIUM | `#7A5C00` | `#FAF0CE` |
| LOW | `#0A4A8F` | `#DCE9F8` |
| INFO | `#5A5A55` | `#EAE9E5` |

Severity is expressed as chip text colour on a tinted chip — **never as a filled
row**. A row-level fill turns the queue into stripes and destroys the vertical
scan down the entity column.

### Acceptance criteria

Any change to these ten values must re-clear all three checks:

1. **Chip text on its own fill ≥ 4.5:1** (WCAG AA, normal text).
   Measured: CRITICAL 6.15 · HIGH 5.82 · MEDIUM 5.48 · LOW 7.14 · INFO 5.71.
2. **No two adjacent rungs merge** — ΔE > 3 between neighbouring fills.
   Measured: 8.32 · 8.88 · 26.57 · 10.85. No pair anywhere in the ramp is
   within ΔE 6.
3. **Every chip is visible against the panel** — ΔE > 5 vs `#FCFBFA`.
   Measured: 10.69 · 11.01 · 17.64 · 11.68 · 6.53 (INFO is deliberately the
   quietest).

The informal version: squint at a column containing all five levels; no two
adjacent rungs may merge.

## Geometry and spacing

Spacing follows a **4px scale** (Tailwind's default step); the only half-step in
use is the 14px queue column gap.

Radii: `window` 14px · `card` 11px · `sunken` 9px · `control` 8px · `pill` 6px ·
`chip` 4px.

| Element | Shipped |
| --- | --- |
| Icon rail width | 54px |
| Window toolbar height | 38px |
| Section header row | 34px |
| Queue row height | **36px** |
| Severity filter pill | 22px |
| Search input | 26px |
| Page padding | 24px 40px 40px |
| Content ceiling | 1400px |
| Queue column gap | 14px |

Page padding is 24px at the top rather than the 26px originally specced — it
snaps to the 4px scale, and an off-scale value is not worth one pixel.

## Queue view — shipped

Full-width dense table, one row per correlated incident. Not the mockup's 274px
column: the app has two routes and the queue owns its own, so it takes the width.

Grid template — every fixed column is sized to its own worst case so the flexible
entity column takes the remainder:

```
68px  100px  minmax(0,1fr)  62px  178px  166px  110px  62px
```

| Column | Content | Treatment |
| --- | --- | --- |
| SEV | Severity chip | Mono 10px, ramp above |
| INCIDENT | `incident_id` | Mono, accent on row hover |
| PRIMARY ENTITY | `primary_entity` | Mono, `ink`, `title` carries the full value |
| FINDINGS | `finding_count` | Mono, right-aligned, bare number |
| TACTICS | count + short labels | Faint count, then ≤2 abbreviated tactics + `+n` |
| SOURCES | per-source event counts | Mono, `sshd 21 · cloudtrail 10` |
| WINDOW · UTC | `first_seen → last_seen` | Mono, right-aligned, `04:41 → 04:59` |
| SPAN | duration | Mono, right-aligned, `18m 13s` |

Four rules this table learned the hard way:

- **Entity keys are not underlined.** The whole row is the link to the incident;
  underlining the entity advertises a second destination that does not exist.
  Mono against surrounding sans already marks it as a literal value.
- **Window and span are separate columns.** They are two different facts — when
  it happened, and how long it ran. Jammed together they read as one run-on
  string and neither aligns down the queue.
- **Tactics are abbreviated, not truncated.** Full names overflow and clip
  mid-word, which says less than the count already next to them.
  `cred-access · defense-imp +3` fits; the unabbreviated list is on `title`. The
  vocabulary is closed (15 tactics), so all 15 are mapped explicitly in
  `src/lib/tactics.ts` rather than abbreviated at runtime.
- **Findings count is bare, tactic count is faint.** Right-aligned findings sits
  immediately left of the tactics cell, and two equally weighted digits an em
  apart read as one two-digit number.

Long IAM role ARNs (~50 mono characters) fit at the 1400px ceiling. Anything
longer clips with `title` as the fallback.

**Header:** `QUEUE` label, accent-tinted count chip, then severity filter pills
right-aligned — `ALL` plus all five levels the API accepts. Active pill is ink
fill (`#1A1A18`) with white text. Showing only CRIT/HIGH/MED, as the mockup does,
would make LOW and INFO incidents unreachable by filter.

**Footer:** states the active filters, not just a count —
`3 OF 12 INCIDENTS · SEVERITY HIGH · MATCHING "sshd" · ORDERED BY SEVERITY`.
With a small queue, a search that removes nothing is otherwise
indistinguishable from a search that did nothing.

**Ordering** is the API's own (worst-first from `correlate()`) and is never
re-sorted client-side.

### States

| State | Reads as |
| --- | --- |
| Loading | Skeleton rows at full row height, so the page does not jump |
| Error | `ERROR · <status>` + the backend's own message + *Try again* |
| Empty pipeline | `NO INCIDENTS` + how to ingest a log file |
| Filter excludes all | `NO MATCHES` + *Nothing matches that filter.* + *Clear filters* |

The last two are deliberately different. An empty queue is a *good* outcome and
must never read as a broken page; a filter dead-end is something the user can
undo.

### Search

Client-side over already-fetched rows, and it **composes** with the severity
pills rather than replacing them — the pill narrows the fetch server-side, the
needle narrows what came back.

Matches on `incident_id`, `primary_entity`, `severity`, **`entity_keys`**,
**`rule_ids`**, tactics (full and abbreviated) and source types (full and
abbreviated).

Matching deliberately reaches past what the row displays. `IncidentSummary`
carries `entity_keys` and `rule_ids` for exactly this reason: an analyst
pivoting on an address that appears in an incident's evidence but did not win
`_KEY_PRECEDENCE` would otherwise get no hit, and the queue would look empty on
an entity it is in fact reporting.

## Incident detail — shipped

Two columns at roughly **65/35**, `minmax(0,1.85fr) minmax(0,1fr)`, 34px gutter.
Ratio units rather than a fixed sidebar width, so the split holds below the
1400px ceiling instead of the left column absorbing every pixel lost.

**Header:** severity chip · incident id (mono, `text-h-detail`) · score, then a
four-up mono metadata row — primary entity, window in the full form
`02 Aug 2026 · 04:41:07 → 04:56:02 UTC`, span, and detections.

### Left column — the argument

**Summary panel**, bordered, carrying a provenance label driven by
`enrichment_source`. The two states are styled to be told apart without reading:

| `enrichment_source` | Label |
| --- | --- |
| `deterministic` | Muted grey on `sunken` — *generated without LLM — deterministic* |
| `llm` | Accent-tinted — *LLM-generated — structurally validated* |
| anything else | Neutral outline naming the raw value |

An unrecognised value falls into the third state rather than defaulting to the
reassuring one. The claim "rules detect, AI explains" is only checkable by a
reader if the difference is visible on the page.

Summary text renders `whitespace-pre-wrap`: the deterministic summary carries an
indented timeline block whose alignment is load-bearing.

**Timeline** — the centrepiece. One row per finding, in API order (`last_seen`,
decision 18). Each row is a grid:

```
14px marker | 176px duration track | title + meta | evidence count | expander
```

The duration bar is positioned *and* sized against the incident's whole window,
so a row's horizontal offset is when it happened and its length is how long it
ran. Findings differ enormously in span — a 22-second burst next to a 14-minute
chain — and as text those are the same width. Bars with a `MIN_BAR_PERCENT`
floor of 2.5 keep single-instant findings from rendering as empty track.

Rows expand to a sunken mono block of raw evidence lines, verbatim. Attacker-
controlled text is framed, never filtered (decision 10); `pre` means nothing in
it is interpreted.

### Source distinction — three redundant channels

The timeline's job beyond listing findings is to show that one chronology was
assembled from several sources. That has to survive greyscale, colour-blindness
and a compressed README screenshot, so it is carried three times over:

1. a **3px stripe** down the row's leading edge;
2. a **rail marker** whose *shape* differs — square = host, circle = cloud,
   hollow ring = unclassified;
3. the mono source name in the meta line.

The axis is **host vs cloud control plane**, not parser identity
(`src/lib/sources.ts`). Keyed that way, the planned Windows Security parser
joins the host lane rather than demanding a third treatment — two marks stay two
marks and the weave keeps reading.

This is the one **documented extension of the accent** beyond selected-state and
entity/technique references: `--color-accent` marks cloud-plane findings. It is
deliberate. Severity lives in a different column, so the two colour languages do
not collide.

### Right column — the evidence index

Compact stacked panels, no charts: ATT&CK tactics as tags · techniques (mono
accent id, sans name, tactics beneath) · sources with per-source counts and a
total · entity keys.

Entity keys are deliberately **unbounded and un-truncated**, wrapping with
`break-all`. A full IAM ARN is long precisely because the tail identifies it;
clipping would remove the useful half. The list is allowed to run.

Nothing here is a trend and nothing has a baseline, so a chart would be
decoration standing where a fact belongs.

### States

Loading renders skeleton rows. Error surfaces the backend's own message — for an
unknown id that is the explanation that incidents are recomputed from stored
events, so an id stops resolving when its evidence is gone. Never a blank pane.

### Known redundancy

The deterministic summary contains its own text timeline, which restates the
rows rendered below it. That duplication is in the API payload, not in this
view, and trimming it here would misrepresent what `summarize()` produced.

## Behavior

- Severity pills filter server-side via `?severity=`; search filters client-side
  and composes with them.
- Row click opens the incident. Deep links work; an unknown id shows the
  backend's own explanation rather than a blank pane.
- Nothing is animated. Hover states are colour and border only.

## Content rules

- Technique references use real MITRE ATT&CK ids. Note the catalog is on v19:
  log tampering resolves as `T1685.002`, not the retired `T1562.008`.
- Copy is factual and lowercase-technical in mono contexts, sentence case in
  prose. No exclamation, no vendor voice.
- **All timestamps render in UTC**, never the viewer's locale — the logs are UTC
  and the summary says UTC, and two clocks in one workflow is a 3am bug.

## Divergences from the mockups

The mockups predate the read API and show data the backend does not model.
Rather than fabricate it, the implementation omits it:

| Mockup element | Why absent |
| --- | --- |
| `INC-0001` sequential ids | Real ids are content hashes (`INC-fe9ac9b7`); positional ids were removed deliberately (decision 16) |
| Row snippet, `OPEN` / `ASSIGN`, `2 NEW`, `TRIAGE ALL` | No assignment, read state or workflow actions exist; the prose summary is detail-only |
| Stat-card sparklines and deltas (`+12`, `−4m`) | No time series, no baseline to compare against |
| Analysts on shift, containment %, response tasks | Not modelled anywhere in the backend |
| Notes, audit log, `Export` / `Escalate` | Same |
| `Severity score 92 / 100` | `severity_score` is the ladder's integer (90 = CRITICAL), not a 0–100 score |
| `RETENTION 30D` | A data-retention claim the app cannot back |
| Four extra icon-rail buttons | The app has one destination; a button that does nothing is worse than an empty rail |
