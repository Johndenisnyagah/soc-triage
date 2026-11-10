# SOC Triage — frontend design spec

The authoritative record of what the frontend actually looks like. Values here
are transcribed from the shipped implementation, not from intent — every colour,
size and width below is either a token in `src/index.css` under `@theme` or a
value measured off the running app (1440 × 900 viewport, Chromium).

**Status.** Three views are built: the queue (`/`), incident detail
(`/incidents/:incidentId`) and ingest (`/ingest`).

**On the palette:** the frontend shipped first on a warm light theme and moved
to the LogLens AI design language in the migration specced in
`docs/UI-MIGRATION.md`: LogLens's dark blue-grey surfaces, Inter, square
geometry, its collapsible rail and its page rhythm. It adopts LogLens's
*visual system*, not its feature set — no workflow states, notifications,
confidence meters or audit log, because the backend models none of them. The
severity ramp is soc-triage's own, recomputed for the dark panel, and is still
the one colour decision here with hard acceptance criteria. The light ramp is
kept below (*Light mode*) rather than deleted.

Mockups live in `screens/`. They were drawn before the read API existed, on the
original light theme, and show data the backend does not model; see
*Divergences* at the end. They are design history, not screenshots — the
shipped app is shown in `docs/screenshots/`.

## Direction

Dark, utilitarian, dense. Blue-grey surfaces stepping darker for insets, soft
rules instead of heavy cards, square corners everywhere, monospace for anything
machine-generated (IDs, entity keys, timestamps, technique IDs, counts, log
lines) and a humanist sans for anything a person wrote (titles, labels, prose).
Single indigo accent, used for selected/active state, primary actions, and
entity + technique references. No gradients, no coloured surfaces beyond the
accent wash, the status edges and the severity chips.

## Type

Both families are loaded from Google Fonts in `index.html`, with a system
fallback stack so the layout survives an offline load.

```
--font-sans: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif
--font-mono: "JetBrains Mono", ui-monospace, "SFMono-Regular", "Cascadia Mono", Consolas, monospace
```

`Inter` 300–700 · `JetBrains Mono` 400/500. Body sets
`font-feature-settings: "ss01", "cv11"` (LogLens's alternates).

The dense data scale is unchanged from the light theme — density is the one
thing both designs agreed on:

| Token | Size | Line height | Tracking | Used for |
| --- | --- | --- | --- | --- |
| `text-label` | 10px | 1.2 | 0.1em | Mono column headers and inline labels, uppercase |
| `text-meta` | 11.5px | 1.35 | — | Secondary row values: tactics, sources, window, span |
| `text-body` | 12.5px | 1.45 | — | Primary row values: incident id, entity, counts |
| `text-prose` | 12.5px | 1.6 | — | Paragraph copy (summary, empty/error states) |
| `text-stat` | 24px | 1.1 | — | Mono stat value (ingest funnel, severity score) |

LogLens's structural type is adopted for view chrome only:

| Token | Size | Line height | Tracking | Used for |
| --- | --- | --- | --- | --- |
| `text-eyebrow` | 10px | 1.2 | 0.18em | PageHead eyebrow, 500, uppercase |
| `text-h-page` | 32px | 1.1 | −0.02em | PageHead title, 600 |
| `text-subtitle` | 13px | 1.5 | — | PageHead subtitle, rail labels |
| `text-section` | 11px | 1.2 | 0.16em | SectionTitle, 500, uppercase |
| `text-btn` | 11px | 1.2 | 0.12em | Buttons, 600, uppercase |
| `text-chip` | 10px | 1.2 | 0.14em | Severity chip, 700, uppercase |
| `text-evidence` | 11px | 1.65 | — | Raw evidence and parse-error excerpts |

`text-h-detail`, `text-h-ledger` and `text-score` remain as tokens; nothing
currently renders them.

Mono numerals are `tabular-nums` globally, so counts and timestamps do not
reflow between renders.

## Color

| Role | Token | Value |
| --- | --- | --- |
| App background, insets | `bg-app` | `#1A1F29` |
| Panel | `panel` | `#232A36` |
| Inset inside a panel (tags, hover) | `card` | `#2A313E` |
| Rail & toolbar | `rail` | `#161A23` |
| Border | `line` | `#323A49` |
| Divider, row rule | `line-soft` | `#2A313E` |
| Ink | `text` | `#E6E8EC` |
| Ink secondary | `text-mid` | `#B5BAC4` |
| Ink dim | `text-dim` | `#6B7283` |
| Ink faint | `text-faint` | `#4A5160` |
| Accent (fill) | `accent` | `#4B6CF6` (hover `#5B7BFF`) |
| Accent (text) | `accent-ink` | `#8299FF` |
| On accent | `on-accent` | `#FFFFFF` |
| Accent tint / wash / hair | `accent-tint` / `accent-wash` / `accent-hair` | accent at 12% / 8% / 35% |
| Status | `success` / `warn` / `danger` / `info` | `#5DD39E` / `#F9E547` / `#EF5B6B` / `#F08A4B` |
| Danger tint | `danger-tint` | danger at 12% |
| Row hover | `hover` | white at 2.5% |
| Skeleton | `skeleton` | white at 4% |

Insets go *darker* than the panel, not lighter: evidence blocks, timeline
tracks and inputs sit on `bg-app`.

### Which ink carries what

Measured WCAG 2.x contrast on `panel` / `bg-app`:

| Ink | On panel | On bg-app | Allowed for |
| --- | --- | --- | --- |
| `text` | 11.76 | 13.46 | Data, titles |
| `text-mid` | 7.41 | 8.48 | Data, prose, labels that are claims |
| `text-dim` | **2.99** | 3.43 | Non-essential labels only: section titles, column headers, units, eyebrows |
| `text-faint` | **1.81** | 2.07 | Decoration only: separators, arrows, rules. Never a word that must be read |
| `accent` as text | **3.28** | 3.75 | Never — use `accent-ink` |
| `accent-ink` | 5.46 | 6.25 | Technique ids, incident id on row hover, the `llm` label (5.05 on its accent wash) |

Two places this table overrode the migration spec: queue column headers are
`text-dim`, not `text-faint`; and the deterministic provenance label is
`text-mid`, not `text-dim`, because that label *is* the claim the architecture
asks a reader to check.

**Known shortfall:** white on the accent fill is **4.40:1** (3.67 on hover),
just under AA for the 11px button and active-pill labels. It is LogLens's
accent unchanged; fixing it means darkening the accent fill for buttons only,
which would split the accent in two. Recorded here rather than silently
accepted.

## Severity ramp

Severity is the primary scanning dimension of the queue, so it is the one place
in this design where colour carries information rather than decoration.

**The ramp spans temperature as well as value.** Red → orange → yellow → **blue**
→ neutral. The cold rung at LOW is load-bearing: an all-warm ramp puts MEDIUM,
LOW and INFO within a few degrees of hue and they collapse into a single smear —
precisely on the three levels an analyst most needs to separate at a glance.

**Fills are explicit colours, never the ink at low opacity.**

| Level | Ink | Fill |
| --- | --- | --- |
| CRITICAL | `#FF8A95` | `#3D1F27` |
| HIGH | `#FFAB63` | `#3B2A19` |
| MEDIUM | `#E9C84A` | `#343018` |
| LOW | `#5FB8E8` | `#182D3B` |
| INFO | `#A9B0BD` | `#343B4B` |

The chip is LogLens's badge shape: square, 10px mono 700 uppercase at 0.14em,
`4px 8px`, with a 1px edge in the chip's own ink at 35%. CRITICAL measures
77.2 × 22px. Severity is expressed as chip text colour on a tinted chip —
**never as a filled row**.

**LOW must not read as the accent.** `#5FB8E8` sits ΔE 24.5 from `#4B6CF6`, so a
LOW chip cannot be mistaken for a selected state. Do not drift LOW toward
indigo. (LogLens's own four-level palette was not usable here: it has no INFO
rung and maps MEDIUM to the accent.)

### Acceptance criteria

Any change to these ten values must re-clear all three checks. Measured off the
rendered chips (computed colours match the table exactly), CIEDE2000 for ΔE:

1. **Chip text on its own fill ≥ 4.5:1.**
   Measured: CRITICAL 6.55 · HIGH 7.35 · MEDIUM 8.11 · LOW 6.44 · INFO 5.14.
2. **No two adjacent rungs merge** — ΔE > 3 between neighbouring fills.
   Measured: 15.67 · 9.73 · 22.38 · 8.15. Worst pair anywhere in the ramp is
   LOW↔INFO at 8.15.
3. **Every chip is visible against the panel** — ΔE > 5 vs `#232A36`.
   Measured: 18.05 · 18.62 · 20.93 · 5.27 · 5.85. LOW and INFO are the quiet
   pair; the 1px ink edge is what keeps them reading as chips.

## Geometry and spacing

Spacing follows a **4px scale**; the only half-step in use is the 14px queue
column gap.

**Square.** Every radius token (`window`, `card`, `sunken`, `control`, `pill`,
`chip`) is `0px`; the names survive so component code did not churn. The one
place a radius survives is the timeline marker *shape* — square host, round
cloud — because shape is a redundant channel carrying real information. Any
other rounded corner is a bug.

| Element | Shipped |
| --- | --- |
| Icon rail | **69px** collapsed · **210px** expanded |
| Rail nav button | 44px tall; 44px wide collapsed, full width expanded |
| Toolbar height | 38px |
| View header padding | 32px 48px 24px, sticky |
| View body padding | 28px 48px 40px, sections 28px apart |
| Content ceiling | 1400px |
| Queue row height | **36px** |
| Queue column header | 32px |
| Severity filter pill | 22px |
| Search input | 26px |
| Queue column gap | 14px |
| Detail gutter | 34px |

## Shell

LogLens's collapsible rail. Collapsed by default; the logo mark (34px) expands
it, and a chevron beside the product name collapses it. Width animates over 0.3s `cubic-bezier(0.4,0,0.2,1)`; labels
fade in after the rail starts opening (0.18s, 0.15s delay) and out before it
closes (0.08s), so text never wraps inside a half-open rail. This is the one
motion in the app; under `prefers-reduced-motion` it is instant.

**Two nav links — Queue and Ingest.** Both are real `<Link>`s and
`aria-current` is derived from the route: the detail route and the `*`
fallback belong to the queue. Active is accent fill, white icon and label, and
LogLens's `0 6px 16px -6px` accent glow.

**Logo.** Two interlocking square blocks, one `text` and one `accent`, drawn
bare at 34px with `crispEdges` — no tile behind it, because half the mark is
the accent and would vanish on an accent fill. The fills read the theme
tokens, so the mark follows the palette. The same mark, with literal hexes, is
the favicon (`public/favicon.svg`). It replaced the original shield, which the
migration spec had kept as soc-triage's one piece of brand; the owner chose
this mark instead.

**Toolbar** keeps the 38px breadcrumb bar on `rail` with a `line-soft` bottom
rule and the queue's search input on the right. The light theme's window-chrome
dots are gone.

### Page rhythm

Every view opens with a `PageHead` in a sticky header on `bg-app`: eyebrow
(10px, 0.18em, `text-dim`), 32px/600 title, 13px `text-mid` subtitle, and a
right-hand slot. `SectionTitle` — 11px uppercase 0.16em `text-dim` plus a
trailing `line-soft` rule — heads every section below it. Buttons (`Btn`) are
11px uppercase 0.12em 600, `8px 14px`, square, 1px `line` border; primary is
accent fill.

## Queue view — shipped

Full-width dense table on a `panel` card, one row per correlated incident.

**Header:** eyebrow `ACTIVITY · n INCIDENTS`, title *Incident queue*, subtitle,
and the severity filter pills in the right slot — `ALL` plus all five levels
the API accepts. Active pill is accent fill with white text; inactive is a
`line` outline with `text-mid`. Showing only CRIT/HIGH/MED, as the mockup does,
would make LOW and INFO incidents unreachable by filter.

Grid template — every fixed column is sized to its own worst case so the flexible
entity column takes the remainder:

```
78px  100px  minmax(0,1fr)  62px  208px  166px  100px  62px
```

Three widths were re-measured under the same worst-case rule when the type and
chip changed:

| Column | Light theme | Now | Why |
| --- | --- | --- | --- |
| SEV | 68px | 78px | The LogLens chip makes CRITICAL 77.2px wide |
| TACTICS | 178px | 208px | Inter is wider than Instrument Sans; the worst label the closed map can produce, `defense-imp · resource-dev +13`, is 175px at 11.5px, plus 12px padding, a two-digit count and the gap |
| WINDOW | 110px | 100px | `04:41 → 04:59` is ~84px; the old width was slack |

At a 1440px viewport the entity column measures 359px and nothing in the sample
data clips; a 47-character IAM ARN (`principal:arn:aws:iam::123456789012:user/deploy`)
fits.

| Column | Content | Treatment |
| --- | --- | --- |
| SEV | Severity chip | Ramp above |
| INCIDENT | `incident_id` | Mono `text-mid`, `accent-ink` on row hover |
| PRIMARY ENTITY | `primary_entity` | Mono `text`, `title` carries the full value |
| FINDINGS | `finding_count` | Mono, right-aligned, bare number |
| TACTICS | count + short labels | Dim count, then ≤2 abbreviated tactics + `+n` |
| SOURCES | per-source event counts | Mono, `sshd 21 · cloudtrail 10 · winsec 12` |
| WINDOW · UTC | `first_seen → last_seen` | Mono, right-aligned, `04:41 → 04:59` |
| SPAN | duration | Mono, right-aligned, `18m 13s` |

Row dividers are `line-soft`; hover is white at 2.5%. Column headers are 10px
mono uppercase `text-dim`.

Source short names strip the vendor prefix (`syslog_sshd` → `sshd`,
`aws_cloudtrail` → `cloudtrail`) except Windows, which maps to `winsec`: the
stripped remainder, `security`, names a log channel rather than a product and
reads as an adjective next to the others.

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
- **Findings count is bare, tactic count is dim.** Right-aligned findings sits
  immediately left of the tactics cell, and two equally weighted digits an em
  apart read as one two-digit number.

**Footer:** states the active filters, not just a count —
`3 OF 12 INCIDENTS · SEVERITY HIGH · MATCHING "sshd" · ORDERED BY SEVERITY`.
With a small queue, a search that removes nothing is otherwise
indistinguishable from a search that did nothing.

**Ordering** is the API's own (worst-first from `correlate()`) and is never
re-sorted client-side.

### States

| State | Reads as |
| --- | --- |
| Loading | Skeleton rows at full 36px row height on the 4% white token, so the page does not jump |
| Error | Danger icon tile, `ERROR · <status>` + the backend's own message + *Try again* |
| Empty pipeline | `NO INCIDENTS` + how to ingest + a primary **Ingest a log file** button to `/ingest` |
| Filter excludes all | `NO MATCHES` + *Nothing matches that filter.* + *Clear filters* |

The last two are deliberately different. An empty queue is a *good* outcome
with a way forward and must never read as a broken page; a filter dead-end is
something the user can undo.

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

Queue and detail stay **separate routes**. LogLens's signature single-page
master/detail split is not adopted: incident ids are content hashes (decision
16) and the shareable deep link is the demo path.

**Header:** eyebrow `← BACK TO QUEUE · CORRELATED INCIDENT`, then severity chip
and the incident id as a 32px mono title, and the ladder's `severity_score` in
the right slot labelled *Severity score* — it is the ladder's integer (90 =
CRITICAL), not a 0–100 score.

**Body**, top to bottom:

1. **Trust line** — *Rules detect; the model only explains.* One line on
   `panel` with a 2px `text-dim` left edge. LogLens's `TrustBanner` carries the
   same idea plus an approval workflow; soc-triage has no workflow, so this
   keeps the claim and drops the actions, and there is nothing to dismiss.
2. **Metadata strip** — primary entity, window in the full form
   `02 Aug 2026 · 04:41:07 → 04:59:20 UTC`, span, detections — four cells at
   `2fr 1.6fr 0.8fr 1fr`, sized so the full window never clips at 1440px.
3. **Two columns** at roughly **65/35**, `minmax(0,1.85fr) minmax(0,1fr)`,
   34px gutter. Ratio units rather than a fixed sidebar width, so the split
   holds below the 1400px ceiling.

### Left column — the argument

**Summary panel** on `panel`, carrying a provenance label driven by
`enrichment_source`. The three states are told apart on three channels at once
— fill, edge and colour — so they never need reading:

| `enrichment_source` | Label |
| --- | --- |
| `deterministic` | `text-mid` on solid `bg-app`, `line-soft` edge, grey square — *generated without LLM — deterministic* |
| `llm` | `accent-ink` on the accent wash, `accent-hair` edge, accent square — *LLM-generated — structurally validated* |
| anything else | `text-mid`, no fill, **dashed** `line` outline, hollow square — *unknown source — \<value\>* |

An unrecognised value falls into the third state rather than defaulting to the
reassuring one. The claim "rules detect, AI explains" is only checkable by a
reader if the difference is visible on the page.

Summary text renders `whitespace-pre-wrap`: the deterministic summary carries an
indented timeline block whose alignment is load-bearing.

**Timeline** — the centrepiece. One row per finding, in API order (`last_seen`,
decision 18), on a `panel` card with `line-soft` row rules. Each row is a grid:

```
14px marker | 176px duration track | title + meta | evidence count | expander
```

The duration bar is positioned *and* sized against the incident's whole window,
so a row's horizontal offset is when it happened and its length is how long it
ran. Bars with a `MIN_BAR_PERCENT` floor of 2.5 keep single-instant findings
from rendering as empty track. Track and bar are square; the track sits on
`bg-app`.

Rows expand to the raw evidence, verbatim: `bg-app`, 1px `line-soft`, 11px mono
at 1.65, capped at **220px** and scrolled, so one chatty finding cannot push
the chronology off the page. Attacker-controlled text is framed, never filtered
(decision 10); `pre` means nothing in it is interpreted.

### Source distinction — three redundant channels

The timeline's job beyond listing findings is to show that one chronology was
assembled from several sources. That has to survive greyscale, colour-blindness
and a compressed README screenshot, so it is carried three times over:

1. a **3px stripe** down the row's leading edge, matching the duration bar;
2. a **rail marker** whose *shape* differs — square = host, circle = cloud,
   hollow ring = unclassified;
3. the mono source name in the meta line.

| Kind | Stripe / bar | Marker |
| --- | --- | --- |
| host | `text-mid` at 85% | `text`, square |
| cloud | `accent` | `accent`, circle |
| other | `text-faint` at 60% | hollow `text-dim` ring |

**Greyscale, measured.** Host and cloud stripes are 1.76:1 apart in luminance;
markers 3.59:1. The migration spec proposed host at 55%, which lands on exactly
the accent's luminance (1.00:1) — the stripe would have carried nothing in
greyscale and only shape would have separated the lanes. The unclassified ring
is `text-dim` because a 1px ring at `text-faint` (1.81:1) vanishes.

The axis is **host vs cloud control plane**, not parser identity
(`src/lib/sources.ts`). Keyed that way, the Windows Security parser joined the
host lane without a third treatment — two marks stay two marks and the weave
keeps reading.

`accent` marking cloud-plane findings is a **documented extension of the
accent** beyond selected state and references. Severity lives in a different
column, so the two colour languages do not collide.

### Right column — the evidence index

Compact stacked `panel` cards with `line` borders and `SectionTitle` headings,
no charts: ATT&CK tactics as square `card` tags · techniques (mono `accent-ink`
id, sans name, tactics beneath) · sources with per-source counts and a total ·
entity keys.

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

## Ingest view — shipped

The front door for `POST /api/ingest`. Styled after LogLens's `UploadLogs`;
built against soc-triage's own endpoint and `IngestResponse`.

- **Drop zone** — dashed `line` border on `panel`, 56px accent icon tile,
  accent border and wash on drag-over. The whole zone is the file input's
  label, so click, keyboard and drop all reach it. One file per upload,
  matching the endpoint. No extension allow-list: the parser is chosen by
  content server-side.
- **Syslog year** — the endpoint's optional `default_year`, because syslog
  carries no year.
- **Result** — a success edge naming the file, detected `source_type` and
  `sniff()` confidence, with a primary link to the queue; then the parse funnel
  as a five-up stat strip: lines read → lines skipped → events emitted →
  duplicates skipped → events persisted. Parse errors, when present, list line,
  reason and the verbatim excerpt.
- **Failure** — a danger edge with the backend's own words. A `422` adds its
  `supported_formats` verbatim and the best vs minimum confidence; a `413` adds
  the upload cap.
- **Sample files** — names the three committed files in `sample_logs/`, so a
  cold visitor has something to drop in.

LogLens's staged fake-progress checklist is **not** ported: the request is one
round trip, and animating steps that are not happening would be a claim the app
cannot back.

## Behavior

- Severity pills filter server-side via `?severity=`; search filters client-side
  and composes with them.
- Row click opens the incident. Deep links work; an unknown id shows the
  backend's own explanation rather than a blank pane.
- From an empty database, every step — ingest a sample, read the parse stats,
  open an incident, expand evidence, return — is reachable by mouse alone.
- Nothing is animated except the rail's width. Hover states are colour and
  border only.

## Content rules

- Technique references use real MITRE ATT&CK ids. Note the catalog is on v19:
  log tampering resolves as `T1685.002`, not the retired `T1562.008`.
- Copy is factual and lowercase-technical in mono contexts, sentence case in
  prose. No exclamation, no vendor voice.
- **All timestamps render in UTC**, never the viewer's locale — the logs are UTC
  and the summary says UTC, and two clocks in one workflow is a 3am bug.

## Light mode — not shipped

LogLens ships a `[data-theme="light"]` override, and porting it is one CSS
block. It is not part of this design yet. If it is added, the severity ramp
needs a second verified set of ten values for a light panel — and the set the
light theme shipped with is exactly that, verified against `#FCFBFA`:

| Level | Ink | Fill |
| --- | --- | --- |
| CRITICAL | `#A61B1B` | `#FBE3E1` |
| HIGH | `#8A4B08` | `#FBEBDA` |
| MEDIUM | `#7A5C00` | `#FAF0CE` |
| LOW | `#0A4A8F` | `#DCE9F8` |
| INFO | `#5A5A55` | `#EAE9E5` |

Measured then: ink on fill 6.15 · 5.82 · 5.48 · 7.14 · 5.71; adjacent fills ΔE
8.32 · 8.88 · 26.57 · 10.85; fill vs panel ΔE 10.69 · 11.01 · 17.64 · 11.68 ·
6.53. Re-measure against whatever light panel LogLens's override uses
(`#FFFFFF`) before shipping them.

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
| Four extra icon-rail buttons | The rule is *no dead controls*. When this was written the app had one destination, so the rail had one button; with `/ingest` it has two, Queue and Ingest. The mockup's other four would still do nothing, and a button that does nothing is worse than an empty rail |

The same rule governs what was taken from LogLens: its notification panel and
polling, `StatusBadge`, `UserChip`, status-mutation buttons, confidence meters,
`Settings`, `AuditLog` and `Dashboard` have no data behind them here, so only
their styling — where it applied — was adopted.
