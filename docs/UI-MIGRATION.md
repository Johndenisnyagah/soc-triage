# UI migration — adopt the LogLens AI design language in soc-triage

Handoff spec for Claude Code. Replaces the frontend's visual system wholesale.
Read this and `frontend/DESIGN.md` before touching any file.

**Goal.** soc-triage currently ships a warm light theme (off-white paper, orange
accent). LogLens AI ships a dark blue-grey theme that John designed and prefers.
Move soc-triage onto the LogLens language, refined — fixing the inconsistencies
LogLens itself carries rather than reproducing them.

Two things are happening and they are separate:

1. **A reskin** — palette, typeface, geometry, page rhythm (§2–§4, §6–§9).
2. **A navigation fix** — the app has a backend capability with no front door
   and a nav control that does nothing (§5). This is a real defect, found by
   using the app, not a styling preference.

**Scope.** `frontend/` only. No backend file changes. No API shape changes.

---

## 0. The one trap

This is not a port of LogLens. soc-triage keeps its own functionality; only the
visual language changes. The finished app should read as the same *design
system* as LogLens, not as the same *application*.

LogLens's UI serves a product with features soc-triage does not have: incident
status workflow (open/reviewed/resolved/false-positive), notification polling,
audit log, settings, user chips, AI confidence meters.

**Adopt the visual system. Do not adopt the feature set.**

`DESIGN.md` → *Divergences from the mockups* already records why the current
frontend omits assignment, read state, workflow actions, sparklines and
retention claims: the backend does not model them, and inventing them would put
a claim on screen the app cannot back. That reasoning is unchanged. If a
LogLens component has no data behind it in soc-triage, port the *styling* of
that component and drop the component.

Concretely, do **not** port: `Sidebar`'s notification panel and 30s polling,
`StatusBadge`, `UserChip`, the status-mutation footer buttons, the confidence
bar/meter, `TrustBanner`'s "awaiting your approval" actions list, `Settings`,
`AuditLog`, `Dashboard`.

The one exception is `UploadLogs`, and only because soc-triage has a real
`POST /api/ingest` endpoint behind it — see §5. Take its *styling*; build the
view against soc-triage's own endpoint and its `IngestResponse`, not LogLens's.

---

## 1. What does not change

These are settled and survive the reskin. Breaking any of them is a regression,
not a redesign.

| Invariant | Where it lives |
| --- | --- |
| `/` queue and `/incidents/:incidentId` detail stay as routes. Deep links work. (A third route is **added** in §5.) | `App.tsx` |
| Types are generated from OpenAPI, never hand-written | `src/api/schema.ts`, `npm run gen:api` |
| Severity filters server-side via `?severity=`; search is client-side and **composes** with the pills | `QueueView` |
| Search reaches past displayed columns into `entity_keys` and `rule_ids` | `QueueView` |
| Queue ordering is the API's own, never re-sorted client-side | `QueueView` |
| Timeline rows in API order (`last_seen`), bars positioned *and* sized against the incident window, `MIN_BAR_PERCENT` 2.5 floor | `Timeline.tsx` |
| Source distinction carried on **three redundant channels**: edge stripe, marker *shape*, mono source name. Axis is host vs cloud plane, not parser identity. | `lib/sources.ts`, `Timeline.tsx` |
| `enrichment_source` renders three visually distinct states; an unrecognised value falls to the neutral one, never the reassuring one | `SummaryPanel.tsx` |
| Raw evidence is `pre`, verbatim, framed not filtered | `Timeline.tsx` |
| Entity keys unbounded, `break-all`, never truncated | `SidePanels.tsx` |
| All timestamps UTC, never viewer locale | `lib/format.ts` |
| Four distinct states per view: loading skeletons at full row height, error with the backend's own message, empty pipeline, filter dead-end | `States.tsx` |
| Tactics abbreviated from the closed 15-item map, not truncated at runtime | `lib/tactics.ts` |

`src/api/`, `src/lib/format.ts`, `src/lib/tactics.ts` and `src/lib/sources.ts`
need **no logic changes** — only the colour class strings inside `sources.ts`.

---

## 2. Token replacement

Replace the `@theme` block in `src/index.css` entirely. Source of truth is
`loglens_ai/frontend/src/index.css`.

### Surfaces, ink, accent

```css
/* Surfaces */
--color-bg-app:     #1a1f29;   /* outermost background      */
--color-panel:      #232a36;   /* card / panel surfaces     */
--color-card:       #2a313e;   /* inset surfaces in panels  */
--color-rail:       #161a23;   /* icon rail                 */

/* Rules */
--color-line:       #323a49;   /* primary borders           */
--color-line-soft:  #2a313e;   /* subtle dividers, row rules */

/* Ink */
--color-text:       #e6e8ec;
--color-text-mid:   #b5bac4;
--color-text-dim:   #6b7283;
--color-text-faint: #4a5160;

/* Accent */
--color-accent:       #4b6cf6;
--color-accent-hover: #5b7bff;

/* Status */
--color-success: #5dd39e;
--color-warn:    #f9e547;
--color-danger:  #ef5b6b;
--color-info:    #f08a4b;
```

Mapping from the current warm tokens:

| Old | New |
| --- | --- |
| `desk` `#efeeeb` | `bg-app` `#1a1f29` |
| `panel` `#fcfbfa` | `panel` `#232a36` |
| `raised` `#ffffff` | `card` `#2a313e` |
| `sunken` / `sunken-deep` | `bg-app` (insets go *darker* in a dark theme, not lighter) |
| `rail` / `queue` | `rail` `#161a23` |
| `edge` | `line` `#323a49` |
| `hair-1..4` | collapse to `line-soft` `#2a313e` — four hairline greys cannot be told apart on a dark panel and the distinction was carrying nothing |
| `ink` / `ink-2` / `ink-muted` / `ink-faint` / `ink-faintest` | `text` / `text-mid` / `text-mid` / `text-dim` / `text-faint` |
| `accent` `#e0620d` | `accent` `#4b6cf6` |
| `accent-tint` / `accent-hair` | `rgba(75,108,246,0.12)` / `rgba(75,108,246,0.35)` |

Delete `--color-desk-hatch`, `.desk-hatch` and `.dot-grid`. LogLens has no desk
metaphor; the hatch and dot-grid were chrome for a window shell being removed
(§5).

### Type

LogLens uses **Inter**, not Instrument Sans. Swap it; keep JetBrains Mono.

```css
--font-sans: 'Inter', system-ui, sans-serif;
--font-mono: 'JetBrains Mono', monospace;
```

Update the Google Fonts link in `index.html` to
`Inter:wght@300;400;500;600;700` + `JetBrains+Mono:wght@400;500`.
Keep `font-feature-settings: "ss01", "cv11"` on body (LogLens sets it).

**Keep the entire existing type scale** (`--text-label` … `--text-score`) and
`tabular-nums`. The half-pixel sizes and the 36px row height are what make the
queue dense, and density is the one thing both designs agree on. LogLens's page
titles are larger (32px `PageHead`); adopt that for view headings only.

### Geometry — flatten the radii

This is the biggest silent visual difference. soc-triage is rounded
(14/11/9/8/6/4px); LogLens is **square** — badges, chips, buttons, panels and
evidence blocks all have no radius.

```css
--radius-window:  0px;
--radius-card:    0px;
--radius-sunken:  0px;
--radius-control: 0px;
--radius-pill:    0px;
--radius-chip:    0px;
```

Keep the radius tokens as names so component code does not churn. Two
exceptions where a radius stays: the rail logo tile (LogLens's mark sits in a
square but the nav buttons are square too — use 0) and nothing else. If a
rounded corner survives anywhere, it is a bug.

LogLens's own `EmptyState` (`rounded-2xl`) and `RawLogBlock` (`rounded-xl`) are
inconsistent leftovers — **do not copy them**. Square everything.

Keep all spacing tokens (`--spacing-rail` through `--spacing-ceiling`) except
`--spacing-rail`, which changes (§5).

---

## 3. Severity ramp — rebuilt and verified

`DESIGN.md` gives the ramp three hard acceptance criteria. **All ten current
values fail on a dark panel** — they were engineered against `#FCFBFA`. The ramp
below is recomputed against `#232a36` and clears all three. Use these values.

```css
--color-sev-critical:      #ff8a95;
--color-sev-critical-fill: #3d1f27;
--color-sev-high:          #ffab63;
--color-sev-high-fill:     #3b2a19;
--color-sev-medium:        #e9c84a;
--color-sev-medium-fill:   #343018;
--color-sev-low:           #5fb8e8;
--color-sev-low-fill:      #182d3b;
--color-sev-info:          #a9b0bd;
--color-sev-info-fill:     #343b4b;
```

Measured (CIEDE2000 for ΔE, WCAG 2.x for contrast):

| Level | Ink on own fill | Fill vs panel ΔE |
| --- | --- | --- |
| CRITICAL | 6.55 | 18.05 |
| HIGH | 7.35 | 18.62 |
| MEDIUM | 8.11 | 20.93 |
| LOW | 6.44 | 5.27 |
| INFO | 5.14 | 5.85 |

Adjacent fill ΔE: 15.66 · 9.73 · 22.38 · 8.15. Worst pair anywhere in the ramp
is LOW↔INFO at 8.15, comfortably past the ΔE 6 bar the light ramp held.

Three things to preserve from the original reasoning:

1. **The ramp still spans temperature, not just value** — red → orange → yellow
   → **blue** → neutral. The cold rung at LOW is load-bearing for exactly the
   same reason as before.
2. **Fills are explicit colours, never the ink at low opacity.** Do not
   substitute `bg-sev-critical/10`.
3. **Severity is chip text on a tinted chip, never a filled row.**

One new constraint the dark theme introduces: **LOW must not read as the accent.**
`#5fb8e8` sits ΔE 24.5 from `#4b6cf6`, so a LOW chip cannot be mistaken for a
selected state. Do not drift LOW toward indigo.

LogLens's own four-level severity palette is *not* usable — it has no INFO rung
and it maps MEDIUM to the accent blue, which collides with selected state.

---

## 4. Source colours (`lib/sources.ts`)

Logic unchanged; swap the class strings. Cloud still takes the accent — that is
`DESIGN.md`'s one documented extension of the accent, and it still holds because
severity lives in a different column.

```ts
export const KIND_BAR: Record<SourceKind, string> = {
  host:  "bg-text-mid/55",
  cloud: "bg-accent",
  other: "bg-text-faint/60",
};
export const KIND_MARK: Record<SourceKind, string> = {
  host:  "bg-text",
  cloud: "bg-accent",
  other: "bg-text-faint",
};
```

`KIND_SHAPE` keeps `rounded-[1px]` / `rounded-full` / hollow ring. **Shape is the
one place a radius survives**, because it is a redundant channel carrying real
information. Update the ring colour token only.

Verify after: the timeline must still read in greyscale. Screenshot it
desaturated and confirm host vs cloud is still distinguishable.

---

## 5. Navigation and reachability — the gap to close

Two defects found by using the app. Fix both; they are the reason this is not a
pure reskin.

### 5a. `POST /api/ingest` has no front door

The backend exposes `POST /api/ingest` (`backend/app/api_ingest.py:82`) and
nothing in the UI calls it. The queue's empty state currently tells the reader
to issue the HTTP request themselves:

> No events currently stored correlate into an incident. Ingest a log file
> through `POST /api/ingest` to populate the queue.

That is a dead end. A first-time visitor — or anyone reviewing the portfolio —
lands on an empty queue and cannot populate it without leaving for a terminal.

**Add a third route, `/ingest`, with a real upload view.**

- Drag-and-drop zone plus a file picker fallback. One file at a time matches
  the endpoint.
- `POST` as `multipart/form-data` to `/api/ingest`.
- On success render the full `IngestResponse`, which is the interesting part:
  detected source type and confidence, lines read, events emitted, lines
  skipped, duplicates skipped. Those numbers are the parser registry's
  confidence scoring and the global dedup made visible, and they are worth
  showing rather than collapsing into "uploaded".
- On `422` (unrecognised format) surface the backend's own message and its
  `supported_formats` list verbatim — do not restate it.
- On `413` surface the size cap.
- After a successful ingest, link straight to the queue.
- Sample files are committed at `sample_logs/`. Mention them in the view so a
  cold visitor has something to drop in.

Read the actual response model in `api_ingest.py` before building the result
panel; do not infer the field names from this document.

### 5b. The rail's nav control is not a control

`components/Shell.tsx` renders the queue nav item as a `<span>` with
`aria-current="page"` and an accent-tinted active style. It looks like a button,
reads to a screen reader as the current page, and does nothing on click. It is
also wrong whenever the user is on the detail route.

Make it a real `<Link>`, and drive `aria-current` from the actual location
rather than hardcoding it.

### 5c. Consequences for the rail

With `/ingest` added the app has **two destinations**, so:

- The rail carries two nav buttons: Queue and Ingest. Both are links with a
  real active state derived from the route.
- `DESIGN.md`'s "the app has one destination; a button that does nothing is
  worse than an empty rail" is now **obsolete** — it was correct when written.
  Update that line rather than deleting it, so the reasoning survives: the rule
  was never "one button", it was "no dead controls".
- The collapsible rail (§6) now earns itself — labels are worth revealing when
  there is more than one place to go.

Still do not add the mockup's other four icons. Two real destinations, two
buttons.

### 5d. Empty state becomes a route, not an instruction

`States.tsx`'s empty-pipeline state keeps its copy but gains a primary button to
`/ingest`. Keep the distinction between *empty pipeline* (a good outcome, with a
way forward) and *filter dead-end* (undo the filter) — that distinction is
already right and must survive.

### What stays out

No assignment, no read state, no workflow actions, no export, no escalate. The
`Divergences` table in `DESIGN.md` still holds for every one of them. `/ingest`
is added because the endpoint exists, not because LogLens has an upload page.

---

## 6. Shell — adopt the LogLens rail

Replace `components/Shell.tsx`. Reference: `loglens_ai/.../layout/Sidebar.tsx`.

**Remove:** the three fake window-chrome dots. LogLens has no window metaphor
and they were decoration.

**Rail.** Collapsible, 69px → 210px, `--color-rail` background, `width`
transition `0.3s cubic-bezier(0.4,0,0.2,1)`. Logo tile at top (keep the existing
shield; it is soc-triage's one piece of brand — do not port the LogLens mark),
product name fading in when expanded, collapse chevron on the right when
expanded. Nav buttons 44px tall, left-aligned at `paddingLeft` 11px collapsed /
14px expanded, label `max-width` 0 → 160px with the staggered opacity LogLens
uses.

Active nav button: `--color-accent` fill, white text, `box-shadow: 0 6px 16px
-6px rgba(75,108,246,0.6)`.

**Set `--spacing-rail: 69px`** and add `--spacing-rail-expanded: 210px`.

**Two nav buttons** — Queue and Ingest (§5c) — both real links with active state
derived from the route. No dead controls beyond them. The rail may stay
collapsed by default; expanding reveals the labels.

**Toolbar.** Keep the 38px breadcrumb toolbar; restyle to `--color-rail`
background with `--color-line-soft` bottom border. Keep the search input on the
right.

---

## 7. Component-by-component

| File | Change |
| --- | --- |
| `index.css` | Full `@theme` replacement (§2, §3). Keep `tabular-nums` rule, keep `:focus-visible` (accent outline still works). Drop `.desk-hatch`, `.dot-grid`. |
| `index.html` | Inter + JetBrains Mono. |
| `App.tsx` | Add the `/ingest` route (§5a). Keep the `*` fallback to the queue. |
| `Shell.tsx` | Rewrite per §6. Nav items become real `<Link>`s with route-derived active state (§5b, §5c). |
| `views/IngestView.tsx` | **New** (§5a). Styling borrowed from LogLens `UploadLogs`; behaviour built against `POST /api/ingest` and its real response model. |
| `SeverityPill.tsx` | Restyle only: 10px bold uppercase, `letter-spacing: 0.14em`, `padding: 4px 8px`, square, `1px` border in the chip ink at ~35% alpha. Follow LogLens `SeverityBadge`'s shape. |
| `QueueView.tsx` | Keep the grid template, columns, ordering, search and filter logic **exactly**. Restyle: row dividers `--color-line-soft`, row hover `rgba(255,255,255,0.025)`, column headers 10px uppercase `0.1em` in `--color-text-faint`. Filter pills: active = accent fill + white text (replacing ink fill). Add a `PageHead` (§8). |
| `IncidentDetailView.tsx` | Keep the `minmax(0,1.85fr) minmax(0,1fr)` split and 34px gutter. Left column on `--color-panel`, right column panels on `--color-panel` with `--color-line` borders. |
| `SummaryPanel.tsx` | Keep all three `enrichment_source` states and their semantics. Restyle: deterministic = `--color-text-dim` on `--color-bg-app`; llm = `--color-accent` on `rgba(75,108,246,0.08)` with an accent border; unknown = `--color-text-mid` on transparent with a `--color-line` outline. The three must stay tellable apart without reading. |
| `Timeline.tsx` | Keep the grid, bar maths, expansion and evidence rendering. Restyle: evidence block = `--color-bg-app` bg, `1px solid --color-line-soft`, mono 11px, `line-height: 1.65`, `max-height: 220px`, scroll. |
| `SidePanels.tsx` | Panels on `--color-panel`, `1px solid --color-line`. Section titles adopt LogLens's pattern: 11px uppercase `0.16em` `--color-text-dim` + a `flex: 1` 1px rule in `--color-line-soft`. |
| `States.tsx` | Restyle skeletons to `rgba(255,255,255,0.04)`. Error icon tile `rgba(239,91,107,0.12)` with `--color-danger`. Keep all four states and their distinct copy. Empty-pipeline state gains a primary button to `/ingest` (§5d). |

### New components to add

Port these from LogLens, restyled and trimmed:

- **`PageHead`** — eyebrow (10px uppercase `0.18em` dim) + 32px/600 title
  (`-0.02em`) + 13px subtitle + a right slot. Use it on all three views. This is
  the single biggest structural borrow and it is what makes the views read as
  LogLens.
- **`SectionTitle`** — the 11px uppercase label + trailing rule. Used throughout
  the detail view.
- **`Btn`** — `ghost` / default / `primary` variants. 11px uppercase `0.12em`
  600, `padding: 8px 14px`, square, `1px solid --color-line`. Primary is accent
  fill. Only wire up buttons that have real behaviour.

Do **not** port `TrustBanner` as-is (its body describes approval workflow that
does not exist here), but **do** port the idea: a one-line banner on the detail
view stating that rules detect and the model only explains. soc-triage's
`enrichment_source` label already makes this checkable; the banner states it.
Keep it to the claim, with no action list.

---

## 8. Layout

Queue and detail stay separate routes. Do not adopt LogLens's single-page
master/detail split, even though it is LogLens's signature move: soc-triage's
incident ids are content hashes (decision 16) and the shareable deep link is the
demo path and the README screenshot. A preview pane can be added later; it is
not part of this migration.

Do adopt LogLens's page rhythm:

- **Sticky view header** on `--color-bg-app`, `padding: 32px 48px 24px`,
  `border-bottom: 1px solid --color-line-soft`, containing `PageHead` with the
  filter controls in its right slot.
- **Body** at `padding: 28px 48px 40px`, `display: flex; flex-direction: column;
  gap: 28px`.

This replaces the current `24px 40px 40px` page padding. Keep the 1400px ceiling.

---

## 9. Dependencies

Add **`lucide-react`** only. Icons are needed and hand-rolling them is churn.

Do **not** add:

- `framer-motion` — `DESIGN.md` says "Nothing is animated. Hover states are
  colour and border only." That is a deliberate restraint and it survives. The
  rail's width transition is plain CSS.
- `axios` — the app uses `fetch` and has no reason to change.
- `react-router-dom` — soc-triage is on `react-router` v8. Do not downgrade to
  match LogLens.

---

## 10. Optional: light-mode toggle

LogLens ships a `[data-theme="light"]` override. Porting it is cheap (one CSS
block) and gives soc-triage a theme switch. **Not part of this migration** — if
added later, the severity ramp needs a second verified set of ten values for the
light panel, and the ones currently in `DESIGN.md` are exactly that set. Note
this in `DESIGN.md` so the old values are not simply deleted.

---

## 11. Order of work

Do the navigation fix **first**, on the current light theme, and commit it
separately. It is a behaviour change and it should be reviewable on its own
rather than buried in a diff that touches every colour in the app.

1. **Navigation (§5), light theme, own commit.** `/ingest` route and view, rail
   links made real, empty-state button. Verify you can ingest a sample file
   from the browser and land on a populated queue.
2. Tokens: `index.css` + `index.html` fonts. Everything will look broken; that
   is expected.
3. `SeverityPill` + `lib/sources.ts` class strings. Verify the ramp (§12).
4. `Shell.tsx` rail and toolbar.
5. `PageHead`, `SectionTitle`, `Btn`.
6. `QueueView` restyle + `PageHead`.
7. `IncidentDetailView`, `SummaryPanel`, `Timeline`, `SidePanels`.
8. `IngestView` restyle.
9. `States.tsx`.
10. Rewrite `frontend/DESIGN.md` against the shipped result — it is explicitly a
    transcription of what shipped, not of intent, so every hex, size and width
    in it must be re-measured off the running app, not copied from this
    document. Update the obsolete "one destination" line (§5c) rather than
    deleting it, and move the light ramp's ten values into the light-mode note
    (§10) rather than dropping them.
11. Re-shoot `frontend/screens/` and the README screenshots.

---

## 12. Verification before you call it done

- `npm run typecheck` clean; `npm run build` succeeds.
- Backend suite still passes (no backend files were touched — confirm with
  `git status`).
- **Severity ramp:** render all five chips and re-measure. Every ink ≥ 4.5:1 on
  its own fill; every adjacent fill pair ΔE > 3; every fill ΔE > 5 vs
  `#232a36`. Report the numbers, do not eyeball them.
- **Greyscale test:** desaturate a detail-view screenshot. Host vs cloud timeline
  rows must still be distinguishable by shape and stripe alone.
- **Contrast:** `--color-text` on `--color-panel` measures 11.76:1. Confirm
  `--color-text-dim` (`#6b7283`) on `--color-panel` — if it lands under 4.5:1 it
  may be used only for non-essential labels, never for data.
- All four queue states and all three `enrichment_source` states render and are
  visually distinct. Hit each one.
- **Reachability, clicked not reasoned about:** starting from `/` with an empty
  database and using only the mouse — reach `/ingest`, upload a file from
  `sample_logs/`, read the parse stats, return to the queue, open an incident,
  expand an evidence row, and get back to the queue. No step may require typing
  a URL or a terminal command.
- Every rail item navigates, and the active state is correct on all three
  routes — including the detail route, where the queue item should read as
  active.
- Deep link to a known incident id works; an unknown id still surfaces the
  backend's own recomputed-evidence explanation.
- Ingest failure paths render: a `422` on an unrecognised format shows the
  backend's message and `supported_formats`; an oversized file shows the cap.
- No rounded corners survive except the timeline marker shapes.
- Search still matches on `entity_keys` and `rule_ids`, and still composes with
  the severity pills.
- Grep the diff for stock Tailwind scale values (`text-sm`, `slate-`,
  `rounded-lg`, `gray-`). There should be none — same rule as before, new tokens.

Branch, push, and hand back the compare URL per the repo's PR convention in
`CLAUDE.md`.
