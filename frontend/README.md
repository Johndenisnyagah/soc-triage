# Frontend

Vite + React 19 + TypeScript + Tailwind v4. Two routes: the incident queue
(`/`) and incident detail (`/incidents/:incidentId`).

## Running

The frontend needs the API. From `backend/`:

```bash
uvicorn app.main:app --reload --port 8000
```

Then, from `frontend/`:

```bash
npm install && npm run dev
```

Vite proxies `/api` to `localhost:8000`, so the app is same-origin in dev and
never needs a base-URL constant.

An empty database produces an empty queue, which is a correct result rather
than an error — the view says so in words. To put something in it:

```bash
curl -F file=@../sample_logs/auth.log -F default_year=2026 -F default_host=webserver01 http://localhost:8000/api/ingest
```

## Types are generated, not written

`src/api/schema.ts` is generated from the FastAPI OpenAPI document. Do not edit
it. After changing any Pydantic response model:

```bash
cd backend && python scripts/generate_frontend_types.py
```

`backend/tests/test_frontend_types.py` fails if the checked-in file is stale, so
a renamed field cannot reach the browser as a silent `undefined`.

## Design

`DESIGN.md` is the handoff contract and its values are authoritative;
`screens/` holds the mockups it describes. Every colour, type size, radius and
column width from that document lives as a named token in `src/index.css`
under `@theme`.

Nothing in this app should reach for a stock Tailwind scale value — `text-sm`,
`slate-500`, `rounded-lg` — for a property DESIGN.md specifies. The spec's type
sizes are half-pixel (11.5px, 12.5px), its greys are warm, and its row heights
are tighter than the defaults. Mixing the two scales is precisely how the
design drifts airy, which is the one thing this layout cannot survive.

## Divergences from the mockups

The mockups were drawn ahead of the read API and show a number of things the
backend does not model. Rather than fabricate them, the implementation leaves
them out:

| Mockup element | Why it is absent |
| --- | --- |
| `INC-0001` sequential ids | Real ids are content hashes (`INC-fe9ac9b7`). Positional ids were removed deliberately — see decision 16. |
| Row snippet, `OPEN` / `ASSIGN`, `2 NEW`, `TRIAGE ALL` | No assignment, read state or workflow actions exist. The prose summary is detail-only. |
| Stat-card sparklines and deltas (`+12`, `-4m`) | No time series and no baseline to compare against. |
| Analysts on shift, containment %, response tasks | Not modelled anywhere in the backend. |
| Notes, audit log, `Export` / `Escalate` | Same. |
| `Severity score 92 / 100` | `severity_score` is the ladder's integer (90 for CRITICAL), not a 0–100 score. |
| `RETENTION 30D` | A data-retention claim the app cannot back. |

The queue spends the width those elements would have taken on tactic breadth
and the per-source event split — which is what the severity ladder is actually
computed from.
