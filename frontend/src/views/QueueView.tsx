import { useMemo, useState } from "react";
import { Link } from "react-router";
import { fetchIncidents, useResource } from "../api/client";
import type { IncidentSummary, SeverityName } from "../api/schema";
import { SeverityPill } from "../components/SeverityPill";
import { Crumb, Shell } from "../components/Shell";
import {
  EmptyQueue,
  ErrorState,
  LoadingRows,
  NoMatches,
} from "../components/States";
import {
  formatShortClock,
  formatSpan,
  pluralize,
  shortSource,
} from "../lib/format";
import { SEVERITY_ABBREV, SEVERITY_ORDER } from "../lib/severity";
import { shortTactic, summarizeTactics } from "../lib/tactics";

/**
 * The incident queue: one dense row per correlated incident.
 *
 * Every column is a field the API actually returns. The mockup's row also
 * carries a one-line snippet, an assignee and a "new" flag; `IncidentSummary`
 * has no equivalent of any of them (the prose summary is detail-only, and
 * there is no assignment or read state anywhere in the backend), so the row
 * spends that width on tactic breadth and the source split instead -- which is
 * what the severity ladder is actually computed from.
 */

/** One template, shared by the header and every row, so columns cannot drift. */
// Every fixed column is sized to its own worst case and no wider, so the
// flexible entity column gets the remainder: a full IAM role ARN is ~50 mono
// characters and it is the value an analyst actually pivots on, so it is the
// last thing that should be clipped.
const COLUMNS =
  "grid grid-cols-[68px_100px_minmax(0,1fr)_62px_178px_166px_110px_62px] items-center gap-x-3.5";

function HeaderCell({
  children,
  align = "left",
}: {
  children: React.ReactNode;
  align?: "left" | "right";
}) {
  return (
    <div
      className={`font-mono text-label font-medium uppercase text-ink-faintest ${
        align === "right" ? "text-right" : ""
      }`}
    >
      {children}
    </div>
  );
}

function QueueRow({ incident }: { incident: IncidentSummary }) {
  const {
    incident_id,
    severity,
    primary_entity,
    finding_count,
    tactic_count,
    tactics,
    sources,
    first_seen,
    last_seen,
  } = incident;

  const tacticSummary = summarizeTactics(tactics);

  return (
    <Link
      to={`/incidents/${encodeURIComponent(incident_id)}`}
      className={`${COLUMNS} group h-9 border-b border-hair-4 px-4 transition-colors hover:bg-raised`}
    >
      <div>
        <SeverityPill severity={severity} />
      </div>

      <div className="truncate font-mono text-body text-ink-2 group-hover:text-accent">
        {incident_id}
      </div>

      {/* Machine-derived, so mono -- but not underlined. The whole row is the
          link to this incident; underlining the entity advertises a second,
          different destination that does not exist. Mono against the sans of
          the surrounding prose already marks it as a literal value. */}
      <div
        className="truncate font-mono text-body text-ink"
        title={primary_entity}
      >
        {primary_entity}
      </div>

      {/* Bare count: the column header already says what it counts, and an
          abbreviated unit would cost width without adding meaning. */}
      <div className="text-right font-mono text-body text-ink-2">
        {finding_count}
      </div>

      {/* The tactic count is faint and the labels carry the cell: right-aligned
          findings sits immediately left of this column, and two equally weighted
          digits an em apart read as one two-digit number. */}
      <div className="flex min-w-0 items-baseline gap-1.5 pl-3" title={tacticSummary.title}>
        <span className="font-mono text-meta text-ink-faintest">
          {tactic_count}
        </span>
        <span className="truncate text-meta text-ink-faint">
          {tacticSummary.label}
        </span>
      </div>

      <div className="truncate font-mono text-meta text-ink-muted">
        {sources.map((s) => `${shortSource(s.source_type)} ${s.event_count}`).join(" · ")}
      </div>

      {/* Window and span are two different facts -- when it happened, and how
          long it ran -- so they get two columns. Jammed together they read as
          one run-on string and neither aligns down the queue. */}
      <div className="text-right font-mono text-meta text-ink-muted">
        {formatShortClock(first_seen)}
        <span className="mx-1 text-ink-faintest">→</span>
        {formatShortClock(last_seen)}
      </div>

      <div className="text-right font-mono text-meta text-ink-faint">
        {formatSpan(first_seen, last_seen)}
      </div>
    </Link>
  );
}

export function QueueView() {
  const [severity, setSeverity] = useState<SeverityName | null>(null);
  const [search, setSearch] = useState("");

  const queue = useResource(
    (signal) => fetchIncidents(severity, signal),
    [severity],
  );

  const incidents = queue.state === "ready" ? queue.data : [];

  // Client-side, over rows already fetched -- the API has no search parameter,
  // and inventing one on the query string would 422.
  //
  // This *composes* with the severity pills rather than replacing them: the
  // pill narrows the fetch server-side, the needle narrows what came back. A
  // search that reset the pill would silently widen the result set at the
  // moment the analyst was trying to narrow it.
  //
  // Matching reaches past what the row displays. `entity_keys` and `rule_ids`
  // are on the summary payload precisely so this works: an analyst pivoting on
  // an address that appears in an incident's evidence but did not win
  // `_KEY_PRECEDENCE` would otherwise get no hit, and the queue would look
  // empty on an entity it is in fact reporting.
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return incidents;
    return incidents.filter((incident) =>
      [
        incident.incident_id,
        incident.primary_entity,
        incident.severity,
        ...incident.entity_keys,
        ...incident.rule_ids,
        ...incident.tactics,
        ...incident.tactics.map(shortTactic),
        ...incident.sources.map((s) => s.source_type),
        ...incident.sources.map((s) => shortSource(s.source_type)),
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [incidents, search]);

  const filtered = severity !== null || search.trim() !== "";

  function clearFilters() {
    setSeverity(null);
    setSearch("");
  }

  return (
    <Shell
      breadcrumb={
        <>
          <Crumb muted>Activity</Crumb>
          <Crumb muted>/</Crumb>
          <Crumb>Correlated incidents</Crumb>
        </>
      }
      actions={
        <label className="relative block w-[230px]">
          <span className="sr-only">Search incidents</span>
          <svg
            viewBox="0 0 24 24"
            className="pointer-events-none absolute left-2 top-1/2 size-[13px] -translate-y-1/2 text-ink-faint"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="M20 20l-3.5-3.5" />
          </svg>
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="search entity, rule, tactic"
            className="h-control w-full rounded-control border border-edge bg-raised pl-7 pr-2 text-meta text-ink placeholder:text-ink-faint focus:border-ink focus:outline-none"
          />
        </label>
      }
    >
      <div className="px-10 pb-10 pt-6">
        {/* Section header row -- 34px */}
        <div className="flex h-section-row items-center gap-3 border-b border-edge">
          <h1 className="font-mono text-label font-medium uppercase text-ink">
            Queue
          </h1>
          {queue.state === "ready" && (
            <span className="rounded-chip bg-accent-tint px-1.5 py-[2px] font-mono text-label font-medium uppercase text-accent">
              {visible.length}
            </span>
          )}

          <div className="ml-auto flex items-center gap-1">
            <FilterPill
              label="ALL"
              active={severity === null}
              onClick={() => setSeverity(null)}
            />
            {SEVERITY_ORDER.map((level) => (
              <FilterPill
                key={level}
                label={SEVERITY_ABBREV[level]}
                active={severity === level}
                onClick={() => setSeverity(severity === level ? null : level)}
              />
            ))}
          </div>
        </div>

        {/* Column header */}
        <div className={`${COLUMNS} h-7 border-b border-hair-1 px-4`}>
          <HeaderCell>Sev</HeaderCell>
          <HeaderCell>Incident</HeaderCell>
          <HeaderCell>Primary entity</HeaderCell>
          <HeaderCell align="right">Findings</HeaderCell>
          <HeaderCell>
            <span className="pl-3">Tactics</span>
          </HeaderCell>
          <HeaderCell>Sources</HeaderCell>
          <HeaderCell align="right">Window · UTC</HeaderCell>
          <HeaderCell align="right">Span</HeaderCell>
        </div>

        {queue.state === "loading" && <LoadingRows />}

        {queue.state === "error" && (
          <ErrorState error={queue.error} onRetry={queue.reload} />
        )}

        {queue.state === "ready" && visible.length === 0 && (
          // Two different nothings: an empty pipeline is a real result, a
          // filter that excluded everything is a dead end the user can undo.
          filtered ? <NoMatches onClear={clearFilters} /> : <EmptyQueue />
        )}

        {queue.state === "ready" &&
          visible.map((incident) => (
            <QueueRow key={incident.incident_id} incident={incident} />
          ))}

        {queue.state === "ready" && visible.length > 0 && (
          // States the active filters, not just the count. With a queue this
          // small a search that removes nothing is indistinguishable from a
          // search that did nothing, so the line names what is being applied.
          <p className="px-4 pt-3 font-mono text-label font-medium uppercase text-ink-faintest">
            {search.trim() && visible.length !== incidents.length
              ? `${visible.length} of ${pluralize(incidents.length, "incident")}`
              : pluralize(visible.length, "incident")}
            {severity ? ` · severity ${severity}` : ""}
            {search.trim() ? (
              <>
                {" · matching "}
                {/* The needle is the user's own text, echoed back. The label
                    style is uppercase, but forcing case on it would show them
                    something they did not type. */}
                <span className="normal-case">"{search.trim()}"</span>
              </>
            ) : null}
            {" · ordered by severity"}
          </p>
        )}
      </div>
    </Shell>
  );
}

function FilterPill({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`h-[22px] rounded-pill border px-2 font-mono text-label font-medium uppercase transition-colors ${
        active
          ? "border-ink bg-ink text-raised"
          : "border-edge bg-raised text-ink-muted hover:border-ink hover:text-ink"
      }`}
    >
      {label}
    </button>
  );
}
