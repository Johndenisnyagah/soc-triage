import { Link, useParams } from "react-router";
import { fetchIncident, useResource } from "../api/client";
import { Crumb, Shell } from "../components/Shell";
import { SeverityPill } from "../components/SeverityPill";
import { SummaryPanel } from "../components/SummaryPanel";
import { Timeline } from "../components/Timeline";
import {
  EntityKeysPanel,
  SourcesPanel,
  TacticsPanel,
  TechniquesPanel,
} from "../components/SidePanels";
import { ErrorState, LoadingRows } from "../components/States";
import { formatSpan, formatWindow, pluralize } from "../lib/format";

/**
 * Incident detail. Two columns, roughly 65/35, at the queue's density and on
 * the same tokens.
 *
 * The left column is the argument -- what happened, in order. The right column
 * is the evidence index: the sets an analyst pivots on. Nothing in either is
 * computed here; every value is a field the API returned.
 */

function MetaItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <span className="font-mono text-label font-medium uppercase text-ink-faintest">
        {label}
      </span>
      <span className="min-w-0 truncate font-mono text-meta text-ink-2">
        {children}
      </span>
    </div>
  );
}

export function IncidentDetailView() {
  const { incidentId = "" } = useParams();
  const incident = useResource(
    (signal) => fetchIncident(incidentId, signal),
    [incidentId],
  );

  return (
    <Shell
      breadcrumb={
        <>
          <Crumb muted>
            <Link to="/" className="transition-colors hover:text-accent">
              Activity
            </Link>
          </Crumb>
          <Crumb muted>/</Crumb>
          <Crumb muted>
            <Link to="/" className="transition-colors hover:text-accent">
              Correlated incidents
            </Link>
          </Crumb>
          <Crumb muted>/</Crumb>
          <Crumb>
            <span className="font-mono">{incidentId}</span>
          </Crumb>
        </>
      }
    >
      <div className="px-10 pb-10 pt-6">
        <Link
          to="/"
          className="inline-block font-mono text-label uppercase text-ink-muted transition-colors hover:text-accent"
        >
          ← Back to queue
        </Link>

        {incident.state === "loading" && (
          <div className="mt-6">
            <LoadingRows rows={6} />
          </div>
        )}

        {incident.state === "error" && (
          // A 404 here is the interesting case: an id stops resolving when the
          // evidence behind it is no longer stored, and the backend explains
          // exactly that. Surfacing its message beats a generic "not found".
          <ErrorState error={incident.error} onRetry={incident.reload} />
        )}

        {incident.state === "ready" && (
          <>
            <header className="mt-4 border-b border-edge pb-4">
              <div className="flex flex-wrap items-center gap-2.5">
                <SeverityPill severity={incident.data.severity} />
                <h1 className="font-mono text-h-detail font-semibold text-ink">
                  {incident.data.incident_id}
                </h1>
                <span className="font-mono text-meta text-ink-faintest">
                  score {incident.data.severity_score}
                </span>
              </div>

              <div className="mt-3 grid grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1fr)] gap-x-6">
                <MetaItem label="Primary entity">
                  <span
                    className="text-ink"
                    title={incident.data.primary_entity}
                  >
                    {incident.data.primary_entity}
                  </span>
                </MetaItem>
                <MetaItem label="Window">
                  {formatWindow(
                    incident.data.first_seen,
                    incident.data.last_seen,
                  )}
                </MetaItem>
                <MetaItem label="Span">
                  {formatSpan(incident.data.first_seen, incident.data.last_seen)}
                </MetaItem>
                <MetaItem label="Detections">
                  {pluralize(incident.data.finding_count, "finding")} ·{" "}
                  {pluralize(incident.data.tactic_count, "tactic")}
                </MetaItem>
              </div>
            </header>

            {/* ~65/35. Ratio units rather than a fixed sidebar width, so the
                split holds below the 1400px ceiling instead of the left column
                absorbing every pixel lost. */}
            <div className="mt-6 grid grid-cols-[minmax(0,1.85fr)_minmax(0,1fr)] gap-x-[34px] gap-y-6">
              <div className="flex min-w-0 flex-col gap-6">
                <SummaryPanel
                  summary={incident.data.summary}
                  enrichmentSource={incident.data.enrichment_source}
                />
                <Timeline entries={incident.data.timeline} />
              </div>

              <aside className="flex min-w-0 flex-col gap-4">
                <TacticsPanel tactics={incident.data.tactics} />
                <TechniquesPanel techniques={incident.data.techniques} />
                <SourcesPanel sources={incident.data.sources} />
                <EntityKeysPanel entityKeys={incident.data.entity_keys} />
              </aside>
            </div>
          </>
        )}
      </div>
    </Shell>
  );
}
