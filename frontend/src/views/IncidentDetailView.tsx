import { Link, useParams } from "react-router";
import { ArrowLeft, ShieldCheck } from "lucide-react";
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
import { PageHead, ViewBody, ViewHeader } from "../components/ui";
import { formatSpan, formatWindow, pluralize } from "../lib/format";

/**
 * Incident detail. Two columns, roughly 65/35, at the queue's density and on
 * the same tokens.
 *
 * The left column is the argument -- what happened, in order. The right column
 * is the evidence index: the sets an analyst pivots on. Nothing in either is
 * computed here; every value is a field the API returned.
 *
 * Queue and detail stay separate routes rather than LogLens's master/detail
 * split: incident ids are content hashes (decision 16), and the shareable deep
 * link is the demo path.
 */

function MetaItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1 px-5 py-3.5">
      <span className="font-mono text-label font-medium uppercase text-text-dim">
        {label}
      </span>
      <span className="min-w-0 truncate font-mono text-meta text-text">
        {children}
      </span>
    </div>
  );
}

/**
 * The claim the architecture rests on, stated where a reader can check it.
 * LogLens's `TrustBanner` carries the same idea plus an approval workflow;
 * soc-triage has no workflow, so this keeps the claim and drops the actions.
 * Nothing to dismiss, either: it is one line, and it is always true.
 */
function TrustLine() {
  return (
    <p className="flex items-center gap-3.5 border-l-2 border-text-dim bg-panel px-5 py-3 text-meta leading-relaxed text-text-mid">
      <ShieldCheck
        className="size-4 shrink-0 text-text-mid"
        strokeWidth={1.8}
        aria-hidden="true"
      />
      <span>
        <strong className="mr-1.5 font-semibold text-text">
          Rules detect; the model only explains.
        </strong>
        Every finding here was raised by a deterministic rule, and severity comes
        from the breadth of ATT&CK tactics those rules matched. A language model
        may write the summary — its label says whether one did.
      </span>
    </p>
  );
}

export function IncidentDetailView() {
  const { incidentId = "" } = useParams();
  const incident = useResource(
    (signal) => fetchIncident(incidentId, signal),
    [incidentId],
  );

  const ready = incident.state === "ready" ? incident.data : null;

  return (
    <Shell
      breadcrumb={
        <>
          <Crumb muted>
            <Link to="/" className="transition-colors hover:text-text">
              Activity
            </Link>
          </Crumb>
          <Crumb muted>/</Crumb>
          <Crumb muted>
            <Link to="/" className="transition-colors hover:text-text">
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
      <ViewHeader>
        <PageHead
          eyebrow={
            <>
              <Link
                to="/"
                className="inline-flex items-center gap-1.5 text-text-mid transition-colors hover:text-text"
              >
                <ArrowLeft className="size-3" strokeWidth={2.2} aria-hidden="true" />
                Back to queue
              </Link>
              <span aria-hidden="true" className="text-text-faint">·</span>
              <span>Correlated incident</span>
            </>
          }
          title={
            <span className="flex flex-wrap items-center gap-3.5">
              {ready && <SeverityPill severity={ready.severity} />}
              <span className="font-mono">{incidentId}</span>
            </span>
          }
          right={
            ready ? (
              // `severity_score` is the ladder's integer (90 = CRITICAL), not
              // a 0-100 score, so it is labelled as exactly that.
              <div className="flex flex-col items-end gap-1">
                <span className="font-mono text-label font-medium uppercase text-text-dim">
                  Severity score
                </span>
                <span className="font-mono text-stat text-text">
                  {ready.severity_score}
                </span>
              </div>
            ) : undefined
          }
        />
      </ViewHeader>

      <ViewBody>
        {incident.state === "loading" && (
          <div className="border border-line bg-panel">
            <LoadingRows rows={6} />
          </div>
        )}

        {incident.state === "error" && (
          // A 404 here is the interesting case: an id stops resolving when the
          // evidence behind it is no longer stored, and the backend explains
          // exactly that. Surfacing its message beats a generic "not found".
          <div className="border border-line bg-panel">
            <ErrorState error={incident.error} onRetry={incident.reload} />
          </div>
        )}

        {ready && (
          <>
            <TrustLine />

            {/* Ratios sized so the full UTC window never clips at the 1440
                viewport: the window string is the longest fixed-format value
                here, and the ARN in the first cell has `title` to fall back on. */}
            <div className="grid grid-cols-[minmax(0,2fr)_minmax(0,1.6fr)_minmax(0,0.8fr)_minmax(0,1fr)] divide-x divide-line-soft border border-line bg-panel">
              <MetaItem label="Primary entity">
                <span title={ready.primary_entity}>{ready.primary_entity}</span>
              </MetaItem>
              <MetaItem label="Window">
                {formatWindow(ready.first_seen, ready.last_seen)}
              </MetaItem>
              <MetaItem label="Span">
                {formatSpan(ready.first_seen, ready.last_seen)}
              </MetaItem>
              <MetaItem label="Detections">
                {pluralize(ready.finding_count, "finding")} ·{" "}
                {pluralize(ready.tactic_count, "tactic")}
              </MetaItem>
            </div>

            {/* ~65/35. Ratio units rather than a fixed sidebar width, so the
                split holds below the 1400px ceiling instead of the left column
                absorbing every pixel lost. */}
            <div className="grid grid-cols-[minmax(0,1.85fr)_minmax(0,1fr)] gap-x-[34px] gap-y-7">
              <div className="flex min-w-0 flex-col gap-7">
                <SummaryPanel
                  summary={ready.summary}
                  enrichmentSource={ready.enrichment_source}
                />
                <Timeline entries={ready.timeline} />
              </div>

              <aside className="flex min-w-0 flex-col gap-4">
                <TacticsPanel tactics={ready.tactics} />
                <TechniquesPanel techniques={ready.techniques} />
                <SourcesPanel sources={ready.sources} />
                <EntityKeysPanel entityKeys={ready.entity_keys} />
              </aside>
            </div>
          </>
        )}
      </ViewBody>
    </Shell>
  );
}
