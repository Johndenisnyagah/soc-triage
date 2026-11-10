import type { ReactNode } from "react";
import type { IncidentDetail } from "../api/schema";
import { humanizeTactic, shortSource } from "../lib/format";
import { KIND_MARK, KIND_SHAPE, sourceKind } from "../lib/sources";
import { SectionTitle } from "./ui";

/**
 * The detail view's right column: compact stacked panels, no charts.
 *
 * Everything here is a set the incident carries -- tactics, techniques, entity
 * keys, sources. None of it is a trend and none of it has a baseline to be
 * plotted against, so a chart would be decoration standing where a fact
 * belongs.
 */

function Panel({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <section className="border border-line bg-panel p-4">
      <SectionTitle count={count}>{title}</SectionTitle>
      <div className="mt-3.5">{children}</div>
    </section>
  );
}

export function TacticsPanel({ tactics }: { tactics: string[] }) {
  return (
    <Panel title="ATT&CK tactics" count={tactics.length}>
      {tactics.length === 0 ? (
        <p className="text-meta text-text-mid">No tactics attributed.</p>
      ) : (
        <ul className="flex flex-wrap gap-1.5">
          {tactics.map((tactic) => (
            <li
              key={tactic}
              className="rounded-chip border border-line bg-card px-2 py-1 font-mono text-label uppercase text-text-mid"
            >
              {humanizeTactic(tactic)}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function TechniquesPanel({
  techniques,
}: {
  techniques: IncidentDetail["techniques"];
}) {
  return (
    <Panel title="Techniques" count={techniques.length}>
      {techniques.length === 0 ? (
        <p className="text-meta text-text-mid">
          No technique resolved against the ATT&CK catalog.
        </p>
      ) : (
        <ul className="flex flex-col gap-3">
          {techniques.map((technique) => (
            <li key={technique.technique_id}>
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-body text-accent-ink">
                  {technique.technique_id}
                </span>
                <span className="min-w-0 truncate text-meta text-text">
                  {technique.name}
                </span>
              </div>
              <p className="mt-0.5 font-mono text-label uppercase text-text-dim">
                {technique.tactics.map(humanizeTactic).join(" · ")}
              </p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function EntityKeysPanel({ entityKeys }: { entityKeys: string[] }) {
  return (
    <Panel title="Entity keys" count={entityKeys.length}>
      {/* Deliberately unbounded and un-truncated. These are the values an
          analyst pivots on, and a full IAM ARN is long precisely because the
          tail is what identifies it -- clipping would remove the useful half.
          The list is allowed to run. */}
      <ul className="flex flex-col gap-1">
        {entityKeys.map((key) => (
          <li
            key={key}
            className="font-mono text-meta leading-[1.5] break-all text-text"
          >
            {key}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function SourcesPanel({ sources }: { sources: IncidentDetail["sources"] }) {
  const total = sources.reduce((sum, s) => sum + s.event_count, 0);

  return (
    <Panel title="Sources" count={sources.length}>
      <ul className="flex flex-col gap-1.5">
        {sources.map((source) => {
          const kind = sourceKind(source.source_type);
          return (
            <li
              key={source.source_type}
              className="flex items-center gap-2 font-mono text-meta text-text"
            >
              {/* Same mark as the timeline rail, so the panel and the
                  chronology are visibly talking about the same thing. */}
              <span
                aria-hidden="true"
                className={`size-2 shrink-0 ${KIND_MARK[kind]} ${KIND_SHAPE[kind]}`}
              />
              <span className="min-w-0 truncate" title={source.source_type}>
                {shortSource(source.source_type)}
              </span>
              <span className="ml-auto text-text-mid">{source.event_count}</span>
            </li>
          );
        })}
        <li className="mt-1 flex items-center gap-2 border-t border-line-soft pt-2 font-mono text-label uppercase text-text-dim">
          <span>total events</span>
          <span className="ml-auto text-text-mid">{total}</span>
        </li>
      </ul>
    </Panel>
  );
}
