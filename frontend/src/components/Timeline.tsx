import { useState } from "react";
import type { TimelineEntry } from "../api/schema";
import { formatClock, formatSpan, NO_TIME, shortSource } from "../lib/format";
import {
  KIND_BAR,
  KIND_LABEL,
  KIND_MARK,
  KIND_SHAPE,
  sourceKind,
} from "../lib/sources";

/**
 * The incident timeline: one row per finding, in the order the API returns
 * them (by `last_seen` -- see decision 18; sorting by start time prints
 * effects above their causes).
 *
 * This is the centrepiece of the view and it has one job beyond listing
 * findings: make it obvious, without reading a word, that a single chronology
 * was assembled from more than one log source. That is the product's whole
 * claim, so it is carried by three redundant channels --
 *
 *   1. a proportional duration bar, coloured by source kind;
 *   2. a marker on the rail whose *shape* also differs (square/circle);
 *   3. the mono source label in the meta line.
 *
 * Colour alone would fail a greyscale screenshot and a colour-blind reader,
 * which for the image that goes in the README is not an acceptable risk.
 *
 * A bar rather than only a text range because findings are spans of very
 * different length -- a 22-second burst and a 14-minute chain are the same
 * width as text and obviously different as bars. The precise range stays in
 * the meta line, so nothing is traded away for the picture.
 */

/**
 * Sub-pixel spans still have to be visible, so bars have a floor. Several
 * findings here are single-instant (`first_seen == last_seen`) and would
 * otherwise render as nothing at all -- an event that did happen, drawn as
 * empty track.
 */
const MIN_BAR_PERCENT = 2.5;

function useWindow(entries: readonly TimelineEntry[]) {
  const starts = entries
    .map((e) => (e.first_seen ? Date.parse(e.first_seen) : NaN))
    .filter((n) => !Number.isNaN(n));
  const ends = entries
    .map((e) => (e.last_seen ? Date.parse(e.last_seen) : NaN))
    .filter((n) => !Number.isNaN(n));

  if (starts.length === 0 || ends.length === 0) return null;
  const from = Math.min(...starts);
  const to = Math.max(...ends);
  // An incident whose findings all share one instant has no span to scale
  // against; `span: 0` tells the caller to fall back to full-width bars rather
  // than divide by zero.
  return { from, to, span: to - from };
}

function Bar({
  entry,
  window: win,
}: {
  entry: TimelineEntry;
  window: { from: number; to: number; span: number };
}) {
  const kind = sourceKind(entry.source_type);

  if (!entry.first_seen || !entry.last_seen) {
    return (
      <div className="h-1.5 w-full rounded-full bg-hair-3" title="No timestamps" />
    );
  }

  const start = Date.parse(entry.first_seen);
  const end = Date.parse(entry.last_seen);

  const offset =
    win.span > 0 ? ((start - win.from) / win.span) * 100 : 0;
  const width =
    win.span > 0 ? Math.max(((end - start) / win.span) * 100, MIN_BAR_PERCENT) : 100;

  return (
    <div className="relative h-1.5 w-full rounded-full bg-hair-3">
      <div
        className={`absolute top-0 h-1.5 rounded-full ${KIND_BAR[kind]}`}
        style={{
          left: `${offset}%`,
          // Clamped so a finding ending at the window edge cannot overflow the
          // track by a rounding error.
          width: `${Math.min(width, 100 - offset)}%`,
        }}
      />
    </div>
  );
}

function Row({
  entry,
  window: win,
}: {
  entry: TimelineEntry;
  window: { from: number; to: number; span: number };
}) {
  const [open, setOpen] = useState(false);
  const kind = sourceKind(entry.source_type);
  const hasEvidence = entry.evidence.length > 0;

  return (
    <div className="relative border-b border-hair-4 last:border-b-0">
      {/* Source stripe down the row's leading edge. This is what makes the
          interleaving readable at a glance: scanning the left edge of the
          timeline gives a two-tone bar chart of which source each step came
          from, before any text is read. */}
      <span
        aria-hidden="true"
        className={`absolute inset-y-0 left-0 w-[3px] ${KIND_BAR[kind]}`}
      />
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        disabled={!hasEvidence}
        className="grid w-full grid-cols-[14px_176px_minmax(0,1fr)_58px_16px] items-center gap-x-3 py-2.5 pl-4 pr-3 text-left transition-colors hover:bg-raised disabled:cursor-default"
      >
        {/* Rail marker -- shape and colour both encode the source kind. */}
        <span
          aria-hidden="true"
          className={`size-2.5 ${KIND_MARK[kind]} ${KIND_SHAPE[kind]}`}
        />

        {/* 2. Proportional span within the incident window. */}
        <Bar entry={entry} window={win} />

        <span className="min-w-0">
          <span className="block truncate text-body text-ink">
            {entry.title}
          </span>
          <span className="mt-0.5 block truncate font-mono text-label text-ink-faint">
            <span className="text-ink-muted">
              {formatClock(entry.first_seen)}
              {entry.last_seen !== entry.first_seen && (
                <>
                  <span className="mx-1 text-ink-faintest">→</span>
                  {formatClock(entry.last_seen)}
                </>
              )}
            </span>
            <span className="mx-1.5 text-ink-faintest">·</span>
            {entry.technique_id ? (
              <>
                {/* Accent marks a technique reference, per DESIGN.md. Present
                    but unresolved means a stale static mapping -- shown, not
                    hidden, so it stays visible as a thing to fix. */}
                <span className="text-accent">{entry.technique_id}</span>
                <span className="ml-1.5 font-sans text-meta text-ink-faint">
                  {entry.technique_name ?? "unresolved technique"}
                </span>
              </>
            ) : (
              <span className="text-ink-faintest">no technique mapped</span>
            )}
            <span className="mx-1.5 text-ink-faintest">·</span>
            {/* Short form, matching the queue. The kind is already carried by
                the stripe and the marker, so spelling out `(cloud)` here only
                bought a truncated line. Full value stays on `title`. */}
            <span title={`${entry.source_type} (${KIND_LABEL[kind]})`}>
              {shortSource(entry.source_type)}
            </span>
          </span>
        </span>

        <span className="text-right font-mono text-meta text-ink-muted">
          {entry.evidence_count}
          <span className="ml-1 text-ink-faintest">ev</span>
        </span>

        <span className="text-right font-mono text-meta text-ink-faintest">
          {hasEvidence ? (open ? "−" : "+") : ""}
        </span>
      </button>

      {open && hasEvidence && (
        <div className="px-3 pb-3">
          <pre className="overflow-x-auto rounded-sunken bg-sunken p-3 font-mono text-label leading-[1.6] text-ink-2">
            {/* Raw lines verbatim -- attacker-controlled text is framed, never
                filtered (decision 10). `pre` means nothing here is interpreted. */}
            {entry.evidence.join("\n")}
          </pre>
        </div>
      )}
    </div>
  );
}

export function Timeline({ entries }: { entries: readonly TimelineEntry[] }) {
  const win = useWindow(entries);

  if (entries.length === 0) {
    return (
      <p className="px-3 py-6 text-meta text-ink-muted">
        This incident has no timestamped findings.
      </p>
    );
  }

  const totalSpan = win
    ? formatSpan(new Date(win.from).toISOString(), new Date(win.to).toISOString())
    : NO_TIME;

  return (
    <section>
      <div className="flex h-section-row items-center gap-3 border-b border-edge">
        <h2 className="font-mono text-label font-medium uppercase text-ink">
          Timeline
        </h2>
        <span className="font-mono text-label text-ink-faintest">
          {entries.length} findings · {totalSpan}
        </span>

        {/* Legend. Without it the two marks are a pattern; with it they are a
            statement about which sources the chronology was built from. */}
        <div className="ml-auto flex items-center gap-3">
          <span className="flex items-center gap-1.5 font-mono text-label uppercase text-ink-faint">
            <span className="size-2 rounded-[1px] bg-ink" aria-hidden="true" />
            host
          </span>
          <span className="flex items-center gap-1.5 font-mono text-label uppercase text-ink-faint">
            <span className="size-2 rounded-full bg-accent" aria-hidden="true" />
            cloud
          </span>
        </div>
      </div>

      <div className="rounded-card border border-hair-1 bg-panel">
        {win &&
          entries.map((entry, i) => (
            <Row key={`${entry.rule_id}-${i}`} entry={entry} window={win} />
          ))}
      </div>
    </section>
  );
}
