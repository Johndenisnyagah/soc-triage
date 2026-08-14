import type { ReactNode } from "react";
import type { ApiError } from "../api/client";

/**
 * Loading, error and empty states.
 *
 * The empty case is the one that has to be got right. A security queue with
 * nothing in it is the *good* outcome, and a blank panel is indistinguishable
 * from a view that failed to render -- so "no incidents" is stated in words,
 * with the reason, and it never borrows the error styling.
 */

function Frame({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-[220px] flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      {children}
    </div>
  );
}

function Label({ children }: { children: ReactNode }) {
  return (
    <p className="font-mono text-label font-medium uppercase text-ink-faintest">
      {children}
    </p>
  );
}

function Note({ children }: { children: ReactNode }) {
  return (
    <p className="max-w-[46ch] text-meta leading-relaxed text-ink-muted">
      {children}
    </p>
  );
}

/** Skeleton rows: they hold the table's geometry so the page does not jump. */
export function LoadingRows({ rows = 6 }: { rows?: number }) {
  return (
    <div aria-busy="true" aria-live="polite">
      <span className="sr-only">Loading incidents</span>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="flex h-9 items-center gap-4 border-b border-hair-4 px-4"
        >
          <div className="h-3 w-14 rounded-chip bg-hair-2" />
          <div className="h-3 w-24 rounded-chip bg-hair-3" />
          <div className="h-3 flex-1 rounded-chip bg-hair-3" />
          <div className="h-3 w-16 rounded-chip bg-hair-3" />
          <div className="h-3 w-20 rounded-chip bg-hair-3" />
        </div>
      ))}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  error: ApiError;
  onRetry?: () => void;
}) {
  return (
    <Frame>
      <Label>
        {error.status > 0 ? `Error · ${error.status}` : "Error"}
      </Label>
      <Note>{error.message}</Note>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-2 h-[26px] rounded-control border border-edge bg-raised px-3 text-meta text-ink transition-colors hover:border-ink"
        >
          Try again
        </button>
      )}
    </Frame>
  );
}

/**
 * Nothing detected at all. Deliberately worded as a finding about the data
 * rather than as an apology about the page.
 */
export function EmptyQueue() {
  return (
    <Frame>
      <Label>No incidents</Label>
      <Note>
        No events currently stored correlate into an incident. Ingest a log file
        through <span className="font-mono text-ink-2">POST /api/ingest</span> to
        populate the queue.
      </Note>
    </Frame>
  );
}

/** Incidents exist, but none match the active severity or search. */
export function NoMatches({ onClear }: { onClear: () => void }) {
  return (
    <Frame>
      <Label>No matches</Label>
      <Note>Nothing matches that filter.</Note>
      <button
        type="button"
        onClick={onClear}
        className="mt-2 h-[26px] rounded-control border border-edge bg-raised px-3 text-meta text-ink transition-colors hover:border-ink"
      >
        Clear filters
      </button>
    </Frame>
  );
}
