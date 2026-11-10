import type { ReactNode } from "react";
import { AlertCircle, ArrowRight } from "lucide-react";
import type { ApiError } from "../api/client";
import { Btn, BtnLink } from "./ui";

/**
 * Loading, error and empty states.
 *
 * The empty case is the one that has to be got right. A security queue with
 * nothing in it is the *good* outcome, and a blank panel is indistinguishable
 * from a view that failed to render -- so "no incidents" is stated in words,
 * with the reason, and it never borrows the error styling.
 *
 * Square, like everything else. LogLens's own `EmptyState` is `rounded-2xl`;
 * that is one of its inconsistencies, not part of its language.
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
    <p className="font-mono text-label font-medium uppercase text-text-dim">
      {children}
    </p>
  );
}

function Note({ children }: { children: ReactNode }) {
  return (
    <p className="max-w-[46ch] text-meta leading-relaxed text-text-mid">
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
          className="flex h-9 items-center gap-4 border-b border-line-soft px-5 last:border-b-0"
        >
          <div className="h-3 w-14 bg-skeleton" />
          <div className="h-3 w-24 bg-skeleton" />
          <div className="h-3 flex-1 bg-skeleton" />
          <div className="h-3 w-16 bg-skeleton" />
          <div className="h-3 w-20 bg-skeleton" />
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
      <span
        aria-hidden="true"
        className="mb-1 flex size-9 items-center justify-center bg-danger-tint text-danger"
      >
        <AlertCircle className="size-[18px]" strokeWidth={2} />
      </span>
      <Label>
        {error.status > 0 ? `Error · ${error.status}` : "Error"}
      </Label>
      <Note>{error.message}</Note>
      {onRetry && (
        <Btn onClick={onRetry} className="mt-2">
          Try again
        </Btn>
      )}
    </Frame>
  );
}

/**
 * Nothing detected at all. Deliberately worded as a finding about the data
 * rather than as an apology about the page -- and it carries the way forward,
 * not just a description of it: without the button a first visitor would
 * have to leave for a terminal to see anything at all.
 */
export function EmptyQueue() {
  return (
    <Frame>
      <Label>No incidents</Label>
      <Note>
        No events currently stored correlate into an incident. Ingest a log file
        through <span className="font-mono text-text">POST /api/ingest</span> to
        populate the queue.
      </Note>
      <BtnLink to="/ingest" variant="primary" className="mt-3">
        Ingest a log file
        <ArrowRight className="size-3" strokeWidth={2.5} aria-hidden="true" />
      </BtnLink>
    </Frame>
  );
}

/** Incidents exist, but none match the active severity or search. */
export function NoMatches({ onClear }: { onClear: () => void }) {
  return (
    <Frame>
      <Label>No matches</Label>
      <Note>Nothing matches that filter.</Note>
      <Btn onClick={onClear} className="mt-2">
        Clear filters
      </Btn>
    </Frame>
  );
}
