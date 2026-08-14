/**
 * Timestamp and count formatting.
 *
 * Everything here renders in **UTC**, never the viewer's locale. The logs are
 * UTC, the deterministic summary says UTC, and an analyst correlating a queue
 * row against a raw log line cannot be silently handed a local-time offset --
 * two clocks in one workflow is a paging-at-3am kind of bug. `timeZone: "UTC"`
 * is therefore on every formatter below, not a default anyone can drift off.
 */

const DATE = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

const CLOCK = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
  timeZone: "UTC",
});

const SHORT_CLOCK = new Intl.DateTimeFormat("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
});

/** Placeholder for a null timestamp -- a finding with no timestamped evidence. */
export const NO_TIME = "--";

function parse(iso: string | null): Date | null {
  if (!iso) return null;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** `12 Aug 2026` */
export function formatDate(iso: string | null): string {
  const date = parse(iso);
  return date ? DATE.format(date) : NO_TIME;
}

/** `04:56:02` */
export function formatClock(iso: string | null): string {
  const date = parse(iso);
  return date ? CLOCK.format(date) : NO_TIME;
}

/** `04:56` -- the dense-row form. */
export function formatShortClock(iso: string | null): string {
  const date = parse(iso);
  return date ? SHORT_CLOCK.format(date) : NO_TIME;
}

/**
 * `14m 55s`. Two units at most: an analyst scanning a queue needs the
 * magnitude, and `4h 12m 09s` costs a column's worth of width to say it.
 */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return NO_TIME;

  const totalSeconds = Math.round(ms / 1000);
  const seconds = totalSeconds % 60;
  const minutes = Math.floor(totalSeconds / 60) % 60;
  const hours = Math.floor(totalSeconds / 3600) % 24;
  const days = Math.floor(totalSeconds / 86400);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  return `${seconds}s`;
}

/** Span between two timestamps, or `--` if either is missing. */
export function formatSpan(
  first: string | null,
  last: string | null,
): string {
  const start = parse(first);
  const end = parse(last);
  if (!start || !end) return NO_TIME;
  return formatDuration(end.getTime() - start.getTime());
}

/**
 * `12 Aug 2026 · 04:41:07 → 04:56:02 UTC` -- the full form from DESIGN.md.
 * Collapses to a single clock time when the window has no duration.
 */
export function formatWindow(
  first: string | null,
  last: string | null,
): string {
  const start = parse(first);
  const end = parse(last);
  if (!start && !end) return NO_TIME;
  if (!start || !end) {
    const only = (start ?? end) as Date;
    return `${DATE.format(only)} · ${CLOCK.format(only)} UTC`;
  }

  const head = `${DATE.format(start)} · ${CLOCK.format(start)}`;
  if (start.getTime() === end.getTime()) return `${head} UTC`;

  // Same UTC day: the date is already stated, so only the clock repeats.
  const sameDay = DATE.format(start) === DATE.format(end);
  const tail = sameDay
    ? CLOCK.format(end)
    : `${DATE.format(end)} · ${CLOCK.format(end)}`;
  return `${head} → ${tail} UTC`;
}

/** `1 finding` / `6 findings` -- singular matters in a dense column. */
export function pluralize(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

/**
 * `syslog_sshd` -> `sshd`, `aws_cloudtrail` -> `cloudtrail`.
 *
 * Cosmetic only, and deliberately reversible by eye: the queue is tight on
 * width and the vendor prefixes carry no information the row needs. The full
 * `source_type` is what the detail view and the raw evidence show.
 */
export function shortSource(sourceType: string): string {
  return sourceType.replace(/^(syslog|aws|windows)_/, "");
}

/** `credential-access` -> `credential access`, for prose contexts. */
export function humanizeTactic(tactic: string): string {
  return tactic.replace(/-/g, " ");
}
