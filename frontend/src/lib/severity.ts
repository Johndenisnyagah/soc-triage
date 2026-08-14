import type { SeverityName } from "../api/schema";

/**
 * Severity presentation.
 *
 * `SeverityName` is generated from the backend's `StrEnum`, so adding a level
 * server-side turns every map below into a TypeScript error until it is
 * handled here -- which is the point. A `Record<SeverityName, ...>` that
 * silently fell back to grey would render a new level as if it were noise.
 */

/** Worst first, matching the queue's own ordering. */
export const SEVERITY_ORDER: readonly SeverityName[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
] as const;

/** Filter-pill labels. Abbreviated to keep the pill row on one line. */
export const SEVERITY_ABBREV: Record<SeverityName, string> = {
  CRITICAL: "CRIT",
  HIGH: "HIGH",
  MEDIUM: "MED",
  LOW: "LOW",
  INFO: "INFO",
};

/**
 * Severity is text colour plus a tinted pill, never a filled row (DESIGN.md).
 * A row-level fill would turn the queue into stripes of colour and destroy the
 * scan down the entity column.
 *
 * Each fill is its own colour rather than the ink at low opacity. Opacity
 * tints keep every rung inside one hue family, which is what collapsed
 * MEDIUM/LOW/INFO into a single warm smear -- and the smear lands precisely on
 * the three levels an analyst most needs to tell apart at a glance.
 */
export const SEVERITY_PILL: Record<SeverityName, string> = {
  CRITICAL: "text-sev-critical bg-sev-critical-fill",
  HIGH: "text-sev-high bg-sev-high-fill",
  MEDIUM: "text-sev-medium bg-sev-medium-fill",
  LOW: "text-sev-low bg-sev-low-fill",
  INFO: "text-sev-info bg-sev-info-fill",
};

export const SEVERITY_TEXT: Record<SeverityName, string> = {
  CRITICAL: "text-sev-critical",
  HIGH: "text-sev-high",
  MEDIUM: "text-sev-medium",
  LOW: "text-sev-low",
  INFO: "text-sev-info",
};

const KNOWN = new Set<string>(SEVERITY_ORDER);

/**
 * Narrow the API's `severity: string` to a `SeverityName`.
 *
 * The response models type this field as a plain string (only the query
 * parameter is the enum), so the boundary has to be checked rather than cast.
 * An unrecognised value returns null and the caller renders it verbatim in
 * mono -- visibly unstyled, which beats mapping it onto INFO and understating
 * something the backend considered worth reporting.
 */
export function asSeverity(value: string): SeverityName | null {
  return KNOWN.has(value) ? (value as SeverityName) : null;
}
