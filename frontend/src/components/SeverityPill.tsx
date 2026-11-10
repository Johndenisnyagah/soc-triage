import { asSeverity, SEVERITY_PILL } from "../lib/severity";

/**
 * Severity as a tinted chip: LogLens's `SeverityBadge` shape -- square, 10px
 * bold uppercase at 0.14em, 4px 8px, a 1px edge in the chip's own ink -- on
 * soc-triage's own five-rung ramp. Mono, because the value is
 * machine-assigned: it comes off the tactic-breadth ladder in `correlate()`,
 * not from a person.
 */
export function SeverityPill({
  severity,
  className = "",
}: {
  severity: string;
  className?: string;
}) {
  const known = asSeverity(severity);

  // Unknown values render verbatim and unstyled rather than being folded into
  // the lowest level -- see `asSeverity`.
  const tone = known
    ? SEVERITY_PILL[known]
    : "text-text-mid bg-transparent border-line";

  return (
    <span
      className={`inline-flex items-center rounded-chip border px-2 py-1 font-mono text-chip font-bold uppercase ${tone} ${className}`}
    >
      {severity}
    </span>
  );
}
