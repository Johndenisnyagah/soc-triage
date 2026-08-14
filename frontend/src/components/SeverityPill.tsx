import { asSeverity, SEVERITY_PILL } from "../lib/severity";

/**
 * Severity as a tinted pill. Mono, because the value is machine-assigned --
 * it comes off the tactic-breadth ladder in `correlate()`, not from a person.
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
    : "text-ink-muted bg-hair-4 border border-edge";

  return (
    <span
      className={`inline-flex items-center rounded-pill px-1.5 py-[3px] font-mono text-label font-medium uppercase ${tone} ${className}`}
    >
      {severity}
    </span>
  );
}
