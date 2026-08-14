/**
 * Source classification for the timeline's at-a-glance read.
 *
 * The timeline's whole job is to show one chronology assembled from several
 * log sources, so the source of a finding has to be legible without reading
 * any text. That distinction is drawn on **host vs cloud control plane**,
 * not on the specific parser.
 *
 * Keying it to the axis rather than to `syslog_sshd` / `aws_cloudtrail`
 * matters for what comes next: the planned Windows Security parser is another
 * host source and should join the host lane rather than demand a third
 * treatment. Two marks stay two marks, and the weave keeps reading.
 *
 * Marks differ in **shape as well as colour**, so the interleaving survives
 * greyscale, a colour-blind reader, and a compressed README screenshot.
 */

export type SourceKind = "host" | "cloud" | "other";

const HOST = new Set(["syslog_sshd", "windows_security"]);
const CLOUD = new Set(["aws_cloudtrail"]);

export function sourceKind(sourceType: string): SourceKind {
  if (HOST.has(sourceType)) return "host";
  if (CLOUD.has(sourceType)) return "cloud";
  // An unrecognised source gets its own neutral mark rather than being folded
  // into "host" -- a new parser should look unfamiliar until it is classified,
  // not quietly adopt a lane it may not belong in.
  return "other";
}

/** Fill for the duration bar. */
export const KIND_BAR: Record<SourceKind, string> = {
  host: "bg-ink/65",
  cloud: "bg-accent",
  other: "bg-ink-faint/60",
};

/** Marker colour on the rail. */
export const KIND_MARK: Record<SourceKind, string> = {
  host: "bg-ink",
  cloud: "bg-accent",
  other: "bg-ink-faint",
};

/**
 * Marker shape. Square = host, circle = cloud, hollow = unclassified.
 * Shape is the redundant channel that keeps colour from being load-bearing.
 */
export const KIND_SHAPE: Record<SourceKind, string> = {
  host: "rounded-[1px]",
  cloud: "rounded-full",
  other: "rounded-full ring-1 ring-inset ring-ink-faint bg-transparent!",
};

export const KIND_LABEL: Record<SourceKind, string> = {
  host: "host",
  cloud: "cloud",
  other: "other",
};
