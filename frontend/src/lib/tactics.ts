/**
 * Short labels for ATT&CK tactics.
 *
 * The queue's tactics column is ~190px. Full names ("credential access,
 * defense impairment, ...") overflow it and get clipped mid-word, which tells
 * an analyst strictly less than the count sitting next to it already does.
 * Abbreviating means the labels actually fit, so the column carries *which*
 * tactics rather than just how many.
 *
 * The vocabulary is closed -- 15 tactics across the whole catalog -- so every
 * one is mapped explicitly and no abbreviation is invented at runtime. A
 * release that adds a tactic falls back to the raw name: too long for the
 * column and visibly odd, which is the correct failure. Silently truncating it
 * would hide the fact that the map needs updating.
 */
const SHORT: Record<string, string> = {
  collection: "collection",
  "command-and-control": "c2",
  "credential-access": "cred-access",
  "defense-impairment": "defense-imp",
  discovery: "discovery",
  execution: "execution",
  exfiltration: "exfil",
  impact: "impact",
  "initial-access": "init-access",
  "lateral-movement": "lateral-move",
  persistence: "persist",
  "privilege-escalation": "privesc",
  reconnaissance: "recon",
  "resource-development": "resource-dev",
  stealth: "stealth",
};

/** How many labels fit before the column would clip. */
const VISIBLE = 2;

export function shortTactic(tactic: string): string {
  return SHORT[tactic] ?? tactic;
}

/**
 * The tactics cell: up to two short labels, then `+n` for the remainder.
 *
 * `title` carries the full unabbreviated list, so nothing is actually lost --
 * the abbreviation is a display concern and the real names stay one hover away.
 */
export function summarizeTactics(tactics: readonly string[]): {
  label: string;
  title: string;
} {
  const shown = tactics.slice(0, VISIBLE).map(shortTactic);
  const extra = tactics.length - shown.length;
  return {
    label: shown.join(" · ") + (extra > 0 ? ` +${extra}` : ""),
    title: tactics.join(", "),
  };
}
