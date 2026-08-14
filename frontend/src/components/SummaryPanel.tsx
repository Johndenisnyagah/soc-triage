/**
 * The incident summary, with provenance attached.
 *
 * The label is the point. `enrichment_source` is the one field that says
 * whether this prose came off a deterministic code path or out of a language
 * model, and the architecture's central claim -- rules detect, AI explains --
 * is only checkable by a reader if the difference is visible on the page.
 *
 * So the two states are styled to be told apart at a glance rather than by
 * reading the words: deterministic is quiet and neutral, LLM is accent-tinted
 * and explicitly marked as validated-but-generated. An unrecognised value is
 * neither, and says so, instead of defaulting into the reassuring one.
 */

function Label({ enrichmentSource }: { enrichmentSource: string }) {
  if (enrichmentSource === "deterministic") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-chip border border-hair-1 bg-sunken px-1.5 py-[3px] font-mono text-label font-medium uppercase text-ink-faint">
        <span className="size-1.5 rounded-full bg-ink-faint" aria-hidden="true" />
        generated without LLM — deterministic
      </span>
    );
  }

  if (enrichmentSource === "llm") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-chip border border-accent-hair bg-accent-tint px-1.5 py-[3px] font-mono text-label font-medium uppercase text-accent">
        <span className="size-1.5 rounded-full bg-accent" aria-hidden="true" />
        LLM-generated — structurally validated
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 rounded-chip border border-edge bg-raised px-1.5 py-[3px] font-mono text-label font-medium uppercase text-ink-muted">
      <span className="size-1.5 rounded-full bg-ink-muted" aria-hidden="true" />
      unknown source — {enrichmentSource}
    </span>
  );
}

export function SummaryPanel({
  summary,
  enrichmentSource,
}: {
  summary: string;
  enrichmentSource: string;
}) {
  return (
    <section className="rounded-card border border-hair-1 bg-raised p-4">
      <div className="flex items-center justify-between gap-3">
        <h2 className="font-mono text-label font-medium uppercase text-ink">
          Summary
        </h2>
        <Label enrichmentSource={enrichmentSource} />
      </div>

      {/* The deterministic summary is pre-formatted: it carries an indented
          timeline block whose alignment is load-bearing, so it is rendered
          with newlines preserved rather than reflowed into a paragraph. */}
      <p className="mt-3 whitespace-pre-wrap text-prose text-ink-2">{summary}</p>
    </section>
  );
}
