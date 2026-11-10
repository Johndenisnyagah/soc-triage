import { SectionTitle } from "./ui";

/**
 * The incident summary, with provenance attached.
 *
 * The label is the point. `enrichment_source` is the one field that says
 * whether this prose came off a deterministic code path or out of a language
 * model, and the architecture's central claim -- rules detect, AI explains --
 * is only checkable by a reader if the difference is visible on the page.
 *
 * So the three states are told apart without reading, on three channels at
 * once -- fill, edge and dot:
 *
 *   deterministic  solid inset (the app background), soft rule, grey dot
 *   llm            accent wash, accent edge, accent dot
 *   anything else  no fill, *dashed* outline, hollow dot
 *
 * An unrecognised value is neither of the first two and says so, instead of
 * defaulting into the reassuring one. All three keep their words at text-mid
 * or brighter: this label is the claim, not decoration, so the spec's
 * text-dim (3.43:1 on the inset) is not enough for it.
 */

const CHIP =
  "inline-flex items-center gap-1.5 rounded-chip border px-2 py-1 font-mono text-label font-medium uppercase";

function Label({ enrichmentSource }: { enrichmentSource: string }) {
  if (enrichmentSource === "deterministic") {
    return (
      <span className={`${CHIP} border-line-soft bg-bg-app text-text-mid`}>
        <span className="size-1.5 bg-text-dim" aria-hidden="true" />
        generated without LLM — deterministic
      </span>
    );
  }

  if (enrichmentSource === "llm") {
    return (
      <span className={`${CHIP} border-accent-hair bg-accent-wash text-accent-ink`}>
        <span className="size-1.5 bg-accent" aria-hidden="true" />
        LLM-generated — structurally validated
      </span>
    );
  }

  return (
    <span className={`${CHIP} border-dashed border-line bg-transparent text-text-mid`}>
      <span
        className="size-1.5 ring-1 ring-inset ring-text-mid"
        aria-hidden="true"
      />
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
    <section className="border border-line bg-panel p-5">
      <SectionTitle right={<Label enrichmentSource={enrichmentSource} />}>
        Summary
      </SectionTitle>

      {/* The deterministic summary is pre-formatted: it carries an indented
          timeline block whose alignment is load-bearing, so it is rendered
          with newlines preserved rather than reflowed into a paragraph. */}
      <p className="mt-4 whitespace-pre-wrap text-prose text-text-mid">{summary}</p>
    </section>
  );
}
