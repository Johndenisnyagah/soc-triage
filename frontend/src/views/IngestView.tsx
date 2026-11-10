import { useRef, useState, type DragEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { ApiError, ingestFile } from "../api/client";
import type { IngestResponse } from "../api/schema";
import { Crumb, Shell } from "../components/Shell";
import { pluralize } from "../lib/format";

/**
 * Ingest: the front door for `POST /api/ingest`.
 *
 * Without this view the only way to populate an empty queue was to issue the
 * HTTP request by hand. Everything shown after an upload is a field of the
 * endpoint's own `IngestResponse` -- the parse funnel (lines read, skipped,
 * events emitted, duplicates, persisted) is the parser registry's confidence
 * scoring and the global dedup made visible, so it is laid out rather than
 * collapsed into "uploaded".
 *
 * Nothing here decides what a file is. The parser is picked server-side by
 * content (`sniff()`), so there is no extension allow-list; an unrecognised
 * file comes back as a 422 and the backend's own explanation is shown as-is.
 */

type Phase =
  | { state: "idle" }
  | { state: "uploading"; file: File }
  | { state: "done"; file: File; result: IngestResponse }
  | { state: "error"; file: File; error: ApiError };

const SAMPLE_FILES = ["auth.log", "cloudtrail.json", "windows_security.xml"];

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function stringList(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((v) => typeof v === "string")
    ? value
    : null;
}

function field(detail: unknown, key: string): unknown {
  return detail && typeof detail === "object" && key in detail
    ? (detail as Record<string, unknown>)[key]
    : undefined;
}

function SectionHeader({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-section-row items-center gap-3 border-b border-edge">
      {children}
    </div>
  );
}

function Label({ children }: { children: ReactNode }) {
  return (
    <span className="font-mono text-label font-medium uppercase text-ink-faintest">
      {children}
    </span>
  );
}

function Stat({
  label,
  value,
  note,
}: {
  label: string;
  value: ReactNode;
  note?: ReactNode;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1 border-r border-hair-1 px-4 py-3 last:border-r-0">
      <Label>{label}</Label>
      <span className="font-mono text-stat text-ink">{value}</span>
      {note && <span className="text-meta text-ink-faint">{note}</span>}
    </div>
  );
}

function Result({ result }: { result: IngestResponse }) {
  const { stats } = result;
  const allDuplicates =
    result.events_persisted === 0 && result.duplicates_skipped > 0;

  return (
    <section aria-labelledby="ingest-result" className="mt-6">
      <SectionHeader>
        <h2
          id="ingest-result"
          className="font-mono text-label font-medium uppercase text-ink"
        >
          Ingested
        </h2>
        <span className="truncate font-mono text-meta text-ink-2">
          {result.filename ?? "unnamed upload"}
        </span>
        <span className="ml-auto font-mono text-label font-medium uppercase text-ink-faintest">
          ingest #{result.ingest_id}
        </span>
      </SectionHeader>

      {/* Which parser won, and by how much. Selection is by highest sniff()
          score (decision 2), so the number is the reason this file was read
          the way it was. */}
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1 border-b border-hair-4 px-4 py-3">
        <span className="flex items-baseline gap-2">
          <Label>Detected source</Label>
          <span className="font-mono text-body text-ink">
            {result.source_type}
          </span>
        </span>
        <span className="flex items-baseline gap-2">
          <Label>Confidence</Label>
          <span className="font-mono text-body text-ink">
            {result.detected_confidence.toFixed(3)}
          </span>
        </span>
      </div>

      {/* Left to right is the funnel a file goes through: every line read is
          either skipped or emitted, and every emitted event is either a
          duplicate of one already stored or newly persisted. */}
      <div className="grid grid-cols-5 border-b border-hair-1">
        <Stat label="Lines read" value={stats.lines_read} />
        <Stat
          label="Lines skipped"
          value={stats.lines_skipped}
          note="recognised, not modelled"
        />
        <Stat label="Events emitted" value={stats.events_emitted} />
        <Stat
          label="Duplicates skipped"
          value={result.duplicates_skipped}
          note="already stored"
        />
        <Stat label="Events persisted" value={result.events_persisted} />
      </div>

      {allDuplicates && (
        <p className="border-b border-hair-4 px-4 py-3 text-prose text-ink-muted">
          Every event in this file was already stored. Deduplication is global,
          so re-ingesting a file adds nothing and the queue is unchanged.
        </p>
      )}

      {stats.errors.length > 0 && (
        <div className="border-b border-hair-4 px-4 py-3">
          <Label>
            Parse errors · {stats.errors.length}
            {stats.errors.length >= 100 ? " (capped at 100)" : ""}
          </Label>
          <ul className="mt-2 flex flex-col gap-1.5">
            {stats.errors.map((e, i) => (
              <li
                key={`${e.line_no}-${i}`}
                className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3"
              >
                <span className="font-mono text-meta text-ink-faint">
                  line {e.line_no}
                </span>
                <span className="min-w-0">
                  <span className="block text-meta text-ink-2">{e.reason}</span>
                  {/* Log content is untrusted: framed verbatim, never
                      interpreted. */}
                  <pre className="mt-0.5 overflow-x-auto rounded-chip bg-sunken px-2 py-1 font-mono text-label text-ink-muted">
                    {e.excerpt}
                  </pre>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex items-center gap-3 px-4 pt-4">
        <Link
          to="/"
          className="inline-flex h-[26px] items-center rounded-control border border-accent bg-accent px-3 text-meta font-medium text-raised transition-colors hover:border-accent-hover hover:bg-accent-hover"
        >
          View the queue →
        </Link>
        <span className="text-meta text-ink-faint">
          Incidents are recomputed from every stored event on each read.
        </span>
      </div>
    </section>
  );
}

function Failure({ error }: { error: ApiError }) {
  const detail = error.detail;
  const supported =
    error.status === 422 ? stringList(field(detail, "supported_formats")) : null;
  const best = field(detail, "best_confidence");
  const min = field(detail, "min_confidence");
  const cap = field(detail, "max_upload_bytes");
  const heading = field(detail, "error");

  return (
    <section
      role="alert"
      className="mt-6 rounded-card border border-sev-critical-fill bg-raised"
    >
      <div className="flex items-center gap-3 border-b border-hair-4 px-4 py-2.5">
        <span className="rounded-chip bg-sev-critical-fill px-1.5 py-[2px] font-mono text-label font-medium uppercase text-sev-critical">
          {error.status > 0 ? `Error · ${error.status}` : "Error"}
        </span>
        {typeof heading === "string" && (
          <span className="font-mono text-meta text-ink-2">{heading}</span>
        )}
      </div>
      <div className="flex flex-col gap-3 px-4 py-3">
        {/* The backend's own words, not a restatement. */}
        <p className="max-w-[72ch] text-prose text-ink-2">{error.message}</p>

        {supported && (
          <div className="flex flex-wrap items-baseline gap-2">
            <Label>Supported formats</Label>
            {supported.map((format) => (
              <span
                key={format}
                className="rounded-chip border border-edge bg-sunken px-1.5 py-[1px] font-mono text-meta text-ink-2"
              >
                {format}
              </span>
            ))}
          </div>
        )}

        {typeof best === "number" && typeof min === "number" && (
          <div className="flex items-baseline gap-2">
            <Label>Best confidence</Label>
            <span className="font-mono text-meta text-ink-2">
              {best.toFixed(3)}
            </span>
            <span className="font-mono text-meta text-ink-faint">
              needs ≥ {min}
            </span>
          </div>
        )}

        {typeof cap === "number" && (
          <div className="flex items-baseline gap-2">
            <Label>Upload limit</Label>
            <span className="font-mono text-meta text-ink-2">
              {formatBytes(cap)}
            </span>
          </div>
        )}
      </div>
    </section>
  );
}

export function IngestView() {
  const [file, setFile] = useState<File | null>(null);
  const [year, setYear] = useState("");
  const [dragging, setDragging] = useState(false);
  const [phase, setPhase] = useState<Phase>({ state: "idle" });
  const inputRef = useRef<HTMLInputElement>(null);

  const uploading = phase.state === "uploading";
  const yearValue = year.trim() === "" ? null : Number(year);
  const yearValid =
    yearValue === null || (Number.isInteger(yearValue) && yearValue > 0);

  function choose(next: File | undefined) {
    if (!next || uploading) return;
    setFile(next);
    setPhase({ state: "idle" });
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    // One file per upload, matching the endpoint; extras are ignored.
    choose(event.dataTransfer.files[0]);
  }

  async function submit() {
    if (!file || uploading || !yearValid) return;
    setPhase({ state: "uploading", file });
    try {
      const result = await ingestFile(file, yearValue);
      setPhase({ state: "done", file, result });
    } catch (cause) {
      setPhase({
        state: "error",
        file,
        error:
          cause instanceof ApiError
            ? cause
            : new ApiError(0, "Something went wrong uploading this file."),
      });
    }
    // Clear the picker so choosing the same file again still fires onChange.
    if (inputRef.current) inputRef.current.value = "";
  }

  return (
    <Shell
      breadcrumb={
        <>
          <Crumb muted>Pipeline</Crumb>
          <Crumb muted>/</Crumb>
          <Crumb>Ingest a log file</Crumb>
        </>
      }
    >
      <div className="px-10 pb-10 pt-6">
        <SectionHeader>
          <h1 className="font-mono text-label font-medium uppercase text-ink">
            Ingest
          </h1>
          <span className="text-meta text-ink-faint">
            One file per upload. The parser is chosen by content, not by file
            name.
          </span>
        </SectionHeader>

        {/* The whole zone is the file picker's label, so a click anywhere opens
            the dialog and the hidden input stays keyboard-reachable. */}
        <label
          onDragOver={(event) => {
            event.preventDefault();
            if (!uploading) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={`mt-6 flex cursor-pointer items-center gap-5 rounded-card border border-dashed px-6 py-6 transition-colors has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent ${
            dragging
              ? "border-accent bg-accent-tint"
              : "border-edge bg-raised hover:border-ink-faint"
          } ${uploading ? "cursor-default opacity-60" : ""}`}
        >
          <input
            ref={inputRef}
            type="file"
            className="sr-only"
            disabled={uploading}
            onChange={(event) => choose(event.target.files?.[0])}
          />
          <span
            aria-hidden="true"
            className="flex size-11 shrink-0 items-center justify-center rounded-control bg-ink text-raised"
          >
            <svg
              viewBox="0 0 24 24"
              className="size-5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 4v10M8 10l4 4 4-4" />
              <path d="M4 14v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4" />
            </svg>
          </span>
          <span className="flex min-w-0 flex-col gap-1">
            <span className="truncate text-body font-medium text-ink">
              {file ? file.name : "Drop a log file here, or click to choose one"}
            </span>
            <span className="text-meta text-ink-faint">
              {file
                ? `${formatBytes(file.size)} · click or drop to replace`
                : "sshd syslog, Windows Security event XML, or AWS CloudTrail JSON"}
            </span>
          </span>
        </label>

        <div className="mt-4 flex flex-wrap items-end gap-4">
          <label className="flex flex-col gap-1">
            <Label>Syslog year · optional</Label>
            <input
              type="number"
              inputMode="numeric"
              value={year}
              onChange={(event) => setYear(event.target.value)}
              placeholder={String(new Date().getUTCFullYear())}
              disabled={uploading}
              aria-invalid={!yearValid}
              className="h-control w-[120px] rounded-control border border-edge bg-raised px-2 font-mono text-meta text-ink placeholder:text-ink-faint focus:border-ink focus:outline-none aria-invalid:border-sev-critical"
            />
          </label>
          <p className="max-w-[52ch] pb-1 text-meta text-ink-faint">
            Syslog lines carry no year. Left blank, the server assumes the
            current one; the bundled samples describe 2026.
          </p>
          <button
            type="button"
            onClick={submit}
            disabled={!file || uploading || !yearValid}
            className="ml-auto inline-flex h-[26px] items-center rounded-control border border-accent bg-accent px-3 text-meta font-medium text-raised transition-colors hover:border-accent-hover hover:bg-accent-hover disabled:cursor-not-allowed disabled:border-edge disabled:bg-sunken disabled:text-ink-faint"
          >
            {uploading ? "Ingesting…" : "Ingest"}
          </button>
        </div>

        <div aria-live="polite">
          {phase.state === "uploading" && (
            <p className="mt-6 border-t border-hair-4 px-4 pt-3 font-mono text-label font-medium uppercase text-ink-faintest">
              Parsing {phase.file.name} · {formatBytes(phase.file.size)}
            </p>
          )}
          {phase.state === "done" && <Result result={phase.result} />}
          {phase.state === "error" && <Failure error={phase.error} />}
        </div>

        {/* A cold visitor needs something to drop in. */}
        <div className="mt-10 border-t border-hair-1 pt-4">
          <Label>Sample files</Label>
          <p className="mt-2 max-w-[80ch] text-prose text-ink-muted">
            The repository commits {pluralize(SAMPLE_FILES.length, "sample log")}{" "}
            under <span className="font-mono text-ink-2">sample_logs/</span>
            {": "}
            {SAMPLE_FILES.map((name, i) => (
              <span key={name}>
                {i > 0 && (i === SAMPLE_FILES.length - 1 ? " and " : ", ")}
                <span className="font-mono text-ink-2">{name}</span>
              </span>
            ))}
            . The first two describe one attacker moving between a Linux host
            and an AWS account, and correlate into a single incident; the third
            is a separate intrusion on a Windows workstation.
          </p>
        </div>
      </div>
    </Shell>
  );
}
