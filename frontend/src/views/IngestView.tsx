import { useRef, useState, type DragEvent, type ReactNode } from "react";
import { AlertCircle, ArrowRight, Check, Upload } from "lucide-react";
import { ApiError, ingestFile } from "../api/client";
import type { IngestResponse } from "../api/schema";
import { Crumb, Shell } from "../components/Shell";
import {
  Btn,
  BtnLink,
  PageHead,
  SectionTitle,
  ViewBody,
  ViewHeader,
} from "../components/ui";

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
 *
 * Styling follows LogLens's `UploadLogs`; its staged fake-progress checklist is
 * deliberately not ported. The request is one round trip, and animating steps
 * that are not happening would be a claim the app cannot back.
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

function Label({ children }: { children: ReactNode }) {
  return (
    <span className="font-mono text-label font-medium uppercase text-text-dim">
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
    <div className="flex min-w-0 flex-col gap-1.5 bg-panel px-5 py-4">
      <Label>{label}</Label>
      <span className="font-mono text-stat text-text">{value}</span>
      {note && <span className="text-meta text-text-mid">{note}</span>}
    </div>
  );
}

function Result({ result }: { result: IngestResponse }) {
  const { stats } = result;
  const allDuplicates =
    result.events_persisted === 0 && result.duplicates_skipped > 0;

  return (
    <section aria-labelledby="ingest-result" className="flex flex-col gap-3.5">
      <SectionTitle
        right={
          <span className="font-mono text-label uppercase text-text-dim">
            ingest #{result.ingest_id}
          </span>
        }
      >
        <span id="ingest-result">Result</span>
      </SectionTitle>

      <div className="flex items-center gap-3.5 border-l-2 border-success bg-panel px-5 py-3.5 text-meta text-text-mid">
        <Check className="size-4 shrink-0 text-success" strokeWidth={3} aria-hidden="true" />
        <span className="min-w-0">
          <strong className="mr-1.5 font-semibold text-text">Ingested.</strong>
          <span className="font-mono text-text">{result.filename ?? "unnamed upload"}</span>
          {" read as "}
          <span className="font-mono text-text">{result.source_type}</span>
          {" at confidence "}
          {/* Selection is by highest sniff() score (decision 2), so the number
              is the reason this file was read the way it was. */}
          <span className="font-mono text-text">
            {result.detected_confidence.toFixed(3)}
          </span>
          .
        </span>
        <BtnLink to="/" variant="primary" className="ml-auto">
          View the queue
          <ArrowRight className="size-3" strokeWidth={2.5} aria-hidden="true" />
        </BtnLink>
      </div>

      {/* Left to right is the funnel a file goes through: every line read is
          either skipped or emitted, and every emitted event is either a
          duplicate of one already stored or newly persisted. The 1px gaps
          over the line colour draw the dividers. */}
      <div className="grid grid-cols-5 gap-px border border-line bg-line">
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
        <p className="text-prose text-text-mid">
          Every event in this file was already stored. Deduplication is global,
          so re-ingesting a file adds nothing and the queue is unchanged.
        </p>
      )}

      {stats.errors.length > 0 && (
        <div className="border border-line bg-panel p-4">
          <SectionTitle as="h3" count={stats.errors.length}>
            Parse errors{stats.errors.length >= 100 ? " · capped at 100" : ""}
          </SectionTitle>
          <ul className="mt-3 flex flex-col gap-2">
            {stats.errors.map((e, i) => (
              <li
                key={`${e.line_no}-${i}`}
                className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3"
              >
                <span className="font-mono text-meta text-text-mid">
                  line {e.line_no}
                </span>
                <span className="min-w-0">
                  <span className="block text-meta text-text">{e.reason}</span>
                  {/* Log content is untrusted: framed verbatim, never
                      interpreted. */}
                  <pre className="mt-1 overflow-x-auto border border-line-soft bg-bg-app px-2.5 py-1.5 font-mono text-evidence text-text-mid">
                    {e.excerpt}
                  </pre>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
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
      className="flex flex-col gap-3 border-l-2 border-danger bg-panel px-5 py-4"
    >
      <div className="flex items-center gap-3">
        <AlertCircle className="size-4 shrink-0 text-danger" strokeWidth={2} aria-hidden="true" />
        <span className="font-mono text-label font-semibold uppercase text-danger">
          {error.status > 0 ? `Error · ${error.status}` : "Error"}
        </span>
        {typeof heading === "string" && (
          <span className="font-mono text-meta text-text">{heading}</span>
        )}
      </div>

      {/* The backend's own words, not a restatement. */}
      <p className="max-w-[72ch] text-prose text-text-mid">{error.message}</p>

      {supported && (
        <div className="flex flex-wrap items-center gap-2">
          <Label>Supported formats</Label>
          {supported.map((format) => (
            <span
              key={format}
              className="rounded-chip border border-line bg-card px-2 py-0.5 font-mono text-meta text-text"
            >
              {format}
            </span>
          ))}
        </div>
      )}

      {typeof best === "number" && typeof min === "number" && (
        <div className="flex items-baseline gap-2">
          <Label>Best confidence</Label>
          <span className="font-mono text-meta text-text">{best.toFixed(3)}</span>
          <span className="font-mono text-meta text-text-mid">needs ≥ {min}</span>
        </div>
      )}

      {typeof cap === "number" && (
        <div className="flex items-baseline gap-2">
          <Label>Upload limit</Label>
          <span className="font-mono text-meta text-text">{formatBytes(cap)}</span>
        </div>
      )}
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
      <ViewHeader>
        <PageHead
          eyebrow="Pipeline · POST /api/ingest"
          title="Ingest a log file"
          subtitle="One file per upload. The parser is chosen by content, not by file name, and anything already stored is skipped."
        />
      </ViewHeader>

      <ViewBody>
        <div className="flex flex-col gap-3.5">
          {/* The whole zone is the file picker's label, so a click anywhere
              opens the dialog and the hidden input stays keyboard-reachable. */}
          <label
            onDragOver={(event) => {
              event.preventDefault();
              if (!uploading) setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`flex items-center gap-5 border border-dashed px-8 py-7 transition-colors has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent-ink ${
              dragging
                ? "border-accent bg-accent-wash"
                : "border-line bg-panel hover:border-accent"
            } ${uploading ? "cursor-default opacity-60" : "cursor-pointer"}`}
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
              className="flex size-14 shrink-0 items-center justify-center bg-accent text-on-accent"
            >
              <Upload className="size-6" strokeWidth={1.8} />
            </span>
            <span className="flex min-w-0 flex-col gap-1.5">
              <span className="truncate text-[16px] font-semibold tracking-[-0.01em] text-text">
                {file ? file.name : "Drop a log file here, or click to choose one"}
              </span>
              <span className="text-meta text-text-mid">
                {file
                  ? `${formatBytes(file.size)} · click or drop to replace`
                  : "sshd syslog, Windows Security event XML, or AWS CloudTrail JSON"}
              </span>
            </span>
          </label>

          <div className="flex flex-wrap items-end gap-5 border border-line bg-panel px-5 py-4">
            <label className="flex flex-col gap-1.5">
              <Label>Syslog year · optional</Label>
              <input
                type="number"
                inputMode="numeric"
                value={year}
                onChange={(event) => setYear(event.target.value)}
                placeholder={String(new Date().getUTCFullYear())}
                disabled={uploading}
                aria-invalid={!yearValid}
                className="h-control w-[120px] rounded-control border border-line bg-bg-app px-2 font-mono text-meta text-text placeholder:text-text-dim focus:border-accent focus:outline-none aria-invalid:border-danger"
              />
            </label>
            <p className="max-w-[52ch] pb-1 text-meta text-text-mid">
              Syslog lines carry no year. Left blank, the server assumes the
              current one; the bundled samples describe 2026.
            </p>
            <Btn
              variant="primary"
              onClick={submit}
              disabled={!file || uploading || !yearValid}
              className="ml-auto"
            >
              {uploading ? "Ingesting…" : "Ingest"}
            </Btn>
          </div>
        </div>

        <div aria-live="polite" className="empty:hidden">
          {phase.state === "uploading" && (
            <p className="font-mono text-label font-medium uppercase text-text-dim">
              Parsing {phase.file.name} · {formatBytes(phase.file.size)}
            </p>
          )}
          {phase.state === "done" && <Result result={phase.result} />}
          {phase.state === "error" && <Failure error={phase.error} />}
        </div>

        {/* A cold visitor needs something to drop in. */}
        <section className="flex flex-col gap-3.5">
          <SectionTitle>Sample files</SectionTitle>
          <p className="max-w-[80ch] text-prose text-text-mid">
            The repository commits three sample logs under{" "}
            <span className="font-mono text-text">sample_logs/</span>
            {": "}
            {SAMPLE_FILES.map((name, i) => (
              <span key={name}>
                {i > 0 && (i === SAMPLE_FILES.length - 1 ? " and " : ", ")}
                <span className="font-mono text-text">{name}</span>
              </span>
            ))}
            . Together the first two hold one attacker moving between a Linux
            host and an AWS account, which correlates into a single incident,
            and an unrelated SSH brute force that correlation keeps apart. The
            third is a separate intrusion on a Windows workstation.
          </p>
        </section>
      </ViewBody>
    </Shell>
  );
}
