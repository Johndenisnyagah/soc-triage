import { useCallback, useEffect, useRef, useState } from "react";
import type { IncidentDetail, IncidentSummary, SeverityName } from "./schema";

/**
 * An HTTP failure carrying whatever the backend was willing to say about it.
 *
 * The incident endpoints return structured detail on 404 (`{error, message,
 * incident_id}`) and a list on 422, and that prose is more useful to an analyst
 * than "Request failed" -- a stale bookmark should explain that incidents are
 * recomputed from stored events, not just show a status code.
 */
export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function messageFromBody(status: number, body: unknown): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;

    if (typeof detail === "string") return detail;

    // 404 from the incident endpoints.
    if (detail && typeof detail === "object" && "message" in detail) {
      const message = (detail as { message: unknown }).message;
      if (typeof message === "string") return message;
    }

    // 422 validation errors.
    if (Array.isArray(detail)) {
      const parts = detail
        .map((item) =>
          item && typeof item === "object" && "msg" in item
            ? String((item as { msg: unknown }).msg)
            : null,
        )
        .filter((part): part is string => part !== null);
      if (parts.length > 0) return parts.join("; ");
    }
  }
  return `Request failed with status ${status}.`;
}

async function getJson<T>(path: string, signal: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      signal,
      headers: { Accept: "application/json" },
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    // Distinguished from an HTTP error on purpose: the usual cause in dev is
    // the API not running, and "status 0" would send someone hunting the wrong
    // problem.
    throw new ApiError(
      0,
      "Could not reach the API. Is the backend running on localhost:8000?",
    );
  }

  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      // Non-JSON error body (a proxy 502, say) -- fall through to the default.
    }
    throw new ApiError(response.status, messageFromBody(response.status, body));
  }

  return (await response.json()) as T;
}

export function fetchIncidents(
  severity: SeverityName | null,
  signal: AbortSignal,
): Promise<IncidentSummary[]> {
  // Server-side filtering, per the documented contract. Filtering a cached list
  // in the browser would drift from `?severity=` the moment the backend's
  // severity ladder changes.
  const query = severity ? `?severity=${encodeURIComponent(severity)}` : "";
  return getJson<IncidentSummary[]>(`/api/incidents${query}`, signal);
}

export function fetchIncident(
  incidentId: string,
  signal: AbortSignal,
): Promise<IncidentDetail> {
  return getJson<IncidentDetail>(
    `/api/incidents/${encodeURIComponent(incidentId)}`,
    signal,
  );
}

export type Resource<T> =
  | { state: "loading" }
  | { state: "error"; error: ApiError }
  | { state: "ready"; data: T };

/**
 * Run a fetch and track loading/error/ready, cancelling the in-flight request
 * when the inputs change.
 *
 * The abort matters for the severity pills: clicking through CRIT -> HIGH ->
 * MED fires three overlapping requests, and without cancellation whichever
 * resolves last wins -- the queue can settle showing a filter the user is no
 * longer on.
 */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: readonly unknown[],
): Resource<T> & { reload: () => void } {
  const [resource, setResource] = useState<Resource<T>>({ state: "loading" });
  const [nonce, setNonce] = useState(0);

  // Kept in a ref so `load` does not have to be memoised at every call site.
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    const controller = new AbortController();
    setResource({ state: "loading" });

    loadRef.current(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setResource({ state: "ready", data });
      },
      (cause: unknown) => {
        if (controller.signal.aborted) return;
        setResource({
          state: "error",
          error:
            cause instanceof ApiError
              ? cause
              : new ApiError(0, "Something went wrong loading this view."),
        });
      },
    );

    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { ...resource, reload };
}
