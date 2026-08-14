/**
 * Generated from the FastAPI OpenAPI document. Do not edit by hand.
 *
 * Regenerate after changing any Pydantic response model in
 * `backend/app/api_incidents.py`:
 *
 *     cd backend && python scripts/generate_frontend_types.py
 *
 * `backend/tests/test_frontend_types.py` fails if this file is out of date.
 */

export interface Body_ingest_file_api_ingest_post {
  file: Blob;
  default_year?: number | null;
  default_host?: string | null;
}

export interface HTTPValidationError {
  detail?: ValidationError[];
}

/**
 * The detail view. Inherits the queue row rather than restating it, so the
 * two shapes cannot drift into disagreeing about the same incident.
 */
export interface IncidentDetail {
  incident_id: string;
  /** Severity name, e.g. HIGH */
  severity: string;
  /** Numeric severity, for sorting */
  severity_score: number;
  primary_entity: string;
  finding_count: number;
  tactic_count: number;
  tactics: string[];
  sources: SourceCount[];
  entity_keys: string[];
  /** Distinct rule ids that fired, sorted. Searchable in the queue. */
  rule_ids: string[];
  first_seen: string | null;
  last_seen: string | null;
  summary: string;
  /** 'llm' or 'deterministic' -- the UI labels the latter */
  enrichment_source: string;
  techniques: TechniqueOut[];
  timeline: TimelineEntry[];
}

/**
 * Queue row. Everything needed to triage without opening the incident.
 *
 * `entity_keys` and `rule_ids` are carried here, not just on the detail, so
 * the queue can be searched on them. Without them the only searchable
 * identifier is `primary_entity` -- one key out of the several an incident
 * actually touches -- so an analyst pivoting on an address that appears in the
 * evidence but did not win `_KEY_PRECEDENCE` gets no hit, and the queue looks
 * like it has nothing on an entity it is in fact reporting.
 *
 * This grows the listing payload: both fields are per-incident sets, so a
 * response is roughly the sum of every incident's entity fan-out rather than
 * one key each. That is fine at sample-log scale and is the same bet as
 * recomputing incidents per request (above) -- and it is bounded by
 * `MAX_COOCCURRING_KEYS`, which already caps how wide an incident's key set
 * can get. If the queue ever needs to page, these are the two fields to drop
 * behind a `?fields=` projection first.
 */
export interface IncidentSummary {
  incident_id: string;
  /** Severity name, e.g. HIGH */
  severity: string;
  /** Numeric severity, for sorting */
  severity_score: number;
  primary_entity: string;
  finding_count: number;
  tactic_count: number;
  tactics: string[];
  sources: SourceCount[];
  entity_keys: string[];
  /** Distinct rule ids that fired, sorted. Searchable in the queue. */
  rule_ids: string[];
  first_seen: string | null;
  last_seen: string | null;
}

export interface IngestResponse {
  ingest_id: number;
  filename: string | null;
  source_type: string;
  detected_confidence: number;
  events_persisted: number;
  duplicates_skipped: number;
  stats: ParseStatsOut;
}

export interface ParseErrorOut {
  line_no: number;
  reason: string;
  excerpt: string;
}

export interface ParseStatsOut {
  lines_read: number;
  events_emitted: number;
  lines_skipped: number;
  errors: ParseErrorOut[];
}

/**
 * Query-param spelling of `Severity`.
 *
 * A StrEnum rather than a bare string so FastAPI rejects `?severity=urgent`
 * with a 422 listing the real values, instead of silently returning an empty
 * queue that reads as "nothing is wrong".
 */
export type SeverityName = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface SourceCount {
  source_type: string;
  event_count: number;
}

export interface TechniqueOut {
  technique_id: string;
  name: string;
  tactics: string[];
}

/**
 * One finding, as a row in the analyst's working view.
 *
 * A span, not a point. A threshold rule covering sixteen failures and a
 * sequence rule covering those failures plus the success that followed both
 * *begin* at the same instant, so a single timestamp cannot express that one
 * contains the other -- and a UI given one point per finding can only draw
 * them stacked at the same tick.
 */
export interface TimelineEntry {
  first_seen: string | null;
  last_seen: string | null;
  rule_id: string;
  title: string;
  technique_id: string | null;
  technique_name: string | null;
  source_type: string;
  evidence_count: number;
  evidence: string[];
}

export interface ValidationError {
  loc: (string | number)[];
  msg: string;
  type: string;
  input?: unknown;
  ctx?: Record<string, unknown>;
}
