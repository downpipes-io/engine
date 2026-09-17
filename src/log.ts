// Structured logging helper (§11). log() emits a single line of JSON to the operational
// stream (Workers Logs, persisted by [observability] in wrangler config), so every diagnostic
// line is machine-parseable and lands in a SIEM with a stable shape rather than as free text.
//
// The line carries the §11 standard fields: ts (ISO8601 UTC), level, service, env, event, and the
// optional request-context fields (method, path, status, duration_ms, error_code) when a caller has
// them. event is the human-readable message the call site previously passed to console.*; it is kept
// verbatim so the existing redaction discipline (coarse [err:XXXXXXXX category] ids, never a raw
// exception message, a token or a value) is PRESERVED unchanged. This helper adds structure around
// that already-redacted string; it never introduces a new field that could carry a secret.
//
// SERVICE/ENV are resolved from a module-level binding the entrypoint sets once via configureLog();
// before that (e.g. a unit test that imports a leaf module directly) they fall back to safe defaults,
// so the helper is usable with zero wiring.

export type LogLevel = "debug" | "info" | "warn" | "error";

// LogFields are the optional request-context fields. They are all the §11-standard names so a SIEM
// query is uniform across the four Workers. Anything not supplied is simply omitted from the line.
export interface LogFields {
  method?: string;
  path?: string;
  status?: number;
  duration_ms?: number;
  error_code?: string;
}

const SERVICE = "downpipe-engine";
let logEnv = "unknown";

// configureLog lets the entrypoint stamp the deployment env (from the Worker's ENVIRONMENT binding)
// onto every subsequent line. Optional: an unconfigured logger emits env:"unknown" rather than throwing.
export function configureLog(env: unknown): void {
  const e = (env as { ENVIRONMENT?: unknown } | null | undefined)?.ENVIRONMENT;
  if (typeof e === "string" && e.length > 0) logEnv = e;
}

// log emits one single-line JSON record. event is the (already-redacted) message string; fields carries
// the optional method/path/status/duration_ms/error_code request context. The JSON.stringify is wrapped
// so a logging fault can never affect control flow (observability must never break the request path).
export function log(level: LogLevel, event: string, fields?: LogFields): void {
  let line: string;
  try {
    line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      service: SERVICE,
      env: logEnv,
      event,
      ...(fields?.method !== undefined ? { method: fields.method } : {}),
      ...(fields?.path !== undefined ? { path: fields.path } : {}),
      ...(fields?.status !== undefined ? { status: fields.status } : {}),
      ...(fields?.duration_ms !== undefined ? { duration_ms: fields.duration_ms } : {}),
      ...(fields?.error_code !== undefined ? { error_code: fields.error_code } : {}),
    });
  } catch {
    // Never let a serialisation fault escape the logger.
    return;
  }
  // Route to the matching console sink so Workers Logs preserves the level. The event string is
  // unchanged inside the JSON, so substring-based redaction/format checks continue to hold.
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}
