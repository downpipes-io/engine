// Workers scripts source: snapshots the account's deployed Worker scripts, their CODE (the
// module/bundle bytes), their SETTINGS (bindings + compatibility date/flags + observability/
// limits), and a small VERSIONS inventory, as records through the unchanged seal pipeline.
// Like the cf-config source (and UNLIKE every binding source: KV / R2 / D1 / Secrets), this
// reads the Cloudflare REST API with the engine's read-only discovery token; it is account-
// scoped and needs no Workers binding. It exists because a customer's Worker code + wiring is
// otherwise unrecoverable, including the downpipes engine and console Workers themselves.
//
// FOUR record kinds per script (name-prefixed by script id so the selector can scope by name):
//   "<id>"            -> the script CONTENT: the recoverable code, the module/bundle bytes.
//   "<id>/settings"   -> the script SETTINGS as canonical JSON: bindings, compatibility_date/
//                        flags, observability, limits, placement, tags. SECRET bindings
//                        (secret_text / secret_key) and secrets_store_secret references come
//                        back from the API REDACTED, there is NO value to read, so they are
//                        recorded as a "reprovision checklist" of {name,type} ONLY, never a value.
//   "<id>/versions"   -> a small VERSIONS inventory (version ids + created times), best-effort.
//   "<id>/schedules"  -> the CRON TRIGGERS (cron expression + timestamps), verbatim: uncaptured they
//                        are a silent data-loss gap on restore. No secret material.
//
// FAIL-OPEN per script AND per aspect, exactly like cf-config's per-surface fail-open: a script
// or a sub-call the token cannot read (a missing scope, a deprecated endpoint, a transient fault
// that survived retry, an oversized bundle) becomes an honest "_unavailable" marker record,
// never a hard failure, so one bad script never breaks the whole Workers snapshot. If EVERY
// script fails (and at least one was attempted) the crawl throws loudly: that is a broken token,
// not a per-script gap, and a run must never report a "successful" snapshot that captured nothing.
//
// RESTORE is REPROVISION (the honesty contract, enforced in the restore sink): the engine NEVER
// blind-redeploys a customer's Worker from a backup, that could brick a live service. The backup
// proves the code + the binding/secret inventory are recoverable; the operator re-deploys
// deliberately with the surfaced guidance. There is no destructive restore path for "workers".

import type { CfPacer } from "../cf-pace.ts";
import type { MarkerKey } from "../seal/marker.ts";
import { API_READ_RETRY, parseRetryAfter, rateLimitError, withRetry } from "../seal/retry.ts";
import {
  CF_PAGINATION_MAX_PAGES,
  CF_PAGINATION_PER_PAGE,
  type CfApi,
  type CfPage,
  CfPaginationTruncated,
  type CfResultInfo,
  paginate,
} from "./cf-config-core.ts";
import { inScope } from "./selector.ts";
import {
  classifySourceFaultReason,
  classifySourceFaultStatus,
  faultItemId,
  recordIncompleteFault,
  recordResumeTokenDefect,
  recordShapeAnomaly,
  recordSourceFatal,
  type SourceFaultReason,
} from "./source-fault-ledger.ts";
import type { CrawlEvent, Meter, ResumableSource, Selector, SourceAdapter, SourceRecord } from "./types.ts";

// AspectCounter is the shared per-crawl tally the per-aspect fail-open updates. lastFault holds the most
// recent absorbed throw (never stored, never logged: only its CLOSED status class is read) so the
// all-aspects-failed guard can record WHY the run is fatal (G144) instead of a coarse class with no status.
interface AspectCounter {
  attempted: number;
  succeeded: number;
  lastFault?: unknown;
}

// A single script's content or serialised settings must fit in memory (it is buffered, like the
// D1 export and a cf-config surface). 128 MiB is far above any realistic Worker bundle (the
// platform upload limit is a few MiB compressed); a script past it is marked unavailable rather
// than risk exhausting the Worker. This is the policy: a script over this size exceeds the Worker
// memory budget for buffered capture and is not captured.
export const WORKERS_SCRIPT_SIZE_LIMIT = 128 * 1024 * 1024;

// WORKERS_LIST_PER_PAGE is the per_page hint the scripts list is paged with. The Workers scripts
// list is page-based; this is well within Cloudflare's list maximum (CF_PAGINATION_PER_PAGE), so a
// large account is paged in a handful of calls rather than truncated to the first page.
export const WORKERS_LIST_PER_PAGE = CF_PAGINATION_PER_PAGE;

const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// MARKER_REASON_MAX bounds how much of a failure reason is written into an "_unavailable" archive
// marker; LIST_ERROR_REASON_MAX bounds the same for the thrown scripts-list error message. They are
// kept separate because the marker is persisted into the archive while the list error is a transient
// thrown string, so they may diverge without coupling.
const MARKER_REASON_MAX = 200;
const LIST_ERROR_REASON_MAX = 160;

// WorkersCfApi is the read client the adapter uses. It is the cf-config CfApi read surface
// (get() returns the parsed `result` of a JSON Cloudflare GET) PLUS getRaw(), because the script
// CONTENT endpoint returns the RAW module/bundle bytes (JavaScript / Wasm / a multipart body),
// NOT a JSON success/result envelope, so it cannot go through get(). It is an interface so the
// validator drives every path with an in-memory stub, no network.
export interface WorkersCfApi {
  // get parses a JSON Cloudflare GET and returns its `result` (settings, versions).
  get(path: string): Promise<unknown>;
  // getPage returns ONE page of a list GET WITH its result_info paging envelope, so paginate()
  // can follow page/total_pages (or a cursor) to exhaustion. The scripts list is page-based and
  // returns at most per_page scripts per call; without paging, an account with more than one page
  // of Workers would have the tail silently dropped. Mirrors cf-config's CfApi.getPage.
  getPage(path: string): Promise<CfPage>;
  // getRaw fetches a non-JSON body (the script content) as bytes plus its content type. It
  // throws on a non-2xx response (same loud-on-failure contract as get), so a per-aspect
  // fail-open marker is produced by the caller's try/catch, never by a silent empty record.
  getRaw(path: string): Promise<{ bytes: Uint8Array; contentType: string }>;
}

// makeWorkersCfApi builds the read client over fetch: Bearer auth, transient-fault retry (the
// shared withRetry), the Cloudflare success/errors envelope unwrapped to `result` for get(), and
// a raw-bytes read for getRaw(). It mirrors makeCfApi (cf-config-surfaces.ts) so the two API
// sources share one auth + retry shape; getRaw is the only addition.
// failFor maps a non-2xx to the right error: a 429 carries the parsed Retry-After so withRetry waits
// the SERVER-requested time (the account rate limit), everything else is a plain transient/hard error.
function failFor(path: string, status: number, why: string, headers: Headers): Error {
  if (status === 429) return rateLimitError(`Cloudflare API GET ${path}: ${why}`, parseRetryAfter(headers.get("retry-after")));
  // G144: carry the HTTP STATUS on the thrown error (a bare integer, alongside the message the callers already
  // build). Every media/Workers sink strips the message down to a coarse class, so without this the run row
  // could not separate a 401 expired token from a 403 missing scope from a 5xx Cloudflare outage: the classic
  // "my Images/Stream/Workers backup fails after a token rotation" ticket. The status is a coarse, redaction-
  // safe integer (no body, no headers, no path); the fault ledger folds it into a closed class at the sink.
  const e = new Error(`Cloudflare API GET ${path}: ${why}`) as Error & { status?: number };
  e.status = status;
  return e;
}

// buildRawFetcher is the getRaw read path: it fetches a NON-JSON body (the script content) as bytes
// plus its content type, throwing failFor on a non-2xx (surfacing a JSON error envelope's message
// when present so a fail-open marker is honest about WHY). Split out of makeWorkersCfApi so the
// shared envelope logic and the raw-bytes logic each stay small.
function buildRawFetcher(
  fetchImpl: typeof fetch,
  auth: { authorization: string },
  pacer?: CfPacer,
): (path: string) => Promise<{ bytes: Uint8Array; contentType: string }> {
  return (path) =>
    withRetry(async () => {
      await pacer?.take();
      const resp = await fetchImpl(`${CF_API_BASE}${path}`, { method: "GET", headers: auth });
      if (!resp.ok) {
        const b = (await resp.clone().json().catch(() => null)) as { errors?: Array<{ message?: string }> } | null;
        const why = (b?.errors ?? []).map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${resp.status}`;
        throw failFor(path, resp.status, why, resp.headers);
      }
      const buf = new Uint8Array(await resp.arrayBuffer());
      return { bytes: buf, contentType: resp.headers.get("content-type") ?? "application/octet-stream" };
    }, API_READ_RETRY);
}

export function makeWorkersCfApi(token: string, fetchImpl: typeof fetch = fetch, pacer?: CfPacer): WorkersCfApi {
  const auth = { authorization: `Bearer ${token}` };
  // The optional pacer throttles calls below the account-API limit (proactive); API_READ_RETRY rides
  // out a 429 that still happens (reactive). Both are no-ops when absent (the validator's in-memory
  // stub never uses this builder), so behaviour is unchanged off the network path.
  // callEnvelope keeps the WHOLE decoded body (so getPage can read result_info to follow pages);
  // get() returns just `result` (the single-page reads). Both throw on a non-ok/unsuccessful
  // response, never a silent empty result. Mirrors makeCfApi.callEnvelope in cf-config-core.ts.
  const callEnvelope = (path: string): Promise<{ result: unknown; result_info?: CfResultInfo }> =>
    withRetry(async () => {
      await pacer?.take();
      const resp = await fetchImpl(`${CF_API_BASE}${path}`, { method: "GET", headers: auth });
      const b = (await resp.json().catch(() => null)) as
        | { success?: boolean; result?: unknown; result_info?: CfResultInfo; errors?: Array<{ message?: string }> }
        | null;
      if (!resp.ok || b?.success !== true) {
        const why = (b?.errors ?? []).map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${resp.status}`;
        throw failFor(path, resp.status, why, resp.headers);
      }
      return b?.result_info !== undefined ? { result: b?.result ?? null, result_info: b.result_info } : { result: b?.result ?? null };
    }, API_READ_RETRY);
  return {
    get: async (path) => (await callEnvelope(path)).result ?? null,
    getPage: async (path) => {
      const b = await callEnvelope(path);
      // A list endpoint returns an array; coerce a non-array result to an array so the paginator's
      // accumulation is uniform (a non-array result becomes a one-element page with no result_info,
      // so paging stops immediately). Mirrors cf-config's getPage.
      const result = Array.isArray(b.result) ? b.result : b.result == null ? [] : [b.result];
      return b.result_info !== undefined ? { result, result_info: b.result_info } : { result };
    },
    getRaw: buildRawFetcher(fetchImpl, auth, pacer),
  };
}

// SECRET_BINDING_TYPES are the binding types whose VALUE is write-only and never returned by the
// API: a per-Worker inline secret (secret_text), a secret key (secret_key), and a Secrets Store
// reference (secret_text bindings backed by the store, surfaced as secrets_store_secret). The
// settings record reduces every one of these to a {name,type} reprovision-checklist entry and
// carries NO value field, there is no value to read, and none is fabricated.
const SECRET_BINDING_TYPES = new Set(["secret_text", "secret_key", "secrets_store_secret"]);

// SettingsRecordValue is the SHAPE the settings record serialises: the non-secret config verbatim,
// plus a redaction-safe reprovisionChecklist for the secret bindings. It is the engine's contract
// that a settings backup is value-free for secrets.
interface SettingsRecordValue {
  compatibility_date?: unknown;
  compatibility_flags?: unknown;
  usage_model?: unknown;
  observability?: unknown;
  limits?: unknown;
  placement?: unknown;
  tags?: unknown;
  migrations?: unknown;
  logpush?: unknown;
  // bindings with any secret VALUE stripped: a secret binding keeps only {name,type}; a
  // non-secret binding (kv_namespace, r2_bucket, d1, service, queue, plain_text, json, ...) is
  // kept verbatim (it carries no secret, a plain_text "secret" is a misnomer in the API and is
  // NOT in SECRET_BINDING_TYPES, but we still never widen: only the listed secret types are
  // reduced, everything else is the API's own non-secret value). Always present: redactSettings
  // builds it for every input (an empty array when there are none), so it is required, not optional.
  bindings: unknown[];
  // reprovisionChecklist: the secret bindings by NAME + TYPE only, for the operator to re-create
  // after a restore. Never a value.
  reprovisionChecklist: Array<{ name: string; type: string }>;
}

// redactSettings reduces a raw /settings result to the value-free SettingsRecordValue: it strips
// any value from a secret binding (keeping name + type), keeps non-secret bindings verbatim, and
// extracts the secret bindings into the reprovisionChecklist. It is pure and total over whatever
// JSON the API returns, an unexpected shape (no bindings array, a non-object binding) degrades to
// an empty checklist rather than throwing, so the surrounding fail-open still holds.
export function redactSettings(raw: unknown): SettingsRecordValue {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const rawBindings = Array.isArray(r.bindings) ? r.bindings : [];
  const checklist: Array<{ name: string; type: string }> = [];
  const bindings: unknown[] = [];
  for (const b of rawBindings) {
    if (!b || typeof b !== "object") {
      bindings.push(b); // preserve an odd entry verbatim; it carries no secret we can identify
      continue;
    }
    const rec = b as Record<string, unknown>;
    const type = typeof rec.type === "string" ? rec.type : "";
    const name = typeof rec.name === "string" ? rec.name : "";
    if (SECRET_BINDING_TYPES.has(type)) {
      // A secret binding: record ONLY its name + type. Drop EVERYTHING else (the API returns no
      // value, but we never even carry through whatever else might be on the object, e.g. a
      // store_id, so the record can never become a value oracle). It does NOT go into bindings.
      checklist.push({ name, type });
      continue;
    }
    // A non-secret binding: keep verbatim (it is account metadata, not a secret).
    bindings.push(b);
  }
  // Carry the non-secret top-level settings fields verbatim when present (compatibility, limits,
  // observability, placement, tags, migrations, logpush, usage_model). Unknown extra fields are
  // intentionally dropped from the typed shape but the bindings/checklist split is the guarantee.
  const out: SettingsRecordValue = { bindings, reprovisionChecklist: checklist };
  for (const k of ["compatibility_date", "compatibility_flags", "usage_model", "observability", "limits", "placement", "tags", "migrations", "logpush"] as const) {
    if (r[k] !== undefined) out[k] = r[k];
  }
  return out;
}

// ScriptListItem is the minimal shape the list endpoint yields per script. id is the script name
// the per-script endpoints key on.
interface ScriptListItem {
  id?: unknown;
}

// WorkersToken is the resume cursor: the id of the last script whose records were ALL yielded. A resume
// re-lists (one cheap call) and skips every script id at or before this watermark, so no script's records
// are re-read. Script ids are sorted to a stable order so the watermark is well-defined across slices.
interface WorkersToken {
  after: string;
}

// parseWorkersToken parses a persisted resume token and asserts its shape, mirroring r2.ts's
// parseToken. A corrupt or missing `.after` would otherwise cast silently and leave `after`
// undefined, so the skip-until-watermark filter (`id <= after`) would pass every id and the run
// would silently restart the whole crawl. Throwing here surfaces the corruption immediately.
function parseWorkersToken(token: string): WorkersToken {
  // G213: closed defect class per corruption mode; the token bytes are never recorded.
  let t: WorkersToken;
  try {
    t = JSON.parse(token) as WorkersToken;
  } catch {
    recordResumeTokenDefect("workers", "unparseable");
    throw new Error("malformed Workers resume token (unparseable)");
  }
  if (typeof t !== "object" || t === null || typeof t.after !== "string") {
    recordResumeTokenDefect("workers", "bad-shape");
    throw new Error("malformed Workers resume token");
  }
  return t;
}

export class WorkersSource implements SourceAdapter, ResumableSource {
  readonly sourceType = "workers" as const;
  readonly accountId: string;
  private api: WorkersCfApi;
  private sizeLimit: number;

  // api and sizeLimit are injectable for the validator (an in-memory WorkersCfApi, a tiny limit to
  // exercise the size guard). In production, construct it from the discovery token via
  // makeWorkersCfApi(token), buildAdapter does exactly this.
  constructor(accountId: string, api: WorkersCfApi, sizeLimit: number = WORKERS_SCRIPT_SIZE_LIMIT) {
    this.accountId = accountId;
    this.api = api;
    this.sizeLimit = sizeLimit;
  }

  private acct(): string {
    return encodeURIComponent(this.accountId);
  }

  // listScripts returns EVERY script id in the account, paging the list to exhaustion (one metered
  // call per page). The Cloudflare scripts list is page-based and returns at most per_page scripts
  // per call, so a single unpaged GET silently dropped every script past the first page; paginate()
  // follows page/total_pages (and would follow a cursor) until the list is exhausted, capped at
  // CF_PAGINATION_MAX_PAGES (it throws CfPaginationTruncated rather than loop or silently truncate).
  // A non-array / empty result yields no scripts, an account with no Workers is a valid empty snapshot.
  private async listScripts(meter?: Meter): Promise<string[]> {
    // paginate() owns the per-page call + metering. It needs a CfApi read view; WorkersCfApi already
    // provides get()/getPage(), and paginate never writes, so send() is a never-called guard.
    const cfApi: CfApi = {
      get: (path) => this.api.get(path),
      getPage: (path) => this.api.getPage(path),
      send: () => Promise.reject(new Error("workers source is read-only")),
    };
    const list = (await paginate(
      cfApi,
      `/accounts/${this.acct()}/workers/scripts`,
      meter,
      WORKERS_LIST_PER_PAGE,
      CF_PAGINATION_MAX_PAGES,
    )) as ScriptListItem[];
    const ids: string[] = [];
    for (const s of list) if (typeof s?.id === "string" && s.id.length > 0) ids.push(s.id);
    return ids;
  }

  // marker builds the "_unavailable" record value for a script/aspect the token could not read,
  // mirroring cf-config's marker exactly (so the archive stays one-record-per-attempt and honestly
  // distinguishes "unavailable, and why" from a genuinely empty result).
  private marker(reason: string): Uint8Array {
    return new TextEncoder().encode(JSON.stringify({ _unavailable: reason.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, MARKER_REASON_MAX) }));
  }

  // jsonValue serialises a JSON-able value to record bytes, enforcing the size guard. It throws on
  // an oversize body so the per-aspect try/catch turns it into a marker (never an OOM).
  private jsonValue(name: string, data: unknown): Uint8Array {
    const v = new TextEncoder().encode(JSON.stringify(data ?? null));
    if (v.byteLength > this.sizeLimit) {
      throw new Error(`${name} serialised JSON exceeds the ${this.sizeLimit}-byte limit; a record over this size exceeds the Worker memory budget for buffered capture and is not captured`);
    }
    return v;
  }

  // yieldAspect yields ONE in-scope aspect record for a script: it meters the read, runs the
  // produce() thunk (which fetches + shapes the record bytes) inside the per-aspect fail-open (any
  // throw becomes a marker, never a hard failure), updates the shared attempted/succeeded counter,
  // and yields the record. A record whose name is out of scope is skipped entirely (no meter, no
  // counter touch). Shared by all three aspects so a change to the fail-open shape cannot diverge.
  private async *yieldAspect(name: string, selector: Selector, meter: Meter | undefined, counter: AspectCounter, produce: () => Promise<Uint8Array>): AsyncIterable<SourceRecord> {
    if (!inScope(name, selector)) return;
    counter.attempted++;
    let value: Uint8Array;
    // markerReason (G015) is the CLOSED reason class for the marker below; without it the pack could say a
    // script aspect was "_unavailable" every run and never whether that was a 403 scope gap, a 5xx or the
    // size ceiling, because the WHY only ever existed inside the archive-sealed marker payload.
    let markerReason: SourceFaultReason | undefined;
    // markerKind (CR-04) is set ONLY on the fail-open catch path below, at the exact point the adapter
    // itself decides to substitute a marker for the real aspect bytes -- an assertion of fact, never a
    // guess from the value's shape (a script's real content/settings/versions JSON could otherwise collide
    // with a marker's shape and be misclassified at seal/restore time).
    let markerKind: MarkerKey | undefined;
    try {
      meter?.spend(1, "cfApiRead");
      value = await produce();
      counter.succeeded++;
    } catch (e) {
      value = this.marker((e as Error).message);
      markerKind = "_unavailable";
      markerReason = classifySourceFaultReason(e);
      counter.lastFault = e; // the all-aspects-failed guard classifies the run-fatal status from a REAL fault (G144)
      // G068/G015: attribute the failing aspect. The aspect ("content"/"settings"/"versions"/"schedules") is a
      // closed product token carried raw; the SCRIPT id is customer-owned, so it is reduced to a one-way handle.
      // Without this the pack sees one "_unavailable" count and cannot say which script, or which aspect, is short.
      const cut = name.lastIndexOf("/");
      const script = cut > 0 ? name.slice(0, cut) : name;
      const aspect = cut > 0 ? name.slice(cut + 1) : "aspect";
      recordIncompleteFault("_unavailable", markerReason, { id: await faultItemId(`workers:${aspect}`, script) });
    }
    yield { sourceType: "workers", name, value, ...(markerKind !== undefined ? { markerKind } : {}), ...(markerReason !== undefined ? { markerReason } : {}) };
  }

  // yieldScript yields ONE script's in-scope records (content, settings, versions) through yieldAspect,
  // so each aspect shares one fail-open + metering + counter discipline and only its fetch+shape thunk
  // differs. Factored out so crawl and crawlFrom share one implementation.
  private async *yieldScript(id: string, selector: Selector, meter: Meter | undefined, counter: AspectCounter): AsyncIterable<SourceRecord> {
    const a = encodeURIComponent(id);

    // ---- CONTENT: the recoverable code (one record per script, name = the script id) ----
    yield* this.yieldAspect(id, selector, meter, counter, async () => {
      const { bytes } = await this.api.getRaw(`/accounts/${this.acct()}/workers/scripts/${a}/content`);
      if (bytes.byteLength > this.sizeLimit) {
        throw new Error(`script ${id} content exceeds the ${this.sizeLimit}-byte limit; a script over this size exceeds the Worker memory budget for buffered capture and is not captured`);
      }
      return bytes; // the raw module/bundle bytes ARE the record value (no re-encoding)
    });

    // ---- SETTINGS: bindings + compat + observability/limits, secrets reduced to a checklist ----
    const settingsName = `${id}/settings`;
    yield* this.yieldAspect(settingsName, selector, meter, counter, async () => {
      const raw = await this.api.get(`/accounts/${this.acct()}/workers/scripts/${a}/settings`);
      return this.jsonValue(settingsName, redactSettings(raw));
    });

    // ---- VERSIONS: a small inventory (version ids + created times), best-effort ----
    const versionsName = `${id}/versions`;
    yield* this.yieldAspect(versionsName, selector, meter, counter, async () => {
      const raw = (await this.api.get(`/accounts/${this.acct()}/workers/scripts/${a}/versions`)) as
        | { items?: Array<Record<string, unknown>> }
        | Array<Record<string, unknown>>
        | null;
      // Reduce to an inventory: version id + created time only (never the version's bindings/
      // metadata, which can re-contain secret references; the per-version detail is out of
      // scope for v1). Tolerate either {items:[...]} or a bare array.
      // G110: neither an array nor {items:[...]} coerces to an EMPTY inventory, so on a Cloudflare response-shape
      // change EVERY script's version history archives as "no versions" while the run reports a clean ok. Count it.
      if (!Array.isArray(raw) && !Array.isArray(raw?.items)) recordShapeAnomaly("workers:versions");
      const arr = Array.isArray(raw) ? raw : Array.isArray(raw?.items) ? raw.items : [];
      const inventory = arr.map((v) => ({
        id: typeof v?.id === "string" ? v.id : undefined,
        number: typeof v?.number === "number" ? v.number : undefined,
        created_on: typeof v?.created_on === "string" ? v.created_on : undefined,
      }));
      return this.jsonValue(versionsName, { versions: inventory });
    });

    // ---- SCHEDULES: the script's CRON TRIGGERS. Uncaptured, these are a silent data-loss gap on restore
    // (a reprovisioned Worker loses its cron schedule). They carry NO secret material (a cron expression +
    // timestamps), so capture them verbatim as an inventory a restore can replay. Fail-open per aspect. ----
    const schedulesName = `${id}/schedules`;
    yield* this.yieldAspect(schedulesName, selector, meter, counter, async () => {
      const raw = (await this.api.get(`/accounts/${this.acct()}/workers/scripts/${a}/schedules`)) as
        | { schedules?: Array<Record<string, unknown>> }
        | Array<Record<string, unknown>>
        | null;
      // Tolerate either {schedules:[...]} or a bare array; keep only real cron entries.
      // G110: same silent coercion as versions above, but the consequence is data loss on restore -- a
      // reprovisioned Worker comes back with NO CRON SCHEDULE and the run reported ok. Count the drift.
      if (!Array.isArray(raw) && !Array.isArray(raw?.schedules)) recordShapeAnomaly("workers:schedules");
      const arr = Array.isArray(raw) ? raw : Array.isArray(raw?.schedules) ? raw.schedules : [];
      const crons = arr
        .map((s) => ({
          cron: typeof s?.cron === "string" ? s.cron : undefined,
          created_on: typeof s?.created_on === "string" ? s.created_on : undefined,
          modified_on: typeof s?.modified_on === "string" ? s.modified_on : undefined,
        }))
        .filter((s) => s.cron !== undefined);
      return this.jsonValue(schedulesName, { schedules: crons });
    });
  }

  async *crawl(selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for await (const ev of this.crawlFrom(selector, null, meter)) {
      if (ev.kind === "record") yield ev.record;
    }
  }

  // crawlFrom is the RESUMABLE crawl: it lists the scripts (one cheap call), iterates them in a STABLE
  // sorted order from the resume watermark, yields each script's records, and emits a {mark} AFTER each
  // fully-yielded script so a slice can checkpoint between scripts and resume without re-reading any
  // script. This is what lets an account with more than ~300 scripts back up at all (the seal subrequest
  // cap is ~1000, ~3 calls/script): the run now spans invocations instead of being killed with no progress.
  async *crawlFrom(selector: Selector, token: string | null, meter?: Meter): AsyncIterable<CrawlEvent> {
    let ids: string[];
    try {
      ids = await this.listScripts(meter);
    } catch (e) {
      // A pagination overflow is NOT a token problem: surface it loudly and accurately (never
      // rewrap it as a scope hint, and never silently truncate to the pages read so far).
      if (e instanceof CfPaginationTruncated) throw e;
      // G144: record the transport verdict BEFORE the rewrap below discards it. The rewrapped message is a
      // 160-char hint string, so by the time the run row is written the HTTP status is gone and a 401 expired
      // token, a 403 missing scope and a 5xx outage all read identically. Stage "list": the token could not
      // even enumerate the scripts, which is a different fix from "the list worked but every read failed".
      recordSourceFatal({ sourceType: "workers", statusClass: classifySourceFaultStatus(e), stage: "list" });
      // The LIST itself failing is a broken/under-scoped token, not a per-script gap: fail loudly
      // so a run can never report a "successful" Workers snapshot that listed nothing real.
      throw new Error(
        `Workers scripts list failed (${(e as Error).message.replace(/^Cloudflare API GET [^:]+:\s*/, "").slice(0, LIST_ERROR_REASON_MAX)}); the token likely lacks "Workers Scripts" read scope or is invalid`,
      );
    }
    ids.sort(); // stable order so the resume watermark (last fully-yielded id) is well-defined
    const after = token !== null ? parseWorkersToken(token).after : null;

    const counter: AspectCounter = { attempted: 0, succeeded: 0 };
    for (const id of ids) {
      if (after !== null && id <= after) continue; // already yielded before the resume
      for await (const rec of this.yieldScript(id, selector, meter, counter)) {
        yield { kind: "record", record: rec };
      }
      // Mark AFTER all of this script's records: a slice may end here and resume after this script id.
      yield { kind: "mark", token: JSON.stringify({ after: id } satisfies WorkersToken) };
    }

    // If this is a FROM-SCRATCH crawl (no resume) that attempted scripts and EVERY aspect failed, it is a
    // broken token / lost scope, not a scatter of per-script gaps: fail loudly (the original guard). On a
    // RESUME pass (after !== null) the guard is skipped, since a partial slice legitimately covers a subset.
    if (after === null && counter.attempted > 0 && counter.succeeded === 0) {
      // G144: the list SUCCEEDED and every read failed, which is a narrower diagnosis than "the token is bad":
      // carry the stage (item-read), the closed status class of the last absorbed fault, and the attempted /
      // succeeded magnitude, so support can separate a scope gap from a Cloudflare outage without a re-run.
      recordSourceFatal({
        sourceType: "workers",
        statusClass: classifySourceFaultStatus(counter.lastFault),
        stage: "item-read",
        attempted: counter.attempted,
        succeeded: counter.succeeded,
      });
      throw new Error(
        'every Workers script aspect failed to read; the token likely lacks "Workers Scripts" read scope or is invalid',
      );
    }
  }

  async estimate(selector: Selector): Promise<{ records: number; bytes: number }> {
    // estimate lists scripts (metadata only, never reads content/settings) and counts the in-scope
    // records (up to four per script: content, settings, versions, schedules). Sizes are unknown without
    // reading, so bytes is -1, exactly like cf-config. A list failure surfaces as zero records
    // here (estimate is a projection, not a run) rather than throwing the cost preview.
    let ids: string[];
    try {
      ids = await this.listScripts();
    } catch {
      return { records: 0, bytes: -1 };
    }
    let records = 0;
    for (const id of ids) {
      if (inScope(id, selector)) records++;
      if (inScope(`${id}/settings`, selector)) records++;
      if (inScope(`${id}/versions`, selector)) records++;
      if (inScope(`${id}/schedules`, selector)) records++;
    }
    return { records, bytes: -1 };
  }
}
