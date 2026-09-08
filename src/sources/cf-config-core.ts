// Core types + API client + pagination + read-builders for the cf-config source surface registry
// (cf-config-surfaces.ts). It defines the CfConfigSurface contract (one surface = one archived record),
// the CfApi client over fetch (with the Cloudflare success/errors envelope unwrapped), the bounded
// page-following paginator (page-based AND cursor-based; SRC-4), and the read-builders one()/list()/
// expandRulesets() the registry's read functions are made of. Everything here was MOVED VERBATIM out of
// cf-config-surfaces.ts to keep that module a readable size; the behaviour is unchanged. The registry
// (cf-config-surfaces.ts) and the write specs (cf-config-write.ts) import from here; this module imports
// only the shared leaf (cf-config-shared.ts) plus Meter/withRetry, so there is no cycle.

import type { CfPacer } from "../cf-pace.ts";
import type { Meter } from "../meter.ts";
import { API_READ_RETRY, parseRetryAfter, rateLimitError, withRetry } from "../seal/retry.ts";
import type { CfWriteSkipClass } from "./cf-config-fault.ts";
import type { ConfigChange } from "./cf-config-shared.ts";
import { isPlainObject } from "./cf-config-shared.ts";
import { classifySourceFaultReason, faultItemId, recordIncompleteFault, recordShapeAnomaly } from "./source-fault-ledger.ts";

export type CfScope = "zone" | "account";
export type RestoreTier = "idempotent" | "ordered" | "reprovision";

// ConfigWriteResult is what a surface's write returns: the diff (always computed), and on a real
// apply the count applied plus any per-item skips (a field the API would not let us set).
export interface ConfigWriteResult {
  changes: ConfigChange[];
  applied: number;
  // G191: each skip now carries a CLOSED class alongside its human `reason`. The reason is the raw (prefix-
  // stripped, 120-char) Cloudflare message and stays exactly where it always was -- in the live HTTP response
  // to the operator running the restore. The CLASS is the part that can be counted, grouped and carried in a
  // support pack, and it is what separates "your plan is full" (quota) from "your token lacks the edit scope"
  // (auth) from "the snapshot item is malformed" (validation) -- three tickets with three different remedies
  // that a bare `skipped: 20` integer cannot tell apart.
  skipped: Array<{ path: string; reason: string; cls?: CfWriteSkipClass }>;
}

// CfPage is one decoded page of a Cloudflare LIST response: the `result` array plus the
// `result_info` paging envelope (page-based lists carry {page,total_pages,total_count}; a few
// newer endpoints carry a {cursor} or {cursors:{after}} instead). It is what getPage returns so the
// paginator (paginate()) can decide whether another page exists WITHOUT the single-page get()
// throwing the envelope away.
export interface CfResultInfo {
  page?: number;
  per_page?: number;
  count?: number;
  total_count?: number;
  total_pages?: number;
  cursor?: string; // some endpoints return the NEXT cursor at the top level
  cursors?: { after?: string; before?: string }; // others nest it
}
export interface CfPage {
  result: unknown[];
  result_info?: CfResultInfo;
}

// CfApi is the client a surface uses. get() returns the parsed `result` of a Cloudflare API GET
// (backup, single page); getPage() returns one page WITH its result_info so list surfaces can
// page; send() performs a WRITE, PATCH/PUT/POST/DELETE, for the restore (edit-token) path.
// All throw on a non-ok / unsuccessful response. It is an interface so the validator can drive
// every surface with a stubbed client, no network.
export interface CfApi {
  get(path: string): Promise<unknown>;
  getPage(path: string): Promise<CfPage>;
  send(method: "PATCH" | "PUT" | "POST" | "DELETE", path: string, body?: unknown): Promise<unknown>;
}

export interface CfConfigSurface {
  id: string; // the archived record name (e.g. "dns", "zone-settings")
  scope: CfScope; // "zone" needs a zoneId; "account" reads account-level config
  restoreTier: RestoreTier;
  // read returns the surface's full config as a JSON-able value (one record's value bytes).
  // Every Cloudflare API call is a platform subrequest, so each read meters its calls.
  read(api: CfApi, ids: { accountId: string; zoneId?: string }, meter?: Meter): Promise<unknown>;
  // write is the DIFF-DRIVEN restore for an idempotent (T1) surface. It reads the CURRENT live
  // config, diffs it against the snapshot `data`, and, unless opts.dryRun, applies ONLY the
  // fields that differ, item by item (so one un-settable field never fails the rest, and unchanged
  // fields are never touched). It always returns the diff (for the preview) plus, on a real apply,
  // the applied/skipped counts. Only T1 surfaces implement it; ordered/reprovision are out-of-band.
  write?(api: CfApi, ids: { accountId: string; zoneId?: string }, data: unknown, opts: { dryRun: boolean }, meter?: Meter): Promise<ConfigWriteResult>;
}

const CF_API_BASE = "https://api.cloudflare.com/client/v4";

// ENTITLEMENT_CODES are Cloudflare API error codes whose canonical message is the account-PLAN
// entitlement vocabulary ("not entitled" / "not_entitled"): 50002 (a rulesets phase, e.g. Account WAF,
// is Enterprise-only, "not entitled to use the phase ..."), 10015 (workers "workers.api.error.not_entitled"),
// 10016 (firewall access rules "firewallaccessrules.api.not_entitled.*"). Cloudflare keeps ENTITLEMENT
// distinct from AUTHENTICATION: a token-scope/permission gap is code 10000 "Authentication error" or 9109
// "Unauthorized to access requested resource", NEVER one of these codes. This list is a robustness belt
// for a terse-message variant; ENTITLEMENT_MESSAGE below is the complete, product-agnostic signal.
const ENTITLEMENT_CODES = new Set<number>([50002, 10015, 10016]);
// The Cloudflare account-PLAN entitlement vocabulary. "not entitled" / "not_entitled" is the phrase
// Cloudflare uses for plan/feature gating across products (rulesets, workers, firewall access rules,
// origin rules, ...) and NEVER for a token-scope/permission error (those read "Authentication error" /
// "Unauthorized to access requested resource" / "insufficient permissions"). The match is TIGHT and
// anchored (the literal phrase, \b...\b), deliberately NOT a bare "entitle", so it cannot drift onto a
// permission message. This is the conservative discriminator: it errs toward NOT matching.
const ENTITLEMENT_MESSAGE = /\bnot[ _]entitled\b/i;

// isCfPlanEntitlementError reports whether a failed Cloudflare read is a DEFINITIVE account-PLAN /
// entitlement gate, the account's plan simply does not include the product, so there is nothing to
// back up (benign, like an empty surface), as opposed to an ACTIONABLE fault (a token-scope gap, a
// transient 5xx, a 429 throttle, an unrecognised error). It is deliberately CONSERVATIVE: it returns
// true ONLY for an unambiguous entitlement signal and false for ANYTHING ambiguous, because a wrong
// `true` would HIDE a real token-scope gap (a SILENT MISS, far worse than the mere noise of a benign
// gate counted as actionable). When in doubt, false (actionable). The rules, in order:
//   - a 429 (throttle) or any 5xx (server error) is transient/ambiguous -> NEVER gated (stays actionable);
//   - a definite entitlement CODE -> gated;
//   - the entitlement MESSAGE vocabulary -> gated;
//   - everything else (a bare 403, 9109/10000 auth, an unrecognised error, an empty/unparseable body) -> NOT gated.
export function isCfPlanEntitlementError(status: number, codes: number[], messages: string[]): boolean {
  if (status === 429 || status >= 500) return false; // transient/ambiguous: must stay actionable (unavailable)
  if (codes.some((c) => ENTITLEMENT_CODES.has(c))) return true;
  return messages.some((m) => ENTITLEMENT_MESSAGE.test(m));
}

// CfApiError is what a failed Cloudflare read throws for every non-429 unsuccessful response. It carries
// only the COARSE, redaction-safe signals, the HTTP status and the CF error code list, plus the
// precomputed `planEntitlementGated` verdict (is this a definite account-plan gate, or an actionable
// fault?). The verdict is computed at the throw site because that is the ONLY place the raw CF error
// MESSAGES are in scope, and the raw messages are NEVER stored on the error (no-custody: only the status,
// the numeric codes, and the 1-bit verdict leave this function). The human `.message` is the same coarse
// string the client always produced (the request path + the CF error messages), unchanged, so the shared
// transient-fault classifier (which reads the message) behaves exactly as before. A 429 throttle is NOT a
// CfApiError (it is a rateLimitError carrying Retry-After), so a throttle can never be read as a gate.
export class CfApiError extends Error {
  readonly status: number;
  readonly codes: number[];
  readonly planEntitlementGated: boolean;
  constructor(message: string, status: number, codes: number[], planEntitlementGated: boolean) {
    super(message);
    this.name = "CfApiError";
    this.status = status;
    this.codes = codes;
    this.planEntitlementGated = planEntitlementGated;
  }
}

// makeCfApi builds the read client over fetch: Bearer auth, transient-fault retry (shared
// withRetry), and the Cloudflare success/errors envelope unwrapped. callEnvelope keeps the WHOLE
// decoded body (so getPage can read result_info); call returns just `result` (the single-page get
// and the write path). Both throw on a non-ok/unsuccessful response, never a silent empty result.
export function makeCfApi(token: string, fetchImpl: typeof fetch = fetch, pacer?: CfPacer): CfApi {
  const callEnvelope = (method: string, path: string, body?: unknown): Promise<{ result: unknown; result_info?: CfResultInfo }> =>
    withRetry(async () => {
      // pacer (proactive) keeps the crawl below the account-API limit; on a 429 the error carries the
      // parsed Retry-After so withRetry (reactive) waits the server-requested time. Both no-op when absent
      // (the validator's stubbed CfApi never uses this builder), so off-network behaviour is unchanged.
      await pacer?.take();
      const init: RequestInit = {
        method,
        headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      const resp = await fetchImpl(`${CF_API_BASE}${path}`, init);
      const b = (await resp.json().catch(() => null)) as
        | { success?: boolean; result?: unknown; result_info?: CfResultInfo; errors?: Array<{ code?: number; message?: string; error?: string }> }
        | null;
      // A 200 with NO `success` field at all is not a Cloudflare-envelope response, it is an endpoint
      // that answers in its own shape. Cloudflare has several inside its own API: the SCIM endpoints
      // answer with an RFC 7644 ListResponse (`{schemas, totalResults, Resources}`) and CNI answers with
      // a cursor envelope (`{items, next}`). Treating those as failures would throw away real data (a scim-users
      // response carrying real users would archive as "_unavailable", silently, since fail-open renders it as
      // a marker). Accept the body as the result and record the anomaly so a non-standard shape stays visible
      // rather than becoming invisible.
      // Keyed on the ABSENCE of `result`, not on `success`. Cloudflare has three shapes in its own API
      // that answer without one: SCIM omits `success` too, CNI omits both, and RealtimeKit sets
      // `success:true` and puts its list at `data`. Testing `success === undefined` alone missed the
      // third. `"result" in b` distinguishes an absent key from a present-but-null one, which is a real
      // and different case (G110: a null result on a list endpoint is a shape anomaly, not an empty list).
      // 204 NO CONTENT IS SUCCESS. There is no body to parse, so `b` is null, `resp.ok` is true and
      // `b?.success !== true`, and the refusal branch below then throws on a request that worked. Cloudflare
      // answers 204 on several DELETEs, custom_pages/assets among them.
      //
      // On an account where the create succeeds, without this the round trip would report
      // "CREATE-REFUSED: DELETE ... HTTP 204", a success being read as a failure.
      //
      // Narrowed to 204 deliberately. Accepting any 2xx with an unparseable body would also swallow a
      // malformed 200, and a response that should have carried a result and did not is a real fault worth
      // keeping loud.
      if (resp.status === 204) return { result: null };
      if (resp.ok && b !== null && typeof b === "object" && !("result" in b)) {
        recordShapeAnomaly("cf-config/envelope:no-success-field");
        return { result: b as unknown };
      }
      if (!resp.ok || b?.success !== true) {
        // The Cloudflare error envelope is `{ success:false, errors:[{ code, message }] }`. Extract the
        // numeric codes (coarse, redaction-safe) and the messages SEPARATELY: codes + status ride on the
        // thrown error for downstream classification, while the messages are used ONLY transiently here to
        // compute the entitlement verdict and to build the same human log string as before (never stored raw).
        const errs = b?.errors ?? [];
        const codes = errs.map((e) => e.code).filter((c): c is number => typeof c === "number");
        // `message` OR `error`. Cloudflare is not consistent: most endpoints answer
        // `errors:[{code, message}]`, but some answer `errors:[{code, error}]`, and the account
        // endpoint-healthchecks endpoint is one. Reading only `message` left `messages` empty, so `why`
        // fell back to a bare "HTTP 400" and the operator, the log line and the support pack all got a
        // refusal with no reason on it. It also starved isCfPlanEntitlementError, which reads the messages
        // to decide whether a refusal is a plan gate, so those surfaces could not be classified either.
        const messages = errs
          .map((e) => e.message ?? e.error)
          .filter((m): m is string => typeof m === "string" && m.length > 0);
        const why = messages.join("; ") || `HTTP ${resp.status}`;
        // A 429 is a transient throttle (never an entitlement gate): it stays a rateLimitError carrying the
        // parsed Retry-After so withRetry waits the server-requested time, and, being a plain Error, not a
        // CfApiError, the discovery catch routes it to `unavailable` (the actionable bucket).
        if (resp.status === 429) {
          throw rateLimitError(`Cloudflare API ${method} ${path}: ${why}`, parseRetryAfter(resp.headers.get("retry-after")));
        }
        throw new CfApiError(`Cloudflare API ${method} ${path}: ${why}`, resp.status, codes, isCfPlanEntitlementError(resp.status, codes, messages));
      }
      return b?.result_info !== undefined ? { result: b?.result ?? null, result_info: b.result_info } : { result: b?.result ?? null };
    }, API_READ_RETRY);
  return {
    get: async (path) => (await callEnvelope("GET", path)).result ?? null,
    getPage: async (path) => {
      const b = await callEnvelope("GET", path);
      // A list endpoint returns an array; a single-object endpoint queried by mistake returns an
      // object, coerce both to an array so the paginator's accumulation is uniform (a non-array
      // result becomes a one-element page with no result_info, so paging stops immediately).
      // G110: a LIST endpoint that answers with a NULL/ABSENT result is not an empty list (that is `[]`), it is
      // a response shape we no longer recognise, and the coercion below turns it into a clean empty surface
      // with no marker and no counter. Count it, so a silent API-shape drift is visible in the pack instead of
      // riding as months of green runs. Only the closed counter moves; the body never leaves this function.
      if (b.result == null) recordShapeAnomaly("cf-config/list:null-result");
      const result = Array.isArray(b.result) ? b.result : b.result == null ? [] : [b.result];
      return b.result_info !== undefined ? { result, result_info: b.result_info } : { result };
    },
    send: (method, path, body) => callEnvelope(method, path, body).then((b) => b.result ?? null),
  };
}

// PAGINATION (SRC-4) ----------------------------------------------------------------------------
// A Cloudflare LIST endpoint returns at most one per_page page; the rest are reachable only by
// following the pages. The single-page reads (the old `one(... per_page=N)`) SILENTLY TRUNCATED any
// surface past one page (a zone with >per_page DNS records, firewall rules, custom hostnames, ...).
// paginate() follows every page to exhaustion and accumulates all results.
//
// Page-following supports both Cloudflare paging styles:
//  - PAGE-BASED (the classic list APIs: DNS, firewall access rules, filters, firewall rules, custom
//    hostnames, members, roles, certificate packs, ...): result_info carries {page, total_pages};
//    we request ?page=N&per_page=PER until page >= total_pages (or a short page, count<per_page,
//    proves the end even when total_pages is absent).
//  - CURSOR-BASED (some newer endpoints, e.g. parts of Access/Gateway/Lists): result_info carries a
//    `cursor` (or cursors.after); we pass it back as ?cursor=… until it is empty.
// It is BOUNDED: at most maxPages requests. If a surface still has more pages at that cap, we DO NOT
// loop forever and we DO NOT silently drop the tail, paginate throws a CfPaginationTruncated error
// (the adapter turns it into an honest "_truncated" marker, logged), so a truncation is always
// visible, never silent. Fail-open is preserved: any paging error degrades that one surface.
export const RULESETS_PER_PAGE = 50; // Cloudflare refuses per_page > 50 on the ruleset index (measured).
export const CF_PAGINATION_PER_PAGE = 1000; // Cloudflare's common list maximum; surfaces with a lower hard cap (custom hostnames 50, certificate packs 50) self-limit, paginate handles the rest.
export const CF_PAGINATION_MAX_PAGES = 1000; // a hard ceiling so a buggy/looping endpoint can never spin forever; 1000 pages * 1000/page = 1e6 items, far above any real config surface.

export class CfPaginationTruncated extends Error {
  readonly pagesRead: number;
  readonly accumulated: number;
  constructor(pagesRead: number, accumulated: number) {
    super(`pagination exceeded ${pagesRead} pages (accumulated ${accumulated} records) without exhausting the surface; truncated to avoid an unbounded loop`);
    this.name = "CfPaginationTruncated";
    this.pagesRead = pagesRead;
    this.accumulated = accumulated;
  }
}

// withParam appends a query parameter to a path that may already carry a query string.
function withParam(path: string, key: string, value: string | number): string {
  return `${path + (path.includes("?") ? "&" : "?")}${key}=${encodeURIComponent(String(value))}`;
}
// stripParam removes any pre-existing occurrences of a query parameter (the surface paths hard-code a
// per_page hint; the paginator owns paging, so it normalises page/per_page/cursor before driving).
function stripParam(path: string, key: string): string {
  const [base, query] = path.split("?", 2);
  if (!query) return base ?? path;
  const kept = query.split("&").filter((kv) => kv.split("=", 1)[0] !== key);
  return kept.length ? `${base}?${kept.join("&")}` : (base ?? path);
}

// paginate drives one list surface to exhaustion, metering one call per page, and returns every
// accumulated result. It chooses page-based vs cursor-based from the FIRST page's result_info, and
// guards against an unbounded loop with maxPages (throwing CfPaginationTruncated, never silently
// dropping). perPage/maxPages are injectable so the validator can exercise multi-page + the cap with
// tiny numbers; production passes the module defaults.
export async function paginate(
  api: CfApi,
  basePath: string,
  meter?: Meter,
  perPage: number = CF_PAGINATION_PER_PAGE,
  maxPages: number = CF_PAGINATION_MAX_PAGES,
): Promise<unknown[]> {
  // Normalise the path: drop any hard-coded paging hints, then add our per_page.
  const clean = withParam(stripParam(stripParam(stripParam(basePath, "page"), "per_page"), "cursor"), "per_page", perPage);
  const out: unknown[] = [];
  let page = 1;
  let cursor: string | undefined;
  let useCursor = false;
  for (let i = 0; i < maxPages; i++) {
    const path = useCursor && cursor !== undefined ? withParam(clean, "cursor", cursor) : withParam(clean, "page", page);
    meter?.spend(1, "cfApiRead");
    const pg = await api.getPage(path);
    for (const r of pg.result) out.push(r);
    const info = pg.result_info;
    // Cursor style: a non-empty cursor (top-level or nested) means another page follows.
    const nextCursor = info?.cursor ?? info?.cursors?.after;
    if (typeof nextCursor === "string" && nextCursor !== "") {
      useCursor = true;
      cursor = nextCursor;
      continue;
    }
    if (useCursor) return out; // cursor style and the cursor is now empty: exhausted.
    // Page style. Prefer total_pages when present; else stop when this page came back short
    // (fewer than per_page), a short/empty page is the end of a page-based list.
    const totalPages = typeof info?.total_pages === "number" ? info.total_pages : undefined;
    if (totalPages !== undefined) {
      if (page >= totalPages) return out;
    } else if (pg.result.length < perPage) {
      return out; // short page (covers single-object & no-result_info endpoints: result.length < perPage on the first page)
    }
    page++;
  }
  // Hit the page cap without exhausting: refuse to loop forever AND refuse to silently truncate.
  throw new CfPaginationTruncated(maxPages, out.length);
}

// Z/A are the path interpolation helpers (a surface's path needs the zone or account id).
export type Ids = { accountId: string; zoneId?: string };
// one builds a read that GETs a single (non-list / single-object) endpoint, metering one call.
// Use it ONLY for surfaces that return ONE object (zone settings object, gateway configuration,
// dns settings): a list-shaped surface must use list() so it pages (SRC-4).
export function one(pathFor: (ids: Ids) => string): CfConfigSurface["read"] {
  return (api, ids, meter) => {
    meter?.spend(1, "cfApiRead");
    return api.get(pathFor(ids));
  };
}
// list builds a read for a LIST-shaped surface (DNS records, firewall rules, custom hostnames,
// members, roles, ...): it PAGINATES via paginate() to exhaustion and returns the full array. A
// paging error (including the max-pages truncation guard) propagates so the adapter's per-surface
// fail-open turns it into a marker (an "_unavailable"/"_truncated" record), never a throw that
// breaks the whole snapshot. pathFor receives the ids and returns the BASE list path (no paging
// params, paginate adds them; any hard-coded per_page hint left on the path is normalised away).
export function list(pathFor: (ids: Ids) => string): CfConfigSurface["read"] {
  return (api, ids, meter) => paginate(api, pathFor(ids), meter);
}
// listCapped is list() for the endpoints that REFUSE the default per_page.
//
// Cloudflare's page-size ceiling is not uniform. Most collections accept the registry default, but AI
// Gateway and AI Search cap at 100, the registrar at 50, and custom-page assets at 200, each refusing
// with a different message. A surface reading with too large a page size does not degrade, it FAILS,
// and fail-open then archives it as an "_unavailable" marker. That is the worst shape a coverage bug
// can take: the surface looks registered, every run reports clean, and nothing is ever captured.
//
// A surface reading with too large a page size does not merely degrade; a read that never exercises the
// paginator with the surface's own page-size ceiling can be registered in a state where it never captures
// anything at all.
export function listCapped(pathFor: (ids: Ids) => string, perPage: number): CfConfigSurface["read"] {
  return (api, ids, meter) => paginate(api, pathFor(ids), meter, perPage);
}
// dig resolves a dotted path, so an envelope that nests its total (RealtimeKit's `paging.total_count`)
// can be read with the same option as one that does not (SCIM's `totalResults`).
function dig(obj: Record<string, unknown> | null, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

// NOT every refusal is a defect or an entitlement gate. Two surfaces refuse an ACCOUNT-OWNED token
// specifically: page-rules answers "Page Rules endpoint does not support account owned tokens", and
// zone-device-policy-certificates answers 1039 "malformed actor email claim" because an account-owned
// token carries no actor email. Both read normally under a user-owned token, so neither is capped or
// tolerated here; the token type is the variable. Recorded so the next sweep does not chase them.
//
// oneTolerating reads a single-object surface, treating a named set of Cloudflare error codes as EMPTY
// rather than as a failure.
//
// The Rulesets API answers a phase that has no entrypoint ruleset with error 10003, "could not find
// entrypoint ruleset in the http_request_snippets phase". That is not a fault: it is what Cloudflare says
// when nothing is configured in that phase, which is the state of most zones. Treating it as a fault gave
// every customer with no snippets and no cloud connector rules an "_unavailable" marker on two surfaces,
// which turns a normal empty configuration into an apparent backup shortfall. Note the two do not even
// agree on the status: snippets answers 404 and cloud connector answers 200 with success:false, so
// matching on the CODE rather than the status is what makes this reliable.
export function oneTolerating(pathFor: (ids: Ids) => string, codes: readonly number[]): CfConfigSurface["read"] {
  return async (api, ids, meter) => {
    meter?.spend(1, "cfApiRead");
    try {
      return await api.get(pathFor(ids));
    } catch (e) {
      if (e instanceof CfApiError && e.codes.some((c) => codes.includes(c))) return null;
      throw e;
    }
  };
}

// paginateAdaptive lists a collection, stepping the page size DOWN if Cloudflare refuses it.
//
// The read side names each surface's ceiling explicitly via listCapped, because a read is defined per
// surface and the ceiling is part of that definition. The WRITE side cannot: writeListSpec is one shared
// apply engine over dozens of collections, and it paginated live state at the registry default. Every
// surface whose ceiling is below that default therefore failed before it could diff, so its writer could
// never work no matter how correct the create body was. Found on ai-gateway-gateways and
// ai-search-namespaces, whose GETs were refused with "Number must be less than or equal to 100" while
// the surfaces' own read() succeeded, because only the read had been capped.
//
// Stepping down rather than requiring a per-surface number is deliberate: the alternative is a second
// table of ceilings that must be kept in step with the first, and a surface added with a cap on the read
// and no entry here would break again in exactly this silent way. The steps cover every ceiling measured
// against the live API (200, 100, 50, 10). A refusal that is NOT about the page size rethrows at once,
// so this never masks an auth or entitlement failure as a paging problem.
export async function paginateAdaptive(api: CfApi, basePath: string, meter?: Meter, perPage?: number): Promise<unknown[]> {
  const steps = perPage === undefined ? [CF_PAGINATION_PER_PAGE, 200, 100, 50, 10] : [perPage];
  let last: unknown;
  for (const pp of steps) {
    try {
      return await paginate(api, basePath, meter, pp);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      if (!/per_page|per page|less than or equal|expected number to be|Invalid pagination|Invalid list options|Invalid query params|must be between/i.test(msg)) throw e;
      last = e;
    }
  }
  throw last;
}

// expandIds reads a list that returns IDENTIFIERS ONLY and fetches each item's real object.
//
// rum-site-info is the case that found this: /rum/site_info/site_tag/list answers ["<site_tag>", ...] and
// nothing else, so the archive held a list of opaque ids while the host, the site token and the snippet
// configuration, which is the whole content, lived at /rum/site_info/{tag} and were never captured. A
// restore from that archive could not have rebuilt anything.
//
// It is a sibling of listWithSub rather than the same thing: listWithSub keeps the row and ATTACHES a
// nested collection to it, while this REPLACES a bare identifier with the object it names.
//
// Fail-open per item, like listWithSub: an id whose object cannot be read is kept as the bare id and a
// shape anomaly is recorded, so one unreadable item never costs the whole surface.
//
// NOT COVERED BY THE DRIFT GUARD, and worth saying rather than leaving to be discovered. That guard drives
// each read with a synthetic list whose item is an OBJECT, so the pass-through branch below is what runs
// and the per-item endpoint is never recorded in the baseline. Shaping the fixture to return a primitive
// just for this would be fitting the guard to one surface; the honest position is that this endpoint is
// exercised against the live API and not by the offline drift guard.
export function expandIds(
  listPathFor: (ids: Ids) => string,
  itemPathFor: (ids: Ids, id: string) => string,
  perPage?: number,
): CfConfigSurface["read"] {
  return async (api, ids, meter) => {
    const rows = (await paginate(api, listPathFor(ids), meter, perPage)) as unknown[];
    const out: unknown[] = [];
    for (const row of rows) {
      // An entry that is ALREADY an object is passed through untouched: a surface that starts returning
      // full objects must not be re-fetched item by item for no reason.
      if (isPlainObject(row)) {
        out.push(row);
        continue;
      }
      const id = typeof row === "string" ? row : "";
      if (id === "") {
        recordShapeAnomaly("cf-config/expand-ids:not-an-id");
        out.push(row);
        continue;
      }
      try {
        meter?.spend(1, "cfApiRead");
        out.push((await api.get(itemPathFor(ids, id))) ?? row);
      } catch {
        recordShapeAnomaly("cf-config/expand-ids:item-read-failed");
        out.push(row);
      }
    }
    return out;
  };
}

// listWithSub reads a collection whose items own a NESTED collection living at its own endpoint, and
// attaches that collection to each item so the snapshot holds the whole object.
//
// Gateway lists are the case this exists for. The list endpoint returns {id, name, type, count} and NO
// items: the values live at /gateway/lists/{id}/items. Without this, a backup would capture "this list has
// 3 entries" and none of the three, which for a Zero Trust allowlist or blocklist is the entire
// security-relevant content, and nothing would report a shortfall, because a count is a perfectly valid
// field and the surface reads cleanly.
//
// The sub-read is FAIL-OPEN per item: one list whose items cannot be read leaves that list's `items`
// absent and a shape anomaly recorded, rather than failing the surface and losing every other list too.
// An absent `items` is deliberately NOT an empty array: "we could not read them" and "there are none"
// must not look identical in an archive.
//
// It costs one extra metered call per item, which is why it is not the default shape for every surface.
export function listWithSub(
  pathFor: (ids: Ids) => string,
  subPathFor: (ids: Ids, id: string) => string,
  key: string,
  perPage?: number,
): CfConfigSurface["read"] {
  return async (api, ids, meter) => {
    const rows = (await paginate(api, pathFor(ids), meter, perPage)) as Array<Record<string, unknown>>;
    const out: Array<Record<string, unknown>> = [];
    for (const row of rows) {
      if (!isPlainObject(row)) {
        out.push(row);
        continue;
      }
      const id = typeof row.id === "string" ? row.id : "";
      if (id === "") {
        recordShapeAnomaly(`cf-config/${key}:no-id`);
        out.push(row);
        continue;
      }
      try {
        const sub = await paginate(api, subPathFor(ids, id), meter, perPage);
        out.push({ ...row, [key]: sub });
      } catch {
        recordShapeAnomaly(`cf-config/${key}:sub-read-failed`);
        out.push(row);
      }
    }
    return out;
  };
}

// listEnvelope reads an endpoint whose list does NOT sit at `result`, and pulls it out of a named key.
//
// Two of Cloudflare's own APIs need this. SCIM answers with an RFC 7644 ListResponse, so the users and
// groups live at `Resources`. CNI answers with a cursor envelope, so its interconnects live at `items`.
// Both previously threw on a 200 and archived as "_unavailable" markers while holding real data.
//
// It does NOT paginate: both endpoints page by their own scheme (startIndex for SCIM, a cursor for CNI)
// rather than by Cloudflare's page/per_page. So it does the next best thing and DETECTS a short read
// instead of assuming one page is all there is. `totalKey` names a field carrying the declared total
// (SCIM's totalResults) and `moreKey` names a field that is truthy when the server has more to give
// (CNI's next cursor). Either signal records a _truncated fault, so an archive that captured 66 of 500
// groups says so rather than presenting 66 as the whole set. totalResults equalling the returned length is
// a fact about a particular account's data, never a property to rely on.
export function listEnvelope(
  pathFor: (ids: Ids) => string,
  key: string,
  opts?: { totalKey?: string; moreKey?: string },
): CfConfigSurface["read"] {
  return async (api, ids, meter) => {
    meter?.spend(1, "cfApiRead");
    const body = (await api.get(pathFor(ids))) as Record<string, unknown> | null;
    const inner = body === null ? null : body[key];
    if (Array.isArray(inner)) {
      const declared = opts?.totalKey === undefined ? undefined : dig(body, opts.totalKey);
      if (typeof declared === "number" && declared > inner.length) {
        recordIncompleteFault("_truncated", "page-cap", { recordsAccumulated: inner.length });
      }
      const more = opts?.moreKey === undefined ? undefined : body?.[opts.moreKey];
      if (more !== undefined && more !== null && more !== false && more !== "") {
        recordIncompleteFault("_truncated", "cursor-stall", { recordsAccumulated: inner.length });
      }
      return inner;
    }
    // The key is absent or not an array: report the shape rather than inventing an empty list, because
    // "the envelope changed" and "there is nothing configured" must not look identical in an archive.
    recordShapeAnomaly(`cf-config/envelope:${key}-missing`);
    return { _unavailable: `the response did not carry an array at "${key}"` };
  };
}
// expandRulesets reads the ruleset index then each ruleset's rules (the unified Rulesets API holds
// WAF custom rules, managed overrides, rate-limiting, transforms, redirects, cache and origin
// rules, all as phases under one index). Account or zone depending on `scope`.
export function expandRulesets(scope: CfScope): CfConfigSurface["read"] {
  return async (api, ids, meter) => {
    const base = scope === "zone" ? `/zones/${ids.zoneId}` : `/accounts/${ids.accountId}`;
    // The ruleset INDEX is itself a list, paginate it so an account with many rulesets is not
    // truncated, then fetch each ruleset's rules by id (one metered call each).
    // RULESETS_PER_PAGE, not the registry default. Cloudflare answers `per_page` above 50 on the ruleset
    // index with "query parameter error: per_page cannot be greater than 50", so the default 1000 would make
    // BOTH ruleset surfaces throw and archive as "_unavailable" markers. That is the modern WAF
    // configuration in its entirety, and it is the most valuable thing the product captures; the ceiling is
    // 50, measured against the live API.
    const index = (await paginate(api, `${base}/rulesets`, meter, RULESETS_PER_PAGE)) as Array<{ id?: string }>;
    const out: unknown[] = [];
    for (const rs of index) {
      if (typeof rs?.id !== "string") {
        // G110: a ruleset the index returned WITHOUT an id is silently dropped here. If Cloudflare ever renames
        // that field, EVERY ruleset is dropped and the surface archives as an empty array while the run reports
        // a clean ok. Count the tolerant-parse drop (a closed product-token scope, never the malformed object).
        recordShapeAnomaly("cf-config/rulesets:index-item");
        continue;
      }
      meter?.spend(1, "cfApiRead");
      try {
        out.push(await api.get(`${base}/rulesets/${rs.id}`));
      } catch (e) {
        // G068: ONE ruleset failing (an Enterprise-phase ruleset the plan does not entitle, a 403 on a deleted
        // site) voids the WHOLE rulesets surface: the throw propagates and the adapter marks the surface
        // "_unavailable", so the pack sees only the bare surface id and never WHICH ruleset sank it, nor that
        // every other ruleset read fine. Record the failing item under a COMPOUND id before rethrowing (the
        // ruleset id is customer-owned, so it is reduced to a stable one-way handle, never carried raw), with
        // the closed reason class. Per-item fail-open is a separate behaviour fix; the evidence closes now.
        recordIncompleteFault("_unavailable", classifySourceFaultReason(e), { id: await faultItemId("cf-config/rulesets", rs.id) });
        throw e;
      }
    }
    return out;
  };
}
