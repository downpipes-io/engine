// Platform-issued ingest credentials + the credentialed /support pull routes. Moved
// verbatim out of support.ts (which keeps the bundle assembly/signing this module serves);
// behaviour is unchanged.

import { b64urlEncode, constantTimeEqual, hexEncode, utf8 } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import type { Env } from "../env.d.ts";
import { bumpAdminCounter, bumpAdminCounters, recordExportAttempt } from "./diag-counters.ts";
import type { AdminCounterName } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { doURL } from "../do-url.ts";
import { sealedSupportBundle } from "./support.ts";
import { grantExpiryState, nowIso } from "./support-shared.ts";

// ---- platform-issued ingest credentials (client/secret) ------------------------------
//
// The platform issues a CLIENT/SECRET credential per scope, the shape every SIEM
// HTTP-pull connector and the vendor's support tooling understands:
//   - scope "diagnostics": vendor support pulls the signed bundle during a ticket
//     (short-lived; 7-day cap, 72-hour default).
//   - scope "audit-feed": the customer's SIEM collector polls the hash-chained audit
//     events (long-lived; 365-day cap, 90-day default), seq-cursored for checkpointing.
//   - scope "metrics": a Prometheus-compatible scraper (Prometheus, Grafana, the Datadog/
//     New Relic/Dynatrace/Elastic/Splunk Observability agents, Grafana Cloud's agentless
//     scraper) pulls the /metrics text-exposition surface (admin/metrics.ts). It is the
//     same pull-connector shape as the other two scopes (a scrape target is exactly a
//     bearer-presenting pull client), so it reuses this mint/check/revoke machinery
//     rather than a parallel credential mechanism; the longest cap of the three (meant to
//     sit in a scrape config indefinitely, still expiring and re-mintable, never permanent).
// One credential is active per scope; re-granting replaces it; revocation is immediate.
// The clientId is a non-secret lookup label; the SECRET is shown once at grant and only
// its SHA-384 persists; verification is constant-time; the MOST RECENT 50 pulls are recorded on the
// grant (older entries roll over), so the customer sees when each credential was used.
// The credential is presented as a single bearer (Authorization: Bearer <clientId>.<secret>)
// because one opaque field fits every collector's configuration form.

export type IngestScope = "diagnostics" | "audit-feed" | "metrics";

export const INGEST_TTL_CAPS_SECONDS: Record<IngestScope, { max: number; default: number }> = {
  diagnostics: { max: 7 * 24 * 3600, default: 72 * 3600 },
  "audit-feed": { max: 365 * 24 * 3600, default: 90 * 24 * 3600 },
  metrics: { max: 400 * 24 * 3600, default: 365 * 24 * 3600 },
};

export interface IngestGrant {
  clientId: string; // non-secret label, e.g. dpc_xxxxxxxx
  secretSha384: string; // hex SHA-384 of the secret; the secret itself is never stored
  scope: IngestScope;
  grantedAt: string;
  grantedBy: string | null; // the granting Owner's verified email (null for the bare-token path)
  expiresAt: string;
  pulls: { at: string }[]; // the most recent 50 pulls (customer-visible; the DO rolls older entries over)
}

// mintIngestCredential creates the credential and its storable grant record. The secret
// is shown ONCE in the grant response and never again.
export async function mintIngestCredential(scope: IngestScope, grantedBy: string | null, ttlSeconds: number | undefined): Promise<{ clientId: string; secret: string; grant: IngestGrant }> {
  const caps = INGEST_TTL_CAPS_SECONDS[scope];
  const ttl = Math.min(Math.max(Math.floor(ttlSeconds ?? caps.default), 60), caps.max);
  const clientId = `dpc_${b64urlEncode(crypto.getRandomValues(new Uint8Array(9)))}`;
  const secret = `dps_${b64urlEncode(crypto.getRandomValues(new Uint8Array(24)))}`;
  const grant: IngestGrant = {
    clientId,
    secretSha384: hexEncode(await sha384(utf8(secret))),
    scope,
    grantedAt: nowIso(),
    grantedBy,
    expiresAt: new Date(Date.now() + ttl * 1000).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    pulls: [],
  };
  return { clientId, secret, grant };
}

// classifyIngestCredentialCheck is checkIngestCredential's SINGLE implementation, returning the CLOSED
// reason the check failed instead of a bare false. A never-minted credential, an expired one and a
// rotated secret the scraper was never updated with would otherwise all produce the same 401, so the
// cause would be undiagnosable from the pack.
//
// ANTI-ORACLE: the reason is recorded PACK-SIDE only. Every caller still answers the client with
// the same bare, detail-free 401 -- no branch here is ever oracled back to a presenter, and the secret
// comparison stays constant-time. The returned value is a member of a closed enum, never the bearer, the
// clientId or the stored hash.
export type IngestCheckOutcome = "ok" | "no-grant" | "credential-expired" | "credential-expiry-unreadable" | "bearer-malformed" | "client-id-mismatch" | "secret-mismatch";

export async function classifyIngestCredentialCheck(presented: string, grant: IngestGrant | null): Promise<IngestCheckOutcome> {
  if (!grant) return "no-grant";
  const expiry = grantExpiryState(grant.expiresAt);
  // The unreadable arm is FIRST and distinct: it is not an expiry verdict, it is the absence of one.
  if (!expiry.readable) return "credential-expiry-unreadable";
  if (expiry.expired) return "credential-expired";
  const dot = presented.indexOf(".");
  if (dot <= 0) return "bearer-malformed";
  const clientId = presented.slice(0, dot);
  const secret = presented.slice(dot + 1);
  if (clientId !== grant.clientId) return "client-id-mismatch";
  if (!secret.startsWith("dps_")) return "bearer-malformed";
  const presentedHash = await sha384(utf8(secret));
  const stored = grant.secretSha384;
  if (stored.length !== 96 || !/^[0-9a-f]+$/.test(stored)) return "secret-mismatch";
  const storedBytes = new Uint8Array(48);
  for (let i = 0; i < 48; i++) storedBytes[i] = parseInt(stored.slice(i * 2, i * 2 + 2), 16);
  return constantTimeEqual(presentedHash, storedBytes) ? "ok" : "secret-mismatch";
}

// checkIngestCredential verifies a presented bearer ("<clientId>.<secret>") against the
// stored grant: clientId match (non-secret), CONSTANT-TIME hash comparison of the
// secret, and server-side expiry. It never logs or echoes the presented value. It is now a thin
// yes/no over classifyIngestCredentialCheck, so the gate and the recorded reason can never diverge.
export async function checkIngestCredential(presented: string, grant: IngestGrant | null): Promise<boolean> {
  return (await classifyIngestCredentialCheck(presented, grant)) === "ok";
}

// redactGrant is the customer-facing view of a grant (GET /admin/support): everything
// except the secret hash, which has no reason to leave the store.
//
// redactGrant answers the question every existing reader is ACTUALLY asking -- "is this credential
// still usable" -- for which an unreadable expiry is `true`, because the gate refuses it. The
// discriminating fact rides BESIDE it rather than replacing it: `expiryUnreadable` appears only in
// the third state, so a reader that knows about it can say "unreadable" instead of "expired", and one
// that does not is at worst coarse rather than inverted. It never carries the timestamp text that
// would not parse.
export function redactGrant(grant: IngestGrant | null): Record<string, unknown> | null {
  if (!grant) return null;
  const expiry = grantExpiryState(grant.expiresAt);
  return {
    clientId: grant.clientId,
    scope: grant.scope,
    grantedAt: grant.grantedAt,
    grantedBy: grant.grantedBy,
    expiresAt: grant.expiresAt,
    expired: expiry.readable ? expiry.expired : true,
    ...(expiry.readable ? {} : { expiryUnreadable: true }),
    pulls: grant.pulls,
  };
}

// handleSupportPull serves the two credentialed pull routes OUTSIDE /admin (no console,
// no Access seat, no admin token): GET /support/diagnostics (the sealed/signed bundle)
// and GET /support/audit-feed?afterSeq=N&limit=M (the hash-chained audit events,
// ascending, seq-cursored for collector checkpointing). The bearer is the platform-
// issued client/secret credential for the matching scope; verification is constant-time
// against the stored hash with server-side expiry; a failed presentation is a plain 401
// with no detail; every successful pull is recorded on the grant for the customer to
// see. Brute force is not a realistic path (the secret carries 192 bits of entropy and
// the comparison leaks no timing), and the surface returns ONLY redaction-safe
// diagnostics, never customer data, keys or configuration writes.
// AUTH_FAILURE_THROTTLE_MS bounds how often a REJECTED pull may drive a diagnostic write. See the call site:
// the branch is reachable by any unauthenticated caller, so recording every attempt would make the observer a
// write amplifier for the attack it is observing. Isolate-local (there is no cross-isolate state to keep, and
// a per-isolate window is exactly the granularity the counter's "is it still happening" question needs).
const AUTH_FAILURE_THROTTLE_MS = 60_000;
let lastAuthFailureRecordedAt = 0;

/**
 * shouldRecordAuthFailure reports whether a rejected-bearer counter bump may be issued now, at most once per
 * AUTH_FAILURE_THROTTLE_MS per isolate. Exported so the validator can pin the anti-amplification property
 * directly rather than inferring it from a round-trip count.
 *
 * @param now - the clock, injected so the validator is deterministic.
 * @returns true when the bump should be issued.
 */
export function shouldRecordAuthFailure(now = Date.now()): boolean {
  if (now - lastAuthFailureRecordedAt < AUTH_FAILURE_THROTTLE_MS) return false;
  lastAuthFailureRecordedAt = now;
  return true;
}

/** resetAuthFailureThrottle clears the isolate-local window. Test-only seam. */
export function resetAuthFailureThrottle(): void {
  lastAuthFailureRecordedAt = 0;
}

// classifyIngestCredentialCheck exists precisely so a refused presentation names WHICH of the five ways
// it failed. That class is threaded into the METRICS scrape surface's own health (admin/metrics.ts
// threads the outcome into METRICS_SCRAPE_OUTCOMES) and into the two /support pulls below, so the SIEM
// audit feed -- the pull whose whole purpose is to be answerable -- can say not just how many pulls were
// rejected, but whether the collector holds a stale clientId from a prior mint (re-issue the
// credential), a secret from before a rotation (update the collector), or nothing at all: three
// different remedies on the CUSTOMER's side.
//
// The generic counter is kept and bumped alongside, in the SAME single write: everything that reads it
// (the pack projection, validate-admin-fault-evidence's vocabulary assertion) is unchanged, and the
// discriminating name rides beside it rather than replacing it. bumpAdminCounters takes both names in
// ONE DO round-trip, so the anti-amplification property the throttle exists for holds: one write per
// window.
//
// The outward 401 is unchanged and stays flat: nothing here is ever oracled back to the presenter.
const INGEST_PULL_REFUSAL_COUNTERS: Readonly<Record<Exclude<IngestCheckOutcome, "ok">, AdminCounterName>> = {
  "no-grant": "ingest-pull-refused-no-grant",
  "credential-expired": "ingest-pull-refused-credential-expired",
  // G312: kept APART from credential-expired on purpose. "Re-mint, the TTL ran out" and "the stored grant is
  // corrupt, re-mint AND look at what corrupted it" are different tickets, and blending them would be this
  // module's own G161-B defect one member later.
  "credential-expiry-unreadable": "ingest-pull-refused-credential-expiry-unreadable",
  "bearer-malformed": "ingest-pull-refused-bearer-malformed",
  "client-id-mismatch": "ingest-pull-refused-client-id-mismatch",
  "secret-mismatch": "ingest-pull-refused-secret-mismatch",
};

/**
 * ingestPullRefusalCounter maps a non-ok pull outcome to its closed counter name. Exported so the validator
 * pins the map against the classifier's own union rather than re-listing the members by hand (a second list
 * is exactly how a new outcome comes to be booked as nothing at all).
 *
 * @param outcome - the closed classifier outcome, "ok" included.
 * @returns the counter name, or null for "ok" (nothing is refused, so nothing is booked).
 */
export function ingestPullRefusalCounter(outcome: IngestCheckOutcome): AdminCounterName | null {
  return outcome === "ok" ? null : INGEST_PULL_REFUSAL_COUNTERS[outcome];
}

export async function handleSupportPull(req: Request, env: Env, scheduler: DurableObjectStub): Promise<Response> {
  const url = new URL(req.url);
  const scope: IngestScope | null = url.pathname === "/support/diagnostics" ? "diagnostics" : url.pathname === "/support/audit-feed" ? "audit-feed" : null;
  if (scope === null || req.method !== "GET") return new Response("not found", { status: 404 });
  const auth = req.headers.get("Authorization") ?? "";
  const presented = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length).trim() : "";
  // Short-circuit an absent bearer BEFORE the DO round-trip (finding F7): an unauthenticated flood of
  // /support/* would otherwise cost one SchedulerDO fetch per request just to be rejected, a softer DoS
  // target than /metrics (which already checks its empty bearer before touching the DO). A missing bearer can
  // never pass checkIngestCredential, so rejecting it here is behaviour-identical and strictly cheaper.
  if (presented === "") return new Response("unauthorised", { status: 401 });
  let grant: IngestGrant | null = null;
  try {
    const resp = await scheduler.fetch(doURL(`/ingest-credential?scope=${scope}`), { method: "GET" });
    ({ grant } = (await resp.json()) as { grant: IngestGrant | null });
  } catch {
    // G161: the grant could not be READ, so the pull is refused FAIL-CLOSED. The collector is locked out
    // by an ENGINE fault, not by a credential fault.
    void bumpAdminCounter(scheduler, "ingest-pull-grant-unreadable");
    return new Response("unavailable", { status: 503 });
  }
  // G161-B: classify ONCE and keep the class, rather than running the same classifier through the boolean
  // wrapper and discarding what it decided. The gate is unchanged -- "ok" is still the only outcome that
  // passes -- so this cannot admit a presentation the boolean refused, nor refuse one it admitted.
  const outcome = await classifyIngestCredentialCheck(presented, grant);
  if (outcome !== "ok") {
    // The outward 401 is UNCHANGED and stays flat (the anti-enumeration property is preserved): the
    // count is recorded pack-side only, so support can say "you have had 4,000 rejected pulls since
    // Tuesday" with a discriminating cause attached.
    //
    // THROTTLED, and that is load-bearing. This branch is reachable by ANY UNAUTHENTICATED caller, so an
    // unthrottled recorder would let a 401 storm drive a DO STORAGE WRITE per request -- turning the very act
    // of observing an attack into a write amplifier for it, on the one route whose anti-DoS ordering (the
    // zero-round-trip rejection of an absent/empty bearer, above) exists precisely to deny that. The throttle
    // is the established idiom for a recorder on an attacker-reachable path: the counter now counts the
    // distinct ~minute WINDOWS in which rejections occurred rather than individual attempts, so it can only
    // UNDER-count, never over-count; lastAt stays exact; and the question it answers ("is this still
    // happening, and since when?") is unchanged.
    //
    // G161-B: the DISCRIMINATING class rides in the SAME single write as the generic count, so the write rate
    // (and therefore the anti-amplification property above) is byte-for-byte what it was.
    if (shouldRecordAuthFailure()) {
      const discriminating = ingestPullRefusalCounter(outcome);
      void bumpAdminCounters(scheduler, { "ingest-pull-auth-failed": 1, ...(discriminating !== null ? { [discriminating]: 1 } : {}) });
    }
    return new Response("unauthorised", { status: 401 });
  }
  // Record the pull (best-effort; the customer-visible usage trail on the grant).
  //
  // G331: CHECKED. This trail is the ONLY evidence a credential is in live use, so a dropped write makes an
  // ACTIVE collector read as ABANDONED in the pack (and support then hunts a decommissioned integration that
  // is in fact polling every minute). recordDiagWrite counts the loss in droppedWrites rather than swallowing
  // it; the pull response is unchanged and is never delayed by the bookkeeping.
  void recordDiagWrite(scheduler, "support-pull-trail", () =>
    scheduler.fetch(doURL("/ingest-credential/record-pull"), {
      method: "POST",
      body: JSON.stringify({ scope, at: nowIso() }),
      headers: { "content-type": "application/json" },
    }),
  );

  if (scope === "diagnostics") {
    // accessPerimeter (G267): a pull that ARRIVED means the collector got THROUGH the perimeter, but the header
    // still says whether one fronts this host (an Access service token would also carry it). Threaded from this
    // request so a vendor-pulled pack carries the same presence boolean the console download does.
    //
    // Guarded (the diagnostics leg builds and SIGNS the whole bundle): a throw inside the seal is caught
    // and recorded, rather than 500'ing the pull anonymously, which is the worst possible failure for the
    // one surface whose entire job is remote diagnosis.
    try {
      const bundle = await sealedSupportBundle(env, scheduler, { accessPerimeter: req.headers.get("cf-access-jwt-assertion") !== null });
      return new Response(JSON.stringify(bundle), { headers: { "content-type": "application/json" } });
    } catch {
      void bumpAdminCounter(scheduler, "ingest-pull-seal-failed");
      return new Response("unavailable", { status: 503 });
    }
  }
  // audit-feed: ascending events with seq > afterSeq, bounded, with the chain head so a
  // collector can checkpoint by seq and verify continuity by prevHash/hash. The afterSeq tail cursor and
  // the limit are pushed DOWN into the DO's export (as query parameters), so the DO returns only the
  // matching window instead of the whole retained log; the Worker no longer loads and filters the entire
  // export in memory (engine-src-022-07).
  //
  // Strict cursor (finding F6): afterSeq is the collector's CHECKPOINT, so a malformed value must not be
  // silently coerced to 0 -- that would replay the whole retained log and, worse, hide a client bug that
  // keeps re-sending a corrupt cursor (a permanent silent re-scan). An absent (or empty) afterSeq defaults to
  // 0 as before; a PRESENT value that is not a finite non-negative number is a clear 400. The limit stays
  // leniently clamped (a page-size hint, the conventional treatment), only the cursor is validated.
  const afterSeqParam = url.searchParams.get("afterSeq");
  let afterSeq = 0;
  if (afterSeqParam !== null && afterSeqParam !== "") {
    const n = Number(afterSeqParam);
    if (!Number.isFinite(n) || n < 0) {
      // G161: a corrupt persisted cursor would otherwise silently coerce to 0, replaying the whole retained
      // log and hiding a client bug that keeps re-sending a corrupt cursor. The 400 is recorded pack-side.
      void bumpAdminCounter(scheduler, "ingest-pull-bad-cursor");
      return new Response(JSON.stringify({ error: "afterSeq must be a non-negative integer" }), { status: 400, headers: { "content-type": "application/json" } });
    }
    afterSeq = Math.floor(n);
  }
  const limit = Math.min(Math.max(Math.floor(Number(url.searchParams.get("limit") ?? "500")) || 500, 1), 1000);
  // Guarded: an audit-export fault here is caught and recorded rather than 500'ing the feed anonymously
  // while the grant keeps looking perfectly healthy.
  //
  // G022: the collector's HALF of the export-attempt record. The counter above is a rate; this is the ledger
  // the pack projects, and it is what distinguishes the SIEM silently missing a day (this channel) from an
  // operator staring at a failed download (the console channel), on the same aggregate. A feed pull is always
  // a cursored JSON page, so format/filtered are fixed by construction; the cursor itself never rides.
  let doc: { events: Array<{ seq: number }>; headSeq: number; headHash: string; earliestSeq?: number };
  try {
    const exportResp = await scheduler.fetch(doURL(`/audit/export?afterSeq=${afterSeq}&limit=${limit}`), { method: "GET" });
    if (!exportResp.ok) {
      void bumpAdminCounter(scheduler, "ingest-pull-audit-export-failed");
      await recordExportAttempt(scheduler, { channel: "collector-feed", format: "json", outcome: "do-error", filtered: true });
      return new Response("unavailable", { status: 503 });
    }
    doc = (await exportResp.json()) as { events: Array<{ seq: number }>; headSeq: number; headHash: string; earliestSeq?: number };
  } catch {
    void bumpAdminCounter(scheduler, "ingest-pull-audit-export-failed");
    await recordExportAttempt(scheduler, { channel: "collector-feed", format: "json", outcome: "do-unavailable", filtered: true });
    return new Response("unavailable", { status: 503 });
  }
  await recordExportAttempt(scheduler, { channel: "collector-feed", format: "json", outcome: "ok", filtered: true });
  const events = doc.events;
  const nextAfterSeq = events.length > 0 ? events[events.length - 1]!.seq : afterSeq;
  // earliestSeq is the oldest entry still retained. A collector compares it to its checkpoint: when
  // afterSeq + 1 < earliestSeq, entries between them were pruned by retention rollover and will NEVER be
  // delivered (a silent audit GAP the headSeq alone could not reveal, finding F2). gapBefore surfaces that
  // explicitly so the collector can alarm rather than trust an unbroken feed. earliestSeq defaults to 0 for
  // an older engine that does not report it (the collector then simply sees no gap signal, as before).
  const earliestSeq = typeof doc.earliestSeq === "number" ? doc.earliestSeq : 0;
  const gapBefore = earliestSeq > 0 && afterSeq + 1 < earliestSeq;
  // G161: a SERVED retention gap is a compliance fact ("were audit entries destroyed before the collector
  // could take them?"), so it is counted -- never a seq range, an event or a caller.
  if (gapBefore) void bumpAdminCounter(scheduler, "ingest-pull-gap-served");
  return new Response(
    JSON.stringify({ kind: "downpipe-audit-feed", v: 1, afterSeq, nextAfterSeq, earliestSeq, gapBefore, headSeq: doc.headSeq, headHash: doc.headHash, count: events.length, events }),
    { headers: { "content-type": "application/json" } },
  );
}
