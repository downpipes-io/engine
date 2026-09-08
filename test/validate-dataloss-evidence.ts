// validate-dataloss-evidence: the four remaining DATA-LOSS support-pack gaps, each driven as a REAL fault,
// through the REAL recorder, the REAL Durable Object, and into a REAL built support bundle.
//
//   SOURCE-DISCOVERY OUTCOMES. GET /sources/discover is fail-open per product: a token missing the R2
//         scope answers 200 with an EMPTY bucket list, and the customer builds their whole backup estate
//         against a form that silently omitted the resources they most needed to protect. "The form is empty"
//         and "the account is empty" were the same observation, everywhere, with no engine-side recorder at all.
//   THE FAILED AUDIT-LOG EXPORT. Both export paths were pass-throughs that recorded nothing when they
//         failed, so a customer who cannot get their tamper-evident evidence OUT of the account left no trace:
//         the pack showed an intact chain, every event present, and nothing saying none of it could be produced.
//         (The audit ROLLOVER signal remains deliberately unshipped: a legitimate rollover is not tamper.)
//   THE FORCED REMOVAL OF THE ONLY PROVEN COPY. The single most destructive operator action in the
//         product, and it was smart-retained only by ACTION NAME -- so one later benign dest clear evicted it
//         from the excerpt, and 40 events of ordinary churn evicted it from the recent window.
//   CONFIG-VERSION BODY RETENTION. The history lists headers; the snapshot you would roll back TO is a
//         separate body, and nothing ever checked it was still there. Ten versions listed as restorable, and
//         you find out which are real in the middle of the incident.
//
// THE BAR: a gap is NOT closed
// until its evidence is in the BUNDLE. So no hop here is taken on trust. Every case drives the REAL fault site,
// lets the REAL SchedulerDO (over MockStorage) apply the REAL chokepoint, and then asserts against the output
// of the REAL buildSupportBundle. A recorder with no caller, or a DO route no gatherer fetches, fails here.
//
// NO-CUSTODY: every case plants customer SENTINELS at the fault site (a bucket, a namespace, an account name,
// an operator e-mail, a Cloudflare message) and asserts that not one of them appears in ANY byte of the stored
// record, the projected section, or the whole bundle.
//
// Run: node test/validate-dataloss-evidence.ts

import { makeScheduler, type MockStorage } from "./validate-scheduler-shared.ts";
import { handleDiscovery } from "../src/admin/router-discovery.ts";
import { handleRbac } from "../src/admin/router-rbac.ts";
import { applyDiscoveryHealth, classifyDiscoveryError, classifyDiscoveryListing, DISCOVERY_OUTCOMES, DISCOVERY_PRODUCTS } from "../src/admin/discovery-health.ts";
import { applyExportAttempt, EXPORT_ATTEMPT_OUTCOMES } from "../src/admin/diag-records.ts";
import { scanConfigBodies, configHistoryKey, type ConfigVersion } from "../src/admin/config-history.ts";
import { fetchDiscoveryHealth } from "../src/admin/support-sections-config.ts";
import { fetchAuditExportAttempts } from "../src/admin/support-sections-audit.ts";
import { resetPendingDroppedWrites, } from "../src/admin/diag-writer.ts";
import { buildSupportBundle, SUPPORT_SECTION_NAMES } from "../src/admin/support.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- the CUSTOMER SENTINELS ------------------------------------------------------------------------------
// Each is planted at a real fault site below. None may appear in any recorded byte.
const SENTINEL_BUCKET = "acme-prod-customer-invoices";
const SENTINEL_ACCOUNT = "Acme Pty Ltd (production)";
const SENTINEL_ACCOUNT_ID = "0123456789abcdef0123456789abcdef";
const SENTINEL_NAMESPACE = "acme-session-store";
const SENTINEL_EMAIL = "cfo@acme.example";
const SENTINEL_TOKEN = "cf-token-Ax9-SECRET-Vv1";
const SENTINEL_MESSAGE = "Authentication error (10000): token lacks com.cloudflare.edge.r2.bucket.read";
const SENTINELS = [SENTINEL_BUCKET, SENTINEL_ACCOUNT, SENTINEL_ACCOUNT_ID, SENTINEL_NAMESPACE, SENTINEL_EMAIL, SENTINEL_TOKEN, SENTINEL_MESSAGE];

function scanForSentinels(v: unknown): string[] {
  const hay = JSON.stringify(v) ?? "";
  return SENTINELS.filter((s) => hay.includes(s));
}

// ---- the harness ------------------------------------------------------------------------------------------
// The scheduler is a REAL SchedulerDO over MockStorage, so every recorder writes through the production route,
// the production applier and production storage, and every pack gatherer reads it back through the production
// route. `faultOn` injects ONE fault into that real DO (a path that answers 503 or throws), which is how the
// export-availability gap is driven without pretending the rest of the engine is a fixture.
// The DO's own snapshot path, reached directly for the G098 seed: it is the ONE production write path for a
// config version (real hash chain, real in-DO signing key, real storage key), so the versions this test then
// damages are the versions production would hold.
type SchedulerDOish = { fetch(req: Request): Promise<Response>; snapshotConfigNow(author: string | null): Promise<{ created: boolean }> };
type Sched = { storage: MockStorage; stub: DurableObjectStub; dobj: SchedulerDOish };
function realScheduler(faultOn?: { path: string; mode: "non-2xx" | "throw" }): Sched {
  const { storage, stub } = makeScheduler();
  const real = stub as unknown as SchedulerDOish;
  const wrapped = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const req = input instanceof Request ? input : new Request(String(input), init);
      const path = new URL(req.url).pathname;
      if (faultOn !== undefined && path === faultOn.path) {
        if (faultOn.mode === "throw") throw new Error(`durable object unreachable: ${SENTINEL_TOKEN}`);
        return new Response("unavailable", { status: 503 });
      }
      return real.fetch(req);
    },
  } as unknown as DurableObjectStub;
  return { storage, stub: wrapped, dobj: real };
}

const OWNER: Caller = { method: "token", email: null, subject: null, role: "owner" } as unknown as Caller;

function routerCtx(sched: Sched, env: Env, method: string, sub: string, search = ""): RouterCtx {
  const url = new URL(`https://engine.example/admin${sub}${search}`);
  return {
    req: new Request(url.toString(), { method }),
    env,
    url,
    scheduler: sched.stub,
    caller: OWNER,
    sub,
    sourceIp: null,
    runtime: undefined,
    verdict: { ok: true } as never,
  } as unknown as RouterCtx;
}

// ---------------------------------------------------------------------------------------------------------
// a SCOPE-BLIND, TRUNCATED, PART-EMPTY discovery -- driven through the real route with a real CF API.
// ---------------------------------------------------------------------------------------------------------
// The global fetch stands in for the Cloudflare API. It answers the account list, a REAL 403 on R2 (the scope
// gap), a FULL page of KV namespaces (the silent truncation), an honestly empty D1, and a 429 on zones. Every
// answer carries a customer sentinel, because the real ones do.
function cloudflareApiDouble(): void {
  const page = (items: unknown[], extra: Record<string, unknown> = {}): Response =>
    new Response(JSON.stringify({ result: items, result_info: { total_pages: 1 }, ...extra }), { status: 200 });
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const path = new URL(input instanceof Request ? input.url : String(input)).pathname;
    if (path.endsWith("/accounts")) return page([{ id: SENTINEL_ACCOUNT_ID, name: SENTINEL_ACCOUNT }]);
    if (path.includes("/r2/buckets")) {
      // The SCOPE GAP: a 403 whose body names the bucket the customer most needs backed up. cfApi turns this
      // into `HTTP 403`, the lister prefixes it "r2: ", and the route answers 200 with an EMPTY bucket list.
      return new Response(JSON.stringify({ errors: [{ message: SENTINEL_MESSAGE }], bucket: SENTINEL_BUCKET }), { status: 403 });
    }
    if (path.includes("/storage/kv/namespaces")) {
      // The SILENT TRUNCATION: a full page (LIST_CAP) of namespaces. Namespace 501 exists and will never be
      // offered on the form.
      return page(Array.from({ length: 500 }, (_, i) => ({ id: `ns${i}`, title: `${SENTINEL_NAMESPACE}-${i}` })));
    }
    if (path.includes("/d1/database")) return page([]); // an HONESTLY empty product: this one is not a fault
    if (path.includes("/secrets_store/stores")) return page([]);
    if (path.startsWith("/client/v4/zones")) return new Response("slow down", { status: 429 });
    return page([]);
  }) as typeof fetch;
}

async function g008(): Promise<void> {
  console.log("\nsource-discovery outcomes reach the bundle:");
  const sched = realScheduler();
  const env = { DISCOVERY_API_TOKEN: SENTINEL_TOKEN } as unknown as Env;
  cloudflareApiDouble();

  const resp = await handleDiscovery(routerCtx(sched, env, "GET", "/sources/discover"));
  ok("the discover route still answers 200 (fail-open is UNCHANGED: this records, it does not gate)", resp?.status === 200);
  const body = (await resp!.json()) as { accounts?: Array<{ r2?: unknown[] }> };
  ok("and it STILL hands the console an empty r2 list -- which is exactly the lie this gap is about", (body.accounts?.[0]?.r2 ?? []).length === 0);

  // The DO's stored record, read through the production route.
  const stored = (await (await sched.stub.fetch(new Request("https://do/discovery-health"))).json()) as { health?: Record<string, unknown> };
  const h = stored.health ?? {};
  const last = (h.lastOutcome ?? {}) as Record<string, string>;
  ok("the fault site RECORDED (a recorder now exists at all: grep sourceDiscovery used to return nothing)", h.observations === 1);
  ok("r2 is recorded DENIED, not empty -- the scope gap the empty form was hiding", last.r2 === "denied");
  ok("kv is recorded TRUNCATED -- the namespaces past the page cap the form will never offer", last.kv === "truncated");
  ok("d1 is recorded EMPTY -- an honestly empty product is NOT a fault, and must not read as one", last.d1 === "empty");
  ok("zones is recorded RATE-LIMITED, a transient cause distinct from a missing scope", last.zones === "rate-limited");
  ok("the observation is counted DEGRADED (the console's 'your account has no sources' is not to be trusted)", h.degradedObservations === 1);
  ok("engineAccountKnown rides: a single-account token names the engine's own account, so attach is possible", h.engineAccountKnown === true);
  ok("REDACTION: the STORED record carries no bucket, namespace, account, token or Cloudflare message", scanForSentinels(h).length === 0);

  const projected = await fetchDiscoveryHealth(sched.stub);
  ok("the pack projector reads it back", (projected.lastOutcome as Record<string, string>)?.r2 === "denied");
  ok("REDACTION: the PROJECTED section carries no sentinel", scanForSentinels(projected).length === 0);

  const bundle = await buildSupportBundle({} as unknown as Env, sched.stub);
  const dh = bundle.discoveryHealth as Record<string, unknown> | undefined;
  ok("THE BUNDLE CARRIES discoveryHealth", dh !== undefined);
  ok("THE BUNDLE distinguishes the scope-blind product from the empty one", (dh?.lastOutcome as Record<string, string>)?.r2 === "denied" && (dh?.lastOutcome as Record<string, string>)?.d1 === "empty");
  ok("discoveryHealth is on the closed roster, so it cannot slip past the sections health vector", SUPPORT_SECTION_NAMES.includes("discoveryHealth" as never));
  ok("the sections vector reports it gathered (ok), not error", (bundle.sections as Record<string, string>).discoveryHealth === "ok");
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel", scanForSentinels(bundle).length === 0);

  // A discovery with NO TOKEN: the account-wide tier is never attempted at all, and that is its own state.
  const noTok = realScheduler();
  await handleDiscovery(routerCtx(noTok, {} as unknown as Env, "GET", "/sources/discover"));
  const nt = ((await (await noTok.stub.fetch(new Request("https://do/discovery-health"))).json()) as { health?: Record<string, unknown> }).health ?? {};
  ok("a discovery with NO TOKEN is recorded as such (not as an empty account)", nt.tokenPresent === false && nt.noTokenObservations === 1);
  ok("and it is NOT counted as a clean 'empty' observation: nothing was listed, so nothing may be claimed", nt.emptyObservations === 0);

  // The CHOKEPOINT under a drifted / hostile writer.
  const hostile = applyDiscoveryHealth(undefined, {
    products: { r2: "denied", "not-a-product": "denied", kv: SENTINEL_MESSAGE },
    tokenPresent: true,
    accountsScanned: 9_999_999,
    boundSources: -3,
    accountName: SENTINEL_ACCOUNT,
    rawError: SENTINEL_MESSAGE,
  }, 1_700_000_000_000);
  ok("HOSTILE: an out-of-vocabulary PRODUCT key is dropped whole", hostile.lastOutcome["not-a-product"] === undefined);
  ok("HOSTILE: a raw Cloudflare message smuggled in as an OUTCOME is dropped, the valid verdict beside it survives", hostile.lastOutcome.kv === undefined && hostile.lastOutcome.r2 === "denied");
  ok("HOSTILE: an absurd count is CLAMPED, a negative one floors at 0", hostile.accountsScanned === 1_000 && hostile.boundSources === 0);
  ok("HOSTILE: a field the applier never reads simply does not exist in the record", !("accountName" in hostile) && !("rawError" in hostile));
  ok("HOSTILE: no sentinel survives the chokepoint", scanForSentinels(hostile).length === 0);

  // The classifier's own contract: text SELECTS an enum member and only the member is returned.
  const cls = classifyDiscoveryError(`r2: HTTP 403 -- ${SENTINEL_MESSAGE} on ${SENTINEL_BUCKET}`);
  ok("the classifier reads the message ONLY to select the closed (product, outcome) pair", cls.product === "r2" && cls.outcome === "denied");
  ok("REDACTION: the classifier's RETURN carries none of the text it read", scanForSentinels(cls).length === 0);
  ok("a listing at the cap is TRUNCATED; one below it is not", classifyDiscoveryListing(500, 500) === "truncated" && classifyDiscoveryListing(499, 500) === "ok");
  ok("every recorded verdict is a member of the closed vocabulary", Object.values(last).every((v) => (DISCOVERY_OUTCOMES as readonly string[]).includes(v)) && Object.keys(last).every((k) => (DISCOVERY_PRODUCTS as readonly string[]).includes(k)));
}

// ---------------------------------------------------------------------------------------------------------
// an audit export that FAILS -- driven through the real console route against a DO that will not export.
// ---------------------------------------------------------------------------------------------------------
async function g022(): Promise<void> {
  console.log("\nthe failed audit-log EXPORT attempt reaches the bundle:");
  resetPendingDroppedWrites();
  const env = {} as unknown as Env;

  // The customer clicks Export and the DO cannot produce the log (the whole-log scan died).
  const sched = realScheduler({ path: "/audit/export", mode: "non-2xx" });
  const resp = await handleRbac(routerCtx(sched, env, "GET", "/audit/export", "?format=csv"));
  ok("the export FAILS for the customer, exactly as before (this records, it does not rescue)", resp?.status === 503);

  const stored = ((await (await sched.stub.fetch(new Request("https://do/export-attempts"))).json()) as { attempts?: Record<string, unknown> }).attempts ?? {};
  ok("the failed ATTEMPT is now RECORDED (no exportAttempts recorder existed anywhere before this)", stored.attempts === 1 && stored.failures === 1);
  ok("the closed outcome says the DO ANSWERED and refused, not that it was unreachable", (stored.byOutcome as Record<string, number>)?.["do-error"] === 1);
  ok("the CHANNEL says an operator is staring at a failed download", (stored.byChannel as Record<string, number>)?.["admin-download"] === 1);
  ok("the FORMAT says it was the CSV whole-log scan, which is a size fault rather than an outage", (stored.byFormat as Record<string, number>)?.csv === 1);
  ok("lastFailureAt rides, so 'is this happening NOW' is answerable", typeof stored.lastFailureAt === "number" && (stored.lastFailureAt as number) > 0);
  ok("REDACTION: the STORED record carries no filter, no cursor, no chain and no sentinel", scanForSentinels(stored).length === 0);

  const bundle = await buildSupportBundle(env, sched.stub);
  const ea = bundle.auditExportAttempts as Record<string, unknown> | undefined;
  ok("THE BUNDLE CARRIES auditExportAttempts", ea !== undefined && ea.failures === 1);
  ok("auditExportAttempts is on the closed roster", SUPPORT_SECTION_NAMES.includes("auditExportAttempts" as never));
  ok("the sections vector reports it gathered (ok), not error", (bundle.sections as Record<string, string>).auditExportAttempts === "ok");
  ok("REDACTION: the WHOLE BUNDLE carries no sentinel", scanForSentinels(bundle).length === 0);

  // A DO that cannot be reached at all: a different remedy, and it must be a different record.
  const gone = realScheduler({ path: "/audit/export", mode: "throw" });
  let threw = false;
  try {
    await handleRbac(routerCtx(gone, env, "GET", "/audit/export"));
  } catch {
    threw = true; // re-thrown deliberately, so the Worker's last-resort catch behaves exactly as before
  }
  ok("a transport fault still propagates to the Worker's last-resort catch (behaviour unchanged)", threw);
  const g = ((await (await gone.stub.fetch(new Request("https://do/export-attempts"))).json()) as { attempts?: Record<string, unknown> }).attempts ?? {};
  ok("...and is recorded as UNREACHABLE, distinct from the DO refusing", (g.byOutcome as Record<string, number>)?.["do-unavailable"] === 1);
  ok("REDACTION: the thrown error's text (which carried a token) reaches no byte of the record", scanForSentinels(g).length === 0);

  // A SUCCESSFUL export is the denominator that makes a failure legible, and a clean account carries nothing.
  const good = realScheduler();
  const okResp = await handleRbac(routerCtx(good, env, "GET", "/audit/export"));
  ok("a successful export is served AND counted, so failures have a denominator", okResp?.status === 200);
  const gj = await fetchAuditExportAttempts(good.stub);
  ok("the successful attempt records no failure", gj.attempts === 1 && gj.failures === 0);
  const virgin = realScheduler();
  const vb = await buildSupportBundle(env, virgin.stub);
  ok("an account that has never exported OMITS the section entirely (honest absence)", vb.auditExportAttempts === undefined);

  // The chokepoint.
  const hostileAtt = applyExportAttempt(undefined, { channel: "admin-download", format: "json", outcome: "ok", filtered: true, actor: SENTINEL_EMAIL, error: SENTINEL_MESSAGE }, 1_700_000_000_000);
  ok("HOSTILE: a field the applier never reads (an actor, an error) does not exist in the record", !("actor" in hostileAtt) && !("error" in hostileAtt) && scanForSentinels(hostileAtt).length === 0);
  const drifted = applyExportAttempt(undefined, { channel: "not-a-channel", format: "json", outcome: "ok", filtered: false }, 1_700_000_000_000);
  ok("HOSTILE: an out-of-vocabulary CHANNEL drops the attempt whole (a misattributed outage is worse than none)", drifted.attempts === 0);
  ok("every recorded outcome is a member of the closed vocabulary", Object.keys((stored.byOutcome ?? {}) as Record<string, number>).every((k) => (EXPORT_ATTEMPT_OUTCOMES as readonly string[]).includes(k)));
  resetPendingDroppedWrites();
}

// ---------------------------------------------------------------------------------------------------------
// the FORCED removal of the only proven copy, BURIED under churn -- and still in the excerpt.
// ---------------------------------------------------------------------------------------------------------
async function appendAudit(sched: Sched, draft: Record<string, unknown>): Promise<void> {
  const r = await sched.stub.fetch(new Request("https://do/audit", { method: "POST", body: JSON.stringify(draft), headers: { "content-type": "application/json" } }));
  if (!r.ok) throw new Error(`audit append failed: ${r.status}`);
}

async function g079(): Promise<void> {
  console.log("\nthe forced removal of the only proven copy survives the excerpt:");
  const sched = realScheduler();
  const env = {} as unknown as Env;

  // 1. THE DESTRUCTIVE ACT. The owner forced past the orphan guard: two downpipes lost their last proven copy
  //    of 47 backed-up runs. This is the event that must never be missing from a pack.
  await appendAudit(sched, {
    actorEmail: SENTINEL_EMAIL,
    actorMethod: "access",
    sourceIp: null,
    action: "dest-config-cleared",
    outcome: "success",
    target: { kind: "dest-change", op: "remove", id: "dest-old", force: true, uncoveredOriginRunCount: 47, affectedDownpipeNames: ["payroll-kv", "invoices-r2"] },
  });

  // 2. THE CHURN that buried it: 60 newer allowlisted governance events, well past the 40-event window.
  for (let i = 0; i < 60; i++) {
    await appendAudit(sched, { actorEmail: SENTINEL_EMAIL, actorMethod: "access", sourceIp: null, action: "role-change", outcome: "success", target: { kind: "role", email: SENTINEL_EMAIL, role: "viewer" } });
  }

  // 3. THE EVICTION that the action-name keystone could not survive: a LATER, entirely benign dest clear. The
  //    keystone rule retains the LATEST dest-config-cleared, and this is now it.
  await appendAudit(sched, {
    actorEmail: SENTINEL_EMAIL,
    actorMethod: "access",
    sourceIp: null,
    action: "dest-config-cleared",
    outcome: "success",
    target: { kind: "dest-change", op: "clear", id: "dest-stale", force: false, uncoveredOriginRunCount: 0 },
  });

  const bundle = await buildSupportBundle(env, sched.stub);
  const events = (bundle.configEvents ?? []) as Array<Record<string, unknown>>;
  const forced = events.find((e) => e.action === "dest-config-cleared" && e.force === true);
  ok("THE BUNDLE CARRIES the forced removal, though 61 newer events buried it and a benign clear displaced it", forced !== undefined);
  ok("...with the MAGNITUDE of what was destroyed (47 runs whose only proven copy was dropped)", forced?.uncoveredOriginRunCount === 47);
  ok("...and WHO lost it (the customer's own downpipe names, the class downpipes[] already carries)", JSON.stringify(forced?.affectedDownpipeNames ?? []) === JSON.stringify(["payroll-kv", "invoices-r2"]));
  ok("...and whether an attributable identity did it, or the shared break-glass token", forced?.attributed === true);
  ok("the benign clear that displaced it is ALSO present (the keystone rule is unchanged, this is additive)", events.some((e) => e.action === "dest-config-cleared" && e.force === false));
  ok("REDACTION: the operator's e-mail is NOT in the excerpt -- only the attributed boolean", scanForSentinels(bundle).length === 0);

  // The control: without the destructive predicate this event is exactly what rolls off. The recent window is
  // 40 events and 61 newer ones exist, so the forced removal is nowhere near it.
  const recentOnly = events.filter((e) => typeof e.seq === "number" && (e.seq as number) > (forced?.seq as number)).length;
  ok("the proof it was genuinely BURIED: dozens of newer events sit above it in the excerpt", recentOnly > 20);
}

// ---------------------------------------------------------------------------------------------------------
// a config version whose BODY is gone -- listed, hashed, chained, and impossible to roll back to.
// ---------------------------------------------------------------------------------------------------------
async function g098(): Promise<void> {
  console.log("\nconfig-version BODY retention gaps reach the bundle:");
  const sched = realScheduler();
  const env = {} as unknown as Env;

  // 1. THREE REAL CONFIG VERSIONS, written through the DO's own production snapshot path: real hash chain, real
  //    in-DO signing key, real `confighist:` storage keys. Each snapshot must DIFFER from the head or the DO
  //    de-dupes it away, so a downpipe with a customer name in it is added between captures. Those names are the
  //    reason the body scan may never project a single field of a snapshot.
  const seedDownpipe = async (i: number): Promise<void> => {
    const r = await sched.stub.fetch(new Request("https://do/downpipes", {
      method: "POST",
      body: JSON.stringify({ id: `dp-${i}`, name: `${SENTINEL_NAMESPACE}-${i}`, enabled: true, cadenceSeconds: 86_400, source: { type: "kv", binding: `KV_${i}`, include: [], exclude: [] } }),
      headers: { "content-type": "application/json" },
    }));
    if (!r.ok) throw new Error(`downpipe seed failed: ${r.status} ${await r.text()}`);
  };
  for (let i = 1; i <= 3; i++) {
    await seedDownpipe(i);
    await sched.dobj.snapshotConfigNow(SENTINEL_EMAIL);
  }
  const versionKeys = sched.storage.rawListKeys().filter((k) => k.startsWith("confighist:")).sort();
  ok("three real, chained, signed config versions exist", versionKeys.length === 3);

  // 2. THE FAULT. Version 2's BODY is gone -- the header (id, at, author, summary, both hashes, the signed
  //    digest) is intact and lists perfectly; the snapshot it promises is not there. This is a rollback point
  //    the console still offers and the engine can no longer produce, and it is what a truncated storage write,
  //    a half-applied migration or a partial restore of the DO leaves behind.
  const damaged = (await sched.storage.get<ConfigVersion>(configHistoryKey(2)))!;
  ok("the version to be damaged is a real one, with a real chain link and a real body", damaged.contentHash.startsWith("sha384:") && damaged.snapshot !== undefined);
  const { snapshot: _gone, ...headerOnly } = damaged as ConfigVersion & { snapshot?: unknown };
  void _gone;
  await sched.storage.put(configHistoryKey(2), headerOnly);

  // 3. THE READ. The DO's own health route, unchanged in every other respect.
  const health = (await (await sched.stub.fetch(new Request("https://do/config-history-health"))).json()) as { count?: number; bodies?: Record<string, unknown>; verify?: Record<string, unknown> };
  ok("the history still LISTS all three versions -- which is the whole false assurance", health.count === 3);
  ok("the BODY scan says only two of them can actually be rolled back to", health.bodies?.listed === 3 && health.bodies?.readable === 2);
  ok("...and names the version whose body is GONE (not merely 'the chain is broken somewhere')", health.bodies?.missing === 1 && health.bodies?.firstDefectiveId === 2);
  ok("the probe SURVIVES a body it cannot hash (before this, verifyConfigChain threw and took the whole probe with it)", health.verify?.verifyFaulted === true && health.verify?.intact === false);

  const bundle = await buildSupportBundle(env, sched.stub);
  const history = (bundle.configIntegrity as Record<string, unknown> | undefined)?.history as Record<string, unknown> | undefined;
  const bodies = history?.bodies as Record<string, unknown> | undefined;
  ok("THE BUNDLE CARRIES the body-retention scan", bodies !== undefined);
  ok("THE BUNDLE says how many rollback points are REAL (2) against how many are OFFERED (3)", bodies?.readable === 2 && bodies?.listed === 3);
  ok("THE BUNDLE names the oldest unrecoverable version", bodies?.missing === 1 && bodies?.firstDefectiveId === 2);
  ok("THE BUNDLE distinguishes 'could not check the chain' from 'the chain is broken at N'", history?.verifyFaulted === true);
  // The snapshot bodies scanned above hold the customer's downpipe labels. The pack carries those labels in
  // downpipes[] BY DESIGN (they are the customer's own, and the diagnosis is unusable without them), so the
  // claim here is the precise one: not one field of a config SNAPSHOT reaches the configIntegrity block. The
  // scan reads the bodies and returns counts and engine-minted version ids, and nothing else.
  ok("REDACTION: not one field of a config snapshot reaches the configIntegrity block", scanForSentinels(bundle.configIntegrity).length === 0);
  ok("the never-rolled chain carries NO rollover keys at all (they mean nothing here and must not appear)", history?.rolledOver === undefined && history?.earliestId === undefined && history?.rolledOverAtLeast === undefined);

  // 5. THE ROLLED-OVER ARM. The keys admitted to the closed set above are
  //    UNREACHABLE on the fixture that admitted them, because that chain begins at version 1, so widening the
  //    allowlist alone would have left them untested by the very check that let them in -- a gate whose
  //    allowlist grew and whose coverage did not. This drives the state they exist for.
  //
  //    THE PRUNE IS SIMULATED AT THE STORAGE LAYER RATHER THAN BY WRITING 2,000 VERSIONS, which is stated
  //    plainly: deleting version 1 leaves exactly what CONFIG_HISTORY_CAP's rollover leaves, a chain whose
  //    earliest surviving id is above 1, and that is the only property under test here. What is NOT claimed is
  //    that the cap fired; `support-pack-fault-oracle.ts` puts that question to a generated fault pack.
  await sched.storage.delete(configHistoryKey(1));
  const rolled = await buildSupportBundle(env, sched.stub);
  const rolledHistory = (rolled.configIntegrity as Record<string, unknown> | undefined)?.history as Record<string, unknown> | undefined;
  ok("A ROLLED-OVER CHAIN SAYS SO: the block appears and declares the rollover", rolledHistory?.rolledOver === true);
  ok("...and names the earliest version that SURVIVES, so a customer asking for a destroyed one can be told it existed", rolledHistory?.earliestId === 2);
  ok("...and says how many were destroyed, as a lower bound", rolledHistory?.rolledOverAtLeast === 1);
  ok("REDACTION: the ROLLED-OVER history block also holds ONLY the closed diagnostic keys", Object.keys(rolledHistory ?? {}).every((k) => ["intact", "versions", "brokenAt", "signingKeyRotated", "verifyFaulted", "bodies", "rolledOver", "rolledOverAtLeast", "earliestId"].includes(k)));
  ok("REDACTION: not one field of a config snapshot reaches the rolled-over block either", scanForSentinels(rolled.configIntegrity).length === 0);
  ok("REDACTION: the projected history block holds ONLY the closed diagnostic keys", Object.keys(history ?? {}).every((k) => ["intact", "versions", "brokenAt", "signingKeyRotated", "verifyFaulted", "bodies", "rolledOver", "rolledOverAtLeast", "earliestId"].includes(k)));
  // rolledOver / rolledOverAtLeast / earliestId are admitted to the closed set
  // and belong to it on the same footing as `brokenAt` and `versions`: an ENGINE-MINTED version id and two
  // numbers derived from it. No field of a config snapshot is involved, which the sentinel scan above already
  // proves independently. They are admitted here rather than left to fail the gate BECAUSE this assertion is
  // the thing standing between that block and a projection that spreads its input, and a gate whose allowlist
  // is stale is a gate that has to be argued past every time it fires.
  //
  // AND THE ASSERTION IS RE-ARMED RATHER THAN MERELY WIDENED: the fixture above has never rolled over, so
  // widening the list alone would leave the three new keys UNTESTED by the check that admitted them. The block
  // below builds a bundle over a chain that HAS rolled over and puts the same closed-set question to it.

  // A HEALTHY history stays silent: the block is surfaced only when there is something to diagnose.
  const clean = realScheduler();
  await clean.stub.fetch(new Request("https://do/upsert", { method: "POST", body: JSON.stringify({ id: "dp-1", name: "kv-nightly", enabled: true, schedule: "0 3 * * *", source: { type: "kv", binding: "KV_1" } }), headers: { "content-type": "application/json" } }));
  await clean.dobj.snapshotConfigNow(null);
  const cleanBundle = await buildSupportBundle(env, clean.stub);
  const cleanHistory = (cleanBundle.configIntegrity as Record<string, unknown> | undefined)?.history;
  ok("a history whose every body is READABLE surfaces nothing (a clean pack stays clean)", cleanHistory === undefined);

  // The pure scanner's own contract, over the shapes storage actually produces.
  const scan = scanConfigBodies([
    { id: 1, snapshot: { downpipes: [], roles: [], groupRoles: [], customRoles: [], notifyChannels: [], notifyRules: [], riskAccepts: [], expiryItems: [] } },
    { id: 2 }, // the body is gone
    { id: 3, snapshot: { downpipes: [] } }, // a HALF-WRITTEN body: it is an object, and it is not a snapshot
    { id: 4, snapshot: `restore of ${SENTINEL_BUCKET}` }, // a body that is not even an object
  ] as unknown as ConfigVersion[]);
  ok("SCAN: an absent body is MISSING; a half-written one is UNREADABLE; a non-object body is UNREADABLE", scan.missing === 1 && scan.unreadable === 2 && scan.readable === 1);
  ok("SCAN: the boundary ids bracket the damage (oldest 2, newest 4)", scan.firstDefectiveId === 2 && scan.newestDefectiveId === 4);
  ok("SCAN: it never throws on a body it cannot read, so it can run BEFORE the verify that would die on it", scan.listed === 4);
  ok("REDACTION: the scan returns counts and engine-minted ids only", scanForSentinels(scan).length === 0);
}

async function main(): Promise<void> {
  await g008();
  await g022();
  await g079();
  await g098();
  console.log(failures === 0 ? "\ndata-loss evidence: OK" : `\ndata-loss evidence: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
