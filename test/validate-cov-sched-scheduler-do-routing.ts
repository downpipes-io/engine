// validate-cov-sched-scheduler-do-routing: a focused branch-coverage validator for RoutingMixin
// (src/sched/scheduler-do-routing.ts), the route() RPC dispatch chain plus the CORE data-plane and the
// ingest-credential / runlog-lock / rate-check sub-dispatches it owns inline. It drives the REAL
// SchedulerDO over in-memory storage, router-bypassed via stub.fetch + an encoded x-downpipe-caller
// header (the documented "FROM THE ROUTER ONLY" trust these DO routes use), so every assertion checks a
// real outcome: an HTTP status, a returned body field, or a stored/audited effect.
//
// What it exercises in the target file:
//  - optionalLockKey: the keyed slot (string key), the empty/non-string fallbacks, and the no-body catch;
//  - routeCore: the cf-config discovery/mode arms (unknown-downpipe 404, bad-mode 400, the persist), the
//    discovery-due filter across each && short-circuit, the tick / tick-info absent-vs-present arm, and the
//    downpipe lifecycle / history / runs-at / rto / replication arms;
//  - routeIngestCredential: scope validation, the owner re-check (granted and refused), the grant-present /
//    null branches, the clientId / expiresAt conditional-spread arms, the ephemeral-vs-functional class, the
//    removed-vs-absent clear branch, and the record-pull grant-present / pulls-fallback / absent branches;
//  - routeRunlogRate / routeRbac / routeAudit / routeRestoreApproval: every case arm reached with a real
//    outcome (success or a clean refusal);
//  - route(): a routeCore hit covers the short-circuit side of every ?? node, and an unmatched route covers
//    the fall-through to notFoundResponse() (404) plus every switch default arm.
// No network is touched at all (these routes do only DO storage + audit appends).
//
// Run: node test/validate-cov-sched-scheduler-do-routing.ts

import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, stub };
}

const OWNER_EMAIL = "owner@routing.example";
const OWNER_SUBJECT = "sub-routing-owner";
const ownerCaller: Caller = { method: "access", email: OWNER_EMAIL, subject: OWNER_SUBJECT, role: "owner", groups: [] };
const viewerCaller: Caller = { method: "access", email: "viewer@routing.example", subject: "sub-routing-viewer", role: "viewer", groups: [] };

async function main(): Promise<void> {
  // The restore-approval gate is OWNER-OPT-IN and OFF by default; this file exercises it, so it arms it.
  const s = makeScheduler();
  await s.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });

  // call() drives a DO route bypassing the router, forwarding a Caller via the encoded header exactly as
  // the router does. A POST sends a JSON body only when one is supplied (so a no-body POST drives the
  // optionalLockKey catch); a GET never carries a body.
  async function call(path: string, caller: Caller | null, body?: unknown, method: "GET" | "POST" = "POST"): Promise<Response> {
    const headers: Record<string, string> = {};
    if (caller !== null) headers[CALLER_HEADER] = encodeCaller(caller);
    const init: RequestInit = { method, headers };
    if (method === "POST" && body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return s.stub.fetch(`https://scheduler.internal${path}`, init);
  }
  const jbody = async (r: Response): Promise<Record<string, unknown>> => (await r.json()) as Record<string, unknown>;

  // ===========================================================================================
  // SECTION 0: bootstrap the first caller as Owner (so the ingest-credential owner re-check passes).
  // ===========================================================================================
  {
    const who = await call(`/whoami?email=${encodeURIComponent(OWNER_EMAIL)}&subject=${OWNER_SUBJECT}&method=access`, null, undefined, "GET");
    ok("[whoami] GET /whoami bootstraps the first caller as Owner (routeRbac dispatch)", who.status === 200 && (await jbody(who)).role === "owner");
  }

  // ===========================================================================================
  // SECTION 1: routeRunlogRate + optionalLockKey (the keyed slot, the empty/non-string fallbacks, the
  //            no-body catch) and the rate-check arm.
  // ===========================================================================================
  {
    const a1 = await call("/runlog-lock/acquire", null, { key: "slotA" });
    const a1b = (await a1.json()) as { acquired: boolean; token?: string };
    ok("[runlog] acquire a keyed slot succeeds with a token (optionalLockKey string branch)", a1.status === 200 && a1b.acquired === true && typeof a1b.token === "string");
    const a2 = (await (await call("/runlog-lock/acquire", null, { key: "slotA" })).json()) as { acquired: boolean };
    ok("[runlog] a second acquire of the SAME keyed slot is refused (the string key really keyed the slot)", a2.acquired === false);

    const rel = await call("/runlog-lock/release", null, { token: a1b.token, key: "slotA" });
    ok("[runlog] release with the holder token frees the keyed slot (ok:true)", rel.status === 200 && (await jbody(rel)).ok === true);
    const a3 = (await (await call("/runlog-lock/acquire", null, { key: "slotA" })).json()) as { acquired: boolean; token?: string };
    ok("[runlog] re-acquire after release mints a fresh token (the slot was genuinely freed)", a3.acquired === true && a3.token !== a1b.token);

    // The DEFAULT slot: a no-body acquire reaches optionalLockKey's catch (req.json throws) -> undefined.
    const d1 = (await (await call("/runlog-lock/acquire", null, undefined)).json()) as { acquired: boolean };
    ok("[runlog] a no-body acquire takes the default slot (optionalLockKey catch -> undefined)", d1.acquired === true);
    // An empty-string key (length 0) and a non-string key both fall through to the DEFAULT slot, which the
    // no-body acquire above is holding, so both are refused (proving the ternary's false arms map to default).
    const d2 = (await (await call("/runlog-lock/acquire", null, { key: "" })).json()) as { acquired: boolean };
    ok("[runlog] an empty-string key maps to the default slot (length-0 ternary arm) and is refused", d2.acquired === false);
    const d3 = (await (await call("/runlog-lock/acquire", null, { key: 123 })).json()) as { acquired: boolean };
    ok("[runlog] a non-string key maps to the default slot (typeof ternary arm) and is refused", d3.acquired === false);

    // rate-check: a tight bucket admits up to max then refuses with a positive retryAfterMs.
    const rc1 = (await (await call("/rate-check", null, { key: "rk", max: 2 })).json()) as { allowed: boolean; retryAfterMs: number };
    const rc2 = (await (await call("/rate-check", null, { key: "rk", max: 2 })).json()) as { allowed: boolean };
    const rc3 = (await (await call("/rate-check", null, { key: "rk", max: 2 })).json()) as { allowed: boolean; retryAfterMs: number };
    ok("[rate] the first two requests in a window are admitted, the third is refused with a Retry-After", rc1.allowed === true && rc2.allowed === true && rc3.allowed === false && rc3.retryAfterMs > 0);
  }

  // ===========================================================================================
  // SECTION 2: routeCore downpipe lifecycle (upsert / list / trigger / heartbeat / complete / delete /
  //            due / history / runs-at / rto / replication) + the tick / tick-info arm.
  // ===========================================================================================
  {
    // tick-info BEFORE any tick: the ?? null fallback (no lastTickAt stored).
    const ti0 = (await (await call("/tick-info", null, undefined, "GET")).json()) as { lastTickAt: number | null };
    ok("[core] tick-info with no prior tick reads lastTickAt null (the ?? null fallback)", ti0.lastTickAt === null);

    const cfg = { id: "p1", name: "Pipe 1", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_p1", include: [], exclude: [] } };
    const up = await call("/downpipes", ownerCaller, cfg);
    ok("[core] POST /downpipes upserts a downpipe (gatedConfigMutation applied, 200)", up.status === 200 && ((await jbody(up)).config as { id: string }).id === "p1");
    const list = (await (await call("/downpipes", null, undefined, "GET")).json()) as Array<{ config: { id: string } }>;
    ok("[core] GET /downpipes lists the upserted downpipe", Array.isArray(list) && list.some((d) => d.config.id === "p1"));

    const due = (await (await call("/due", null, undefined, "GET")).json()) as { due: unknown[] };
    ok("[core] GET /due returns a due set", Array.isArray(due.due));

    const trg = await call("/trigger", null, { id: "p1" });
    const trgb = (await trg.json()) as { runId?: string; index?: number; skipped?: string };
    ok("[core] POST /trigger marks the downpipe in-flight and allocates a run", trg.status === 200 && typeof trgb.runId === "string" && typeof trgb.index === "number");

    const hb = await call("/heartbeat", null, { id: "p1", runId: trgb.runId, index: trgb.index });
    ok("[core] POST /heartbeat reports the run is owned", hb.status === 200 && (await jbody(hb)).owned === true);

    // The completion carries multipartAbortFailed:true (multipart-abort-stranded-parts) so completeRun stamps it
    // on the run row and the otherwise-swallowed stranded-part-storage fault becomes visible in the history ring.
    const comp = await call("/complete", null, { id: "p1", runId: trgb.runId, index: trgb.index, status: "ok", recordCount: 2, bytes: 64, multipartAbortFailed: true });
    ok("[core] POST /complete resolves the in-flight run (ok:true)", comp.status === 200 && (await jbody(comp)).ok === true);

    const hist = (await (await call("/history?id=p1", null, undefined, "GET")).json()) as { entries?: Array<{ multipartAbortFailed?: boolean }> };
    ok("[core] GET /history returns the per-downpipe run ring", Array.isArray(hist.entries) && hist.entries.length >= 1);
    ok("[core] completeRun stamps multipartAbortFailed on the run row (multipart-abort-stranded-parts)", (hist.entries ?? []).some((e) => e.multipartAbortFailed === true));

    // beacon-state: the opt-in vendor-beacon last-attempt outcome (recordBeaconAttempt / getBeaconState).
    // Before any attempt GET reads null (the beacon never emitted); a POST records ok + a clamped status,
    // read back by GET. status 1200 proves the 0..999 clamp.
    const bsNull = await (await call("/beacon-state", null, undefined, "GET")).json();
    ok("[core] GET /beacon-state before any attempt reads null (beacon never emitted)", bsNull === null);
    const bsRec = await call("/beacon-state", null, { ok: true, status: 1200 });
    ok("[core] POST /beacon-state records the attempt outcome (recordBeaconAttempt ok:true)", bsRec.status === 200 && (await jbody(bsRec)).ok === true);
    const bsGet = (await (await call("/beacon-state", null, undefined, "GET")).json()) as { ok?: boolean; status?: number; at?: number };
    ok("[core] GET /beacon-state reads back the outcome with the status clamped to <=999", bsGet.ok === true && bsGet.status === 999 && typeof bsGet.at === "number");

    // drive-budget-yield: the cron seal-loop budget-yield record (failover-probe-budget-exhaustion). Null before
    // any yield; a POST records + clamps the carried count; a GET reads the cumulative count + last carried.
    const dbyNull = await (await call("/drive-budget-yield", null, undefined, "GET")).json();
    ok("[core] GET /drive-budget-yield before any yield reads null", dbyNull === null);
    await call("/drive-budget-yield", null, { carried: 3 });
    const dbyRec = await call("/drive-budget-yield", null, { carried: 5_000_000 }); // over the 1e6 clamp
    ok("[core] POST /drive-budget-yield records a yield (ok:true)", dbyRec.status === 200 && (await jbody(dbyRec)).ok === true);
    const dbyGet = (await (await call("/drive-budget-yield", null, undefined, "GET")).json()) as { count?: number; lastCarried?: number; lastAt?: number };
    ok("[core] GET /drive-budget-yield reads the cumulative count + the clamped last carried-over", dbyGet.count === 2 && dbyGet.lastCarried === 1_000_000 && typeof dbyGet.lastAt === "number");

    // config-snapshot-health: the swallowed auto-snapshot failure tally (config-snapshot-best-effort-gap). With no
    // failures it reads the safe default (count 0, lastAt null), routed via route() -> routeConfigVersion.
    const csh = (await (await call("/config-snapshot-health", null, undefined, "GET")).json()) as { count?: number; lastAt?: string | null };
    ok("[cfg] GET /config-snapshot-health reads the default (0 failures) when none observed", csh.count === 0 && csh.lastAt === null);

    // config-history-health: the lightweight chain verdict + signingKeyRotated (config-history-session-key-regen).
    // First call establishes the key-fingerprint baseline (signingKeyRotated absent) over an empty chain (intact).
    const chh1 = (await (await call("/config-history-health", null, undefined, "GET")).json()) as { count?: number; verify?: { intact?: boolean; signingKeyRotated?: boolean } };
    ok("[cfg] GET /config-history-health reports an intact chain + establishes the key-fp baseline (no rotation yet)", chh1.verify?.intact === true && chh1.verify?.signingKeyRotated === undefined);
    // Overwrite the stored fingerprint so the live key's fingerprint DRIFTS -> a rotation is reported (recoverable
    // context, distinct from a genuine brokenAt content tamper).
    await s.storage.put("config-history-key-fp", "00000000000000000000000000000000");
    const chh2 = (await (await call("/config-history-health", null, undefined, "GET")).json()) as { verify?: { signingKeyRotated?: boolean } };
    ok("[cfg] GET /config-history-health reports signingKeyRotated after the key fingerprint drifts", chh2.verify?.signingKeyRotated === true);

    // change-control/refusals: the refused-change tally (change-number-required-refusal). Default 0 here (the bump
    // path is exercised by validate-change-management); reads WITHOUT touching the CR ledger.
    const ccr = (await (await call("/change-control/refusals", null, undefined, "GET")).json()) as { count?: number; lastAt?: string | null };
    ok("[cfg] GET /change-control/refusals reads the default (0 refusals) when none observed", ccr.count === 0 && ccr.lastAt === null);

    // licence-activation-refusal: the verify-before-store refusal tally (failed-activation-no-trace). Null before
    // any refusal; a POST with a CLOSED reason code records it; a POST with an out-of-vocab code is DROPPED (the
    // count still increments, but no reason code is stored); GET reads the cumulative count back.
    const larNull = await (await call("/licence-activation-refusal", null, undefined, "GET")).json();
    ok("[cfg] GET /licence-activation-refusal before any refusal reads null", larNull === null);
    await call("/licence-activation-refusal", null, { reasonCode: "expired" });
    const larGet1 = (await (await call("/licence-activation-refusal", null, undefined, "GET")).json()) as { count?: number; lastReasonCode?: string };
    ok("[cfg] POST /licence-activation-refusal records a CLOSED reason code (expired)", larGet1.count === 1 && larGet1.lastReasonCode === "expired");
    await call("/licence-activation-refusal", null, { reasonCode: "totally-bogus-value" });
    const larGet2 = (await (await call("/licence-activation-refusal", null, undefined, "GET")).json()) as { count?: number; lastReasonCode?: string };
    ok("[cfg] POST /licence-activation-refusal DROPS an out-of-vocab code (count increments, code absent)", larGet2.count === 2 && larGet2.lastReasonCode === undefined);

    const at = (await call(`/runs/at?downpipe=p1&at=${encodeURIComponent("2099-01-01T00:00:00.000Z")}`, null, undefined, "GET"));
    ok("[core] GET /runs/at resolves a point-in-time run query (200)", at.status === 200);

    const rto = (await (await call("/rto?id=p1", null, undefined, "GET")).json()) as { fleet?: unknown };
    ok("[core] GET /rto returns the fleet + per-downpipe estimate", rto.fleet !== undefined);

    const repRec = await call("/replication/record", null, { id: "p1", ok: true, destinationId: "d1", runId: trgb.runId, index: trgb.index });
    ok("[core] POST /replication/record records a per-destination replication state (ok:true)", repRec.status === 200 && (await jbody(repRec)).ok === true);
    const rep = (await (await call("/replication?id=p1", null, undefined, "GET")).json()) as { dests?: unknown };
    ok("[core] GET /replication returns the per-downpipe replication map", rep.dests !== undefined);

    // A separate downpipe to exercise the delete arm without losing p1.
    await call("/downpipes", ownerCaller, { id: "pdel", name: "Pipe del", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_pdel", include: [], exclude: [] } });
    const del = await call("/delete", ownerCaller, { id: "pdel" });
    ok("[core] POST /delete removes a downpipe (gatedConfigMutation applied, deleted:true)", del.status === 200 && (await jbody(del)).deleted === true);

    // POST /tick records the tick instant and runs the alarm; tick-info then reads the present value.
    const tick = await call("/tick", null, {});
    ok("[core] POST /tick records the tick and re-arms the alarm (ok:true)", tick.status === 200 && (await jbody(tick)).ok === true);
    const ti1 = (await (await call("/tick-info", null, undefined, "GET")).json()) as { lastTickAt: number | null };
    ok("[core] tick-info after a tick reads a numeric lastTickAt (the present arm)", typeof ti1.lastTickAt === "number");
  }

  // ===========================================================================================
  // SECTION 3: routeCore cf-config arms (discovery + mode), each over a known and an unknown downpipe,
  //            and the bad-mode validation throw.
  // ===========================================================================================
  {
    // Seed a cf-config downpipe directly so the handlers have a real dp:<id> to mutate + persist.
    await s.storage.put("dp:cfd", {
      config: { id: "cfd", name: "CF cfg", cadenceSeconds: 3600, enabled: true, source: { type: "cf-config", accountId: "acc-1", cfConfigMode: "auto", include: [], exclude: [] } },
      nextRunAt: Date.now() + 3600_000,
      lastRunId: null,
      inFlight: false,
    });

    const discBad = await call("/cf-config/discovery", null, { id: "no-such-dp", discovery: { at: Date.now(), present: [], empty: [], gated: [], unavailable: [] } });
    ok("[core] POST /cf-config/discovery for an unknown downpipe is a 404 (ok:false, unknown downpipe)", discBad.status === 404 && (await jbody(discBad)).error === "unknown downpipe");
    // The discovery write is gated by sanitiseCfConfigDiscovery, whose surface-id vocabulary is the
    // REGISTRY itself (a surface id can only ever be one of the ~214 known product tokens, so a bucket, an
    // object key, an account id or an error message structurally cannot ride into the pack on this field).
    // "dns" is a real registry surface; a fabricated id is DROPPED, which is the point of the gate.
    const disc = await call("/cf-config/discovery", null, { id: "cfd", discovery: { at: Date.now(), present: ["dns"], empty: [], gated: [], unavailable: [] } });
    ok("[core] POST /cf-config/discovery persists the discovery partition (ok:true)", disc.status === 200 && (await jbody(disc)).ok === true);
    const storedDisc = await s.storage.get<{ cfConfigDiscovery?: { present: string[] } }>("dp:cfd");
    ok("[core] the discovery partition was stored on the downpipe state", (storedDisc as { cfConfigDiscovery?: { present: string[] } }).cfConfigDiscovery?.present.includes("dns") === true);
    // The gate itself: a fabricated surface id never reaches the downpipe state.
    const discJunk = await call("/cf-config/discovery", null, { id: "cfd", discovery: { at: Date.now(), present: ["dns", "acme-prod-backups-bucket"], empty: [], gated: [], unavailable: [] } });
    ok("[core] POST /cf-config/discovery with a junk surface id still succeeds (ok:true)", discJunk.status === 200);
    const storedJunk = await s.storage.get<{ cfConfigDiscovery?: { present: string[] } }>("dp:cfd");
    ok("[core] a non-registry surface id is DROPPED at the DO chokepoint (no free-text seam into the pack)", (storedJunk as { cfConfigDiscovery?: { present: string[] } }).cfConfigDiscovery?.present.includes("acme-prod-backups-bucket") !== true);

    const modeBad = await call("/cf-config/mode", null, { id: "cfd", mode: "sideways" });
    ok("[core] POST /cf-config/mode with an invalid mode is a 400 (mode must be auto or manual)", modeBad.status === 400 && /auto or manual/.test(((await jbody(modeBad)).error as string) ?? ""));
    const modeUnknown = await call("/cf-config/mode", null, { id: "no-such-dp", mode: "manual" });
    // cf-config/mode is now a first-class config mutation (cf-config-mode-set) routed through gatedConfigMutation,
    // so an unknown downpipe throws and surfaces as a 400 like every other config mutation, not the prior special 404.
    ok("[core] POST /cf-config/mode for an unknown downpipe is a 400 (config-mutation throw)", modeUnknown.status === 400 && (await jbody(modeUnknown)).error === "unknown downpipe");
    const mode = await call("/cf-config/mode", null, { id: "cfd", mode: "manual" });
    ok("[core] POST /cf-config/mode sets the capture mode (ok:true)", mode.status === 200 && (await jbody(mode)).ok === true);
    const storedMode = await s.storage.get<{ config: { source: { cfConfigMode: string } } }>("dp:cfd");
    ok("[core] the capture mode was stored on the source", (storedMode as { config: { source: { cfConfigMode: string } } }).config.source.cfConfigMode === "manual");
  }

  // ===========================================================================================
  // SECTION 4: routeCore GET /cf-config/discovery-due over a FRESH DO seeded to isolate each && arm of
  //            the filter, so the result is exactly the one downpipe that passes every condition.
  // ===========================================================================================
  {
    // The restore-approval gate is OWNER-OPT-IN and OFF by default; this file exercises it, so it arms it.
    const s2 = makeScheduler();
    await s2.storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireRestoreApproval: true });
    const cfSource = (over: Record<string, unknown>): Record<string, unknown> => ({ type: "cf-config", accountId: "acc", include: [], exclude: [], ...over });
    const seed = async (id: string, enabled: boolean, source: Record<string, unknown>, discovery?: unknown): Promise<void> => {
      await s2.storage.put(`dp:${id}`, { config: { id, name: id, cadenceSeconds: 3600, enabled, source }, nextRunAt: Date.now() + 3600_000, lastRunId: null, inFlight: false, ...(discovery !== undefined ? { cfConfigDiscovery: discovery } : {}) });
    };
    await seed("dd-disabled", false, cfSource({ cfConfigMode: "auto" })); // fails: enabled
    await seed("dd-notcf", true, { type: "kv", binding: "KV_x", include: [], exclude: [] }); // fails: source type
    await seed("dd-manual", true, cfSource({ cfConfigMode: "manual" })); // fails: mode === auto
    await seed("dd-fresh", true, cfSource({ cfConfigMode: "auto" }), { at: Date.now(), present: [], empty: [], gated: [], unavailable: [] }); // fails: stale
    await seed("dd-due", true, cfSource({ cfConfigMode: "auto" })); // passes all: enabled + cf-config + auto + stale (no discovery)

    const due = (await (await s2.stub.fetch("https://scheduler.internal/cf-config/discovery-due", { method: "GET" })).json()) as { due: Array<{ config: { id: string } }> };
    const ids = due.due.map((d) => d.config.id);
    ok("[core] discovery-due includes the enabled auto-mode cf-config downpipe with a stale cache", ids.includes("dd-due"));
    ok("[core] discovery-due excludes disabled / non-cf-config / manual / fresh downpipes (every && arm)", !ids.includes("dd-disabled") && !ids.includes("dd-notcf") && !ids.includes("dd-manual") && !ids.includes("dd-fresh"));
  }

  // ===========================================================================================
  // SECTION 5: routeIngestCredential — scope validation, the owner re-check, the grant-present/null and
  //            clientId/expiresAt conditional-spread branches, the ephemeral-vs-functional class, the
  //            clear removed/absent branches, and the record-pull grant/pulls/absent branches.
  // ===========================================================================================
  {
    // GET on a fresh scope yields a null grant (the ?? null fallback).
    const g0 = (await (await call("/ingest-credential?scope=audit-feed", null, undefined, "GET")).json()) as { grant: unknown };
    ok("[ingest] GET an unset credential scope yields a null grant (the ?? null fallback)", g0.grant === null);
    // No scope query: the ?? "" fallback then fails the scope allow-list (400).
    const gNoScope = await call("/ingest-credential", null, undefined, "GET");
    ok("[ingest] GET with no scope is a 400 (the ?? '' fallback then the unknown-scope guard)", gNoScope.status === 400);

    // set: scope + owner guards.
    const setBadScope = await call("/ingest-credential/set", ownerCaller, { scope: "nope", grant: {} });
    ok("[ingest] set with an unknown scope is a 400 (unknown credential scope)", setBadScope.status === 400 && /unknown credential scope/.test(((await jbody(setBadScope)).error as string) ?? ""));
    const setViewer = await call("/ingest-credential/set", viewerCaller, { scope: "diagnostics", grant: {} });
    ok("[ingest] a non-owner is refused at the DO owner re-check (403, defence in depth)", setViewer.status === 403);

    // set diagnostics with a full grant (clientId + expiresAt strings): the present-spread arms, the
    // ephemeral lifecycle class, and the auto-observe of the bearer expiry.
    const setDiag = await call("/ingest-credential/set", ownerCaller, { scope: "diagnostics", grant: { clientId: "dpc_diag", expiresAt: "2099-01-01T00:00:00.000Z", secret: "ignored" } });
    ok("[ingest] owner sets the diagnostics credential (200)", setDiag.status === 200 && (await jbody(setDiag)).ok === true);
    const obs = await s.storage.get<{ lifecycleClass?: string }>("expiry:ingest-diagnostics");
    ok("[ingest] the diagnostics bearer expiry is auto-observed as an ephemeral lifecycle item", (obs as { lifecycleClass?: string } | undefined)?.lifecycleClass === "ephemeral");

    // set audit-feed with an expiresAt but NO clientId: the clientId-absent spread arm + the functional class.
    const setFeed = await call("/ingest-credential/set", ownerCaller, { scope: "audit-feed", grant: { expiresAt: "2099-01-01T00:00:00.000Z" } });
    ok("[ingest] owner sets the audit-feed credential without a clientId (200)", setFeed.status === 200);
    const obsFeed = await s.storage.get<{ lifecycleClass?: string }>("expiry:ingest-audit-feed");
    ok("[ingest] the audit-feed bearer expiry is auto-observed as a functional lifecycle item", (obsFeed as { lifecycleClass?: string } | undefined)?.lifecycleClass === "functional");

    // GET the present diagnostics grant.
    const gDiag = (await (await call("/ingest-credential?scope=diagnostics", null, undefined, "GET")).json()) as { grant: { clientId?: string } | null };
    ok("[ingest] GET returns the stored diagnostics grant", gDiag.grant?.clientId === "dpc_diag");

    // set with a grant of {} (present object, no clientId, no expiresAt): grantMeta present but neither
    // spread fires and no expiry is observed. Use audit-feed so a later clear sees a clientId-less prior.
    const setEmpty = await call("/ingest-credential/set", ownerCaller, { scope: "audit-feed", grant: {} });
    ok("[ingest] owner sets an audit-feed grant with no metadata (200, no observe)", setEmpty.status === 200);

    // set with a null grant: the `body.grant ?? null` -> null branch (no spreads, no observe).
    const setNull = await call("/ingest-credential/set", ownerCaller, { scope: "diagnostics", grant: null });
    ok("[ingest] owner sets a null diagnostics grant (the grant ?? null branch, 200)", setNull.status === 200);
    const gNull = (await (await call("/ingest-credential?scope=diagnostics", null, undefined, "GET")).json()) as { grant: unknown };
    ok("[ingest] the null grant is stored and read back as null", gNull.grant === null);

    // clear: scope + owner guards, then the removed-vs-absent branch + the prior.clientId spread arms.
    const clrBadScope = await call("/ingest-credential/clear", ownerCaller, { scope: "nope" });
    ok("[ingest] clear with an unknown scope is a 400", clrBadScope.status === 400);
    const clrViewer = await call("/ingest-credential/clear", viewerCaller, { scope: "audit-feed" });
    ok("[ingest] a non-owner clear is refused (403)", clrViewer.status === 403);
    // Re-set diagnostics with a clientId so clear records the clientId in its audit target.
    await call("/ingest-credential/set", ownerCaller, { scope: "diagnostics", grant: { clientId: "dpc_diag2", expiresAt: "2099-01-01T00:00:00.000Z" } });
    const clrDiag = await call("/ingest-credential/clear", ownerCaller, { scope: "diagnostics" });
    ok("[ingest] owner clears a present diagnostics grant (removed true, 200)", clrDiag.status === 200 && (await jbody(clrDiag)).ok === true);
    ok("[ingest] the diagnostics grant is gone after clear", (await s.storage.get("ingestcred:diagnostics")) === undefined);
    const clrAgain = await call("/ingest-credential/clear", ownerCaller, { scope: "diagnostics" });
    ok("[ingest] clearing an already-absent grant is a no-op (removed false, still 200)", clrAgain.status === 200 && (await jbody(clrAgain)).ok === true);
    // Clear the audit-feed grant that has NO clientId (the prior.clientId-absent spread arm).
    const clrFeed = await call("/ingest-credential/clear", ownerCaller, { scope: "audit-feed" });
    ok("[ingest] owner clears a clientId-less audit-feed grant (removed true, 200)", clrFeed.status === 200);

    // record-pull: scope guard, then the grant-present / pulls-fallback / pulls-present / absent branches.
    const rpBadScope = await call("/ingest-credential/record-pull", null, { scope: "nope", at: "2026-01-01T00:00:00.000Z" });
    ok("[ingest] record-pull with an unknown scope is a 400", rpBadScope.status === 400);
    await call("/ingest-credential/set", ownerCaller, { scope: "diagnostics", grant: { clientId: "dpc_pull", expiresAt: "2099-01-01T00:00:00.000Z" } });
    const rp1 = await call("/ingest-credential/record-pull", null, { scope: "diagnostics", at: "2026-01-01T00:00:00.000Z" });
    ok("[ingest] record-pull on a present grant records the first pull (200)", rp1.status === 200 && (await jbody(rp1)).ok === true);
    const pulled1 = await s.storage.get<{ pulls?: unknown[] }>("ingestcred:diagnostics");
    ok("[ingest] the first pull was appended (pulls ?? [] from an absent list)", (pulled1 as { pulls?: unknown[] } | undefined)?.pulls?.length === 1);
    await call("/ingest-credential/record-pull", null, { scope: "diagnostics", at: "2026-01-02T00:00:00.000Z" });
    const pulled2 = await s.storage.get<{ pulls?: unknown[] }>("ingestcred:diagnostics");
    ok("[ingest] a second pull appends to the existing list (the pulls-present arm)", (pulled2 as { pulls?: unknown[] } | undefined)?.pulls?.length === 2);
    const rpAbsent = await call("/ingest-credential/record-pull", null, { scope: "audit-feed", at: "2026-01-03T00:00:00.000Z" });
    ok("[ingest] record-pull on an absent grant is a harmless no-op (200, the if(grant) false arm)", rpAbsent.status === 200 && (await jbody(rpAbsent)).ok === true);

    // An owner caller with a null email + a source IP exercises the audit-draft actorEmail-null arm and the
    // sourceIp-present arm on BOTH the set and the clear commit (the owner re-check resolves on the SUBJECT,
    // so a null email still passes the gate; the bootstrapped owner is keyed by OWNER_SUBJECT).
    const ownerIpNoEmail: Caller = { method: "access", email: null, subject: OWNER_SUBJECT, sourceIp: "203.0.113.5", role: "owner", groups: [] };
    const setIp = await call("/ingest-credential/set", ownerIpNoEmail, { scope: "diagnostics", grant: { clientId: "dpc_ip", expiresAt: "2099-01-01T00:00:00.000Z" } });
    ok("[ingest] an owner with a null email + source IP can set (the actorEmail-null / sourceIp-present audit arms)", setIp.status === 200 && (await jbody(setIp)).ok === true);
    const clrIp = await call("/ingest-credential/clear", ownerIpNoEmail, { scope: "diagnostics" });
    ok("[ingest] the same owner clears it (the clear actorEmail-null / sourceIp-present audit arms, removed true)", clrIp.status === 200 && (await jbody(clrIp)).ok === true);
  }

  // ===========================================================================================
  // SECTION 6: routeRbac — every case arm reached with a real outcome (the GET reads, the owner-applied
  //            writes, and the role/group/custom-role deletes).
  // ===========================================================================================
  {
    const roles = await call("/roles", null, undefined, "GET");
    ok("[rbac] GET /roles lists the role table (the bootstrapped owner is present)", roles.status === 200 && (await roles.json() as Array<{ role: string }>).some((e) => e.role === "owner"));

    const setRole = await call("/roles", ownerCaller, { email: "member@routing.example", role: "viewer" });
    ok("[rbac] owner POST /roles grants a member a role (applied, 200)", setRole.status === 200);
    const delRole = await call("/roles/delete", ownerCaller, { email: "member@routing.example" });
    ok("[rbac] owner POST /roles/delete removes the member (deleted true, 200)", delRole.status === 200 && (await jbody(delRole)).deleted === true);

    const gr = await call("/group-roles", null, undefined, "GET");
    ok("[rbac] GET /group-roles reads the group mapping (200)", gr.status === 200 && Array.isArray(await gr.json()));
    const setGr = await call("/group-roles", ownerCaller, { group: "eng", role: "operator" });
    ok("[rbac] owner POST /group-roles maps a group to a role (200)", setGr.status === 200);
    const delGr = await call("/group-roles/delete", ownerCaller, { group: "eng" });
    ok("[rbac] owner POST /group-roles/delete removes the mapping (deleted true, 200)", delGr.status === 200 && (await jbody(delGr)).deleted === true);

    const cr = await call("/custom-roles", null, undefined, "GET");
    ok("[rbac] GET /custom-roles reads the custom-role catalogue (200)", cr.status === 200 && Array.isArray(await cr.json()));
    const setCr = await call("/custom-roles", ownerCaller, { name: "covrole", label: "Cov Role", capabilities: ["downpipe.read"], landing: "downpipes", presentation: "shiny", surface: { downpipes: "read" } });
    ok("[rbac] owner POST /custom-roles composes a custom role within authority (200)", setCr.status === 200);
    const delCr = await call("/custom-roles/delete", ownerCaller, { name: "covrole" });
    ok("[rbac] owner POST /custom-roles/delete removes the custom role (deleted true, 200)", delCr.status === 200 && (await jbody(delCr)).deleted === true);
  }

  // ===========================================================================================
  // SECTION 7: routeAudit — the append, the read, the verify, the export, and the status-diff hook.
  // ===========================================================================================
  {
    const draft = { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-secret-present", outcome: "success", target: { kind: "engine-state", field: "secret-present", detail: "signerConfigured" } };
    const ap = await call("/audit", null, draft);
    ok("[audit] POST /audit appends a forwarded draft to the chain (returns a sequenced event)", ap.status === 200 && typeof (await jbody(ap)).seq === "number");
    const rd = (await (await call("/audit?limit=100", null, undefined, "GET")).json()) as { events: unknown[]; headSeq: number };
    ok("[audit] GET /audit reads the ordered chain", Array.isArray(rd.events) && rd.events.length >= 1 && typeof rd.headSeq === "number");
    const vf = (await (await call("/audit/verify", null, undefined, "GET")).json()) as { intact: boolean };
    ok("[audit] GET /audit/verify reports the chain intact", vf.intact === true);
    const ex = await call("/audit/export", null, undefined, "GET");
    ok("[audit] GET /audit/export returns a downloadable export (200)", ex.status === 200);
    // status-baseline (engine-version-change-baseline-suppressed / same-version-redeploy): before any observation
    // the deploy-identity marker is null; the FIRST observation establishes the baseline and stamps it (still
    // appending NO audit "change" burst, so the CR-length contract holds). The obs carries cfVersionId so the
    // present-branch of the baseline write is exercised.
    const sbNull = await (await call("/status-baseline", null, undefined, "GET")).json();
    ok("[audit] GET /status-baseline before any observation reads null", sbNull === null);
    const st = await call("/audit-status", null, { signerConfigured: true, breakGlassConfigured: false, destConfigured: true, engineVersion: "test-1", cfVersionId: "cfv-1" });
    ok("[audit] POST /audit-status establishes the baseline snapshot (first observation appends nothing)", st.status === 200 && (await jbody(st)).appended === 0);
    const sbGet = (await (await call("/status-baseline", null, undefined, "GET")).json()) as { version?: string; cfVersionId?: string; at?: number } | null;
    ok("[audit] GET /status-baseline returns the deploy-identity marker written at the first observation", sbGet !== null && sbGet.version === "test-1" && sbGet.cfVersionId === "cfv-1" && typeof sbGet.at === "number");
  }

  // ===========================================================================================
  // SECTION 8: routeRestoreApproval — every case arm reached with a real outcome (capability refusals,
  //            the read inbox, the read-only gate, the consume no-op, and the drill-evidence read).
  // ===========================================================================================
  {
    const req403 = await call("/restore/request", null, { planHash: "sha384:x", runId: "r", reason: "x" });
    ok("[restore] POST /restore/request with no caller is refused at the DO capability re-check (403)", req403.status === 403);
    const apr403 = await call("/restore/approve", null, { planHash: "sha384:x" });
    ok("[restore] POST /restore/approve with no caller is refused (403)", apr403.status === 403);
    const rej403 = await call("/restore/reject", null, { planHash: "sha384:x" });
    ok("[restore] POST /restore/reject with no caller is refused (403)", rej403.status === 403);
    const inbox = await call("/restore/approvals", null, undefined, "GET");
    ok("[restore] GET /restore/approvals returns the inbox (empty for a caller-less, non-approver read)", inbox.status === 200 && Array.isArray(await inbox.json()));
    const gate = (await (await call("/restore/gate", null, {})).json()) as { usable: boolean; approval: unknown };
    ok("[restore] POST /restore/gate with no planHash gates closed", gate.usable === false && gate.approval === null);
    const consume = (await (await call("/restore/consume", null, {})).json()) as { consumed: boolean };
    ok("[restore] POST /restore/consume with no planHash consumes nothing", consume.consumed === false);
    const drill403 = await call("/drill-evidence", viewerCaller, { runId: "d1", kind: "in-account" });
    ok("[restore] POST /drill-evidence as a viewer (no drill.run) is refused (403)", drill403.status === 403);
    const drillList = await call("/drill-evidence", null, undefined, "GET");
    ok("[restore] GET /drill-evidence returns the evidence log (200)", drillList.status === 200 && Array.isArray(await drillList.json()));

    // The SUCCESS-return arms (this.json(...) after the handler resolves): a second owner gives a distinct
    // checker so maker != checker holds on approve. The owner role holds restore.request/approve + drill.run,
    // so the bootstrapped owner (and a second granted owner) drive each handler to a stored record.
    await call("/roles", ownerCaller, { email: "owner2@routing.example", role: "owner" });
    const owner2: Caller = { method: "access", email: "owner2@routing.example", subject: "sub-routing-owner2", role: "owner", groups: [] };
    // The dry run each request is raised against. requestRestore refuses a plan hash with no recorded
    // preview (it will not mint an approval against a plan it cannot date), so the plan-seen route is part
    // of the sequence, not a convenience.
    await call("/restore/plan-seen", null, { planHash: "sha384:cov-a", plannedAt: Date.now() });
    await call("/restore/plan-seen", null, { planHash: "sha384:cov-b", plannedAt: Date.now() });
    const reqOk = await call("/restore/request", ownerCaller, { planHash: "sha384:cov-a", runId: "run-a", reason: "coverage request" });
    ok("[restore] an owner raises a restore request (200, status requested) -> the request success arm", reqOk.status === 200 && (await jbody(reqOk)).status === "requested");
    const aprOk = await call("/restore/approve", owner2, { planHash: "sha384:cov-a" });
    ok("[restore] a distinct second owner approves it (maker != checker, 200, approved) -> the approve success arm", aprOk.status === 200 && (await jbody(aprOk)).status === "approved");
    await call("/restore/request", owner2, { planHash: "sha384:cov-b", runId: "run-b", reason: "to be rejected" });
    const rejOk = await call("/restore/reject", ownerCaller, { planHash: "sha384:cov-b" });
    ok("[restore] the first owner rejects a separate open request (200, rejected) -> the reject success arm", rejOk.status === 200 && (await jbody(rejOk)).status === "rejected");
    const drillOk = await call("/drill-evidence", ownerCaller, { runId: "run-d", kind: "in-account" });
    ok("[restore] an owner records drill evidence (200) -> the drill-evidence success arm", drillOk.status === 200 && (await jbody(drillOk)).runId === "run-d");
  }

  // ===========================================================================================
  // SECTION 9: route() fall-through — an unmatched key reaches notFoundResponse() (404), which also
  //            covers every switch default arm and the final ?? notFoundResponse() node.
  // ===========================================================================================
  {
    const nf = await call("/no-such-route", null, undefined, "GET");
    ok("[route] an unmatched route falls through every sub-dispatch to a 404 not found", nf.status === 404 && (await nf.text()) === "not found");
  }

  console.log(failures === 0 ? "\nVALIDATE-COV-SCHED-SCHEDULER-DO-ROUTING VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
