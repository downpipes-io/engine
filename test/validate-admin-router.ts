// Prove the ADMIN ROUTER (handleAdmin, src/admin/router.ts) end to end for the report / posture /
// coverage / notify / expiry / drill-evidence routes, which the dedicated validators
// exercise at the DO level but NOT through the router. We drive the REAL handleAdmin against a REAL
// SchedulerDO over in-memory storage, authenticating with the ADMIN_TOKEN break-glass (the token caller
// resolves to owner, so every capability gate passes and we exercise the route bodies, not the gates).
// This covers: the :kind reports dispatch for all four kinds + JSON/PDF + the signed and unsigned (fail-
// open) signing arms + the 404 for an unknown kind; the posture and coverage reads; the notify channel/
// rule/history/test CRUD; the expiry tracker CRUD; and the drill-evidence
// log. No network, no deploy, no cost: the DO answers from in-memory storage and no notification leaves.
// Run:
//   node test/validate-admin-router.ts

import { handleAdmin, resolveRollbackTarget } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { Report } from "../src/admin/reports.ts";
// The in-memory DO storage double is the shared helper (test/mock-storage.ts), so its get/put/delete/
// list/setAlarm semantics live in one place rather than a per-validator copy (finding test-001-03).
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const TOKEN = "router-test-admin-token";

function makeEnv(extra?: Partial<Env>): Env {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN, ...extra } as unknown as Env;
}

// Like makeEnv, but the scheduler stub THROWS on the side-channel POST /audit-status (a DO hiccup) while
// delegating every other request to the real DO. GET /status fires that POST best-effort after the report
// body is already computed, so this isolates the unwrapped fetch: with a try/catch the status read still
// returns its 200 and degrades the observed-event side-channel; without one the throw crashes the response.
function makeEnvWithFailingAuditStatus(extra?: Partial<Env>): Env {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      if ((init?.method ?? "GET") === "POST" && new URL(url).pathname === "/audit-status") {
        throw new Error("simulated DO hiccup on /audit-status");
      }
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  return { SCHEDULER: namespace, ADMIN_TOKEN: TOKEN, ...extra } as unknown as Env;
}

// call drives the FULL router with the ADMIN_TOKEN bearer (the owner break-glass). A body, when present,
// is JSON-encoded; the bearer authenticates every request as the token-fallback owner.
async function call(env: Env, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return handleAdmin(new Request(`https://engine.example${path}`, init), env);
}

// Each numbered section is its own async function so a failure's section is obvious from the call site
// and no single function breaches the length limit (finding test-001-04). main() calls them in order.

// 1. token auth sanity: the bearer resolves to owner.
async function testTokenAuth(): Promise<void> {
  {
    const who = await call(makeEnv(), "GET", "/admin/whoami");
    ok("token bearer authenticates as owner", who.status === 200 && (await who.json() as { role: string }).role === "owner");
    const noAuth = await handleAdmin(new Request("https://engine.example/admin/whoami"), makeEnv());
    ok("no credential is 401", noAuth.status === 401);
  }
}

// 2. reports: all four kinds, JSON, signed + unsigned, PDF, and the 404.
async function testReports(SIGNER: string): Promise<void> {
  {
    const signedEnv = makeEnv({ SIGNER_PRIVATE: SIGNER });
    const unsignedEnv = makeEnv(); // no SIGNER_PRIVATE -> signReportFailOpen returns the report unsigned

    for (const kind of ["restore-tests", "sla-compliance", "posture", "immutability"] as const) {
      const r = await call(signedEnv, "GET", `/admin/reports/${kind}`);
      ok(`report ${kind} is 200 JSON`, r.status === 200);
      const rep = (await r.json()) as Report;
      ok(`report ${kind} body carries the kind`, rep.kind === kind);
      // With a signer configured the report is signed (the signing arm ran).
      ok(`report ${kind} is signed when a signer is configured`, (rep as unknown as { signature?: unknown }).signature !== undefined);
    }

    // The unsigned (fail-open) arm: no signer -> the report still returns 200, just without a signature.
    const unsigned = await call(unsignedEnv, "GET", "/admin/reports/posture");
    ok("report is 200 even with NO signer (fail-open unsigned)", unsigned.status === 200);
    const unsignedRep = (await unsigned.json()) as Report;
    ok("the unsigned report carries no signature", (unsignedRep as unknown as { signature?: unknown }).signature === undefined);

    // A bad signer value exercises signReportFailOpen's catch arm (loadSigner throws -> unsigned returned).
    const badSignerEnv = makeEnv({ SIGNER_PRIVATE: "not-a-valid-64-byte-seed" });
    const badSigned = await call(badSignerEnv, "GET", "/admin/reports/sla-compliance");
    ok("a bad signer degrades to an unsigned 200 (signReportFailOpen catch)", badSigned.status === 200 && (await badSigned.json() as { signature?: unknown }).signature === undefined);

    // PDF rendering for a time-bounded kind (the ?format=pdf branch + renderReportPDF + ab()).
    const pdf = await call(signedEnv, "GET", "/admin/reports/restore-tests?format=pdf&from=0&to=99999999999");
    ok("report ?format=pdf returns a PDF content-type", pdf.status === 200 && (pdf.headers.get("content-type") ?? "").includes("application/pdf"));
    const pdfBytes = new Uint8Array(await pdf.arrayBuffer());
    ok("the rendered PDF starts with the %PDF- magic", pdfBytes.length > 4 && pdfBytes[0] === 0x25 && pdfBytes[1] === 0x50 && pdfBytes[2] === 0x44 && pdfBytes[3] === 0x46);

    // An unknown :kind is a 404 (isReportKind rejects it).
    const bogus = await call(signedEnv, "GET", "/admin/reports/totally-made-up");
    ok("an unknown report kind is 404", bogus.status === 404);

    // The period clamp: a from > to is normalised (fromSeconds <= toSeconds), so a reversed range still 200s.
    const reversed = await call(signedEnv, "GET", "/admin/reports/sla-compliance?from=99999999999&to=0");
    ok("a reversed from/to range is normalised and still 200", reversed.status === 200);
  }
}

// 3. posture + coverage reads.
async function testPostureCoverage(): Promise<void> {
  {
    const env = makeEnv();
    const posture = await call(env, "GET", "/admin/posture");
    ok("GET /posture is 200", posture.status === 200);
    // No inventory stored yet: the coverage read returns the honest unknown shape (never "fully covered").
    const cov0 = await call(env, "GET", "/admin/coverage");
    ok("GET /coverage is 200 before any inventory", cov0.status === 200);
    // Store a small inventory (access.policy-gated; the token owner holds it), then read it back.
    const store = await call(env, "POST", "/admin/coverage/inventory", { kv: [{ id: "ns-1", name: "uploads" }] });
    ok("POST /coverage/inventory stores the inventory (200)", store.status === 200);
    const cov1 = await call(env, "GET", "/admin/coverage");
    ok("GET /coverage is 200 after the inventory is stored", cov1.status === 200);
    // A malformed inventory is rejected 400 by the DO (re-validation), forwarded through the router.
    const badInv = await call(env, "POST", "/admin/coverage/inventory", { kv: [{ name: "no-id" }] });
    ok("a malformed inventory is rejected (400)", badInv.status === 400);

    // Posture risk-accept / unaccept (the owner holds posture.riskaccept). A known checkId is accepted,
    // then unaccepted; an unknown checkId is rejected 400 by the DO re-validation.
    const accept = await call(env, "POST", "/admin/posture/accept", { checkId: "restore-test-recency", reason: "rehearsed offline this quarter" });
    ok("POST /posture/accept accepts a known check (200)", accept.status === 200);
    const unaccept = await call(env, "POST", "/admin/posture/unaccept", { checkId: "restore-test-recency" });
    ok("POST /posture/unaccept clears it (200)", unaccept.status === 200);
    const badAccept = await call(env, "POST", "/admin/posture/accept", { checkId: "not-a-real-check", reason: "x" });
    ok("POST /posture/accept rejects an unknown checkId (400)", badAccept.status === 400);
  }
}

// 3b. restorability assurance routes: the runId-required guard.
// The BLIND restore test and the KEYLESS attestation are gated on restore.verify (the owner holds it).
// We exercise the router's runId-required guard (a 400 before any archive read), which proves the route
// body + gate run without needing a real sealed archive (the heavy decrypt/attest paths are covered in
// validate-restorability at the engine level).
async function testRestorabilityGuards(): Promise<void> {
  {
    const env = makeEnv();
    const verifyNoRun = await call(env, "POST", "/admin/restore/verify", {});
    ok("POST /restore/verify without a runId is 400", verifyNoRun.status === 400);
    const attestNoRun = await call(env, "POST", "/admin/restore/attest", {});
    ok("POST /restore/attest without a runId is 400", attestNoRun.status === 400);
  }
}

// 3c. point-in-time (/runs/at) + RTO (/rto) routes (E4/C1).
// GET /admin/runs/at resolves a by-timestamp run; the router maps the DO's error-hint (missing downpipe /
// unparseable at) to a 400, while an honest "no run at or before T" is a 200 found:false. GET /admin/rto
// returns the (honest-unknown, no downpipes) estimate shape. Both gate on a read capability the owner holds.
async function testPointInTimeRto(): Promise<void> {
  {
    const env = makeEnv();
    // No downpipe seeded: an unknown downpipe resolves to a 200 found:false (a valid answer, not an error).
    const unknown = await call(env, "GET", "/admin/runs/at?downpipe=ghost&at=2026-06-01T00:00:00.000Z");
    ok("GET /runs/at for an unknown downpipe is 200 found:false", unknown.status === 200 && (await unknown.json() as { found: boolean }).found === false);
    // A MISSING downpipe param -> the DO's error hint -> the router maps it to a 400.
    const noDp = await call(env, "GET", "/admin/runs/at?at=2026-06-01T00:00:00.000Z");
    ok("GET /runs/at with no downpipe is mapped to 400 by the router", noDp.status === 400);
    // An UNPARSEABLE at -> error hint -> 400.
    const badAt = await call(env, "GET", "/admin/runs/at?downpipe=ghost&at=not-a-date");
    ok("GET /runs/at with an unparseable at is mapped to 400 by the router", badAt.status === 400);
    // GET /rto: 200 with the honest empty-fleet shape (no downpipes configured -> unknown fleet, [] rows).
    const rto = await call(env, "GET", "/admin/rto");
    const rtoBody = (await rto.json()) as { fleet: { known: boolean }; downpipes: unknown[] };
    ok("GET /rto is 200 with the honest unknown fleet + empty downpipes", rto.status === 200 && rtoBody.fleet.known === false && rtoBody.downpipes.length === 0);
  }
}

// 4. notifications: channels / rules / history / test.
async function testNotifications(): Promise<void> {
  {
    const env = makeEnv();
    const chans0 = await call(env, "GET", "/admin/notify/channels");
    ok("GET /notify/channels is 200 (empty)", chans0.status === 200);
    // Create a webhook channel (a valid https custom URL, no userinfo, not workers.dev).
    const ch = await call(env, "POST", "/admin/notify/channels", { kind: "webhook", name: "ops", url: "https://hooks.example.com/abc", enabled: true });
    ok("POST /notify/channels creates a channel (200)", ch.status === 200);
    const chId = (await ch.json() as { id?: string }).id;
    ok("the created channel has an id", typeof chId === "string");
    // Create a rule referencing the channel.
    const rule = await call(env, "POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: [chId], enabled: true });
    ok("POST /notify/rules creates a rule (200)", rule.status === 200);
    const ruleId = (await rule.json() as { id?: string }).id;
    // Read rules + history.
    ok("GET /notify/rules is 200", (await call(env, "GET", "/admin/notify/rules")).status === 200);
    ok("GET /notify/history is 200", (await call(env, "GET", "/admin/notify/history")).status === 200);
    // POST /notify/test: deliver a synthetic emission to the configured channels (the webhook POST is the
    // only thing that would leave; we stub global fetch so it does not touch the network).
    const origFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response("", { status: 200 })) as typeof fetch;
    let testResp: Response;
    try {
      testResp = await call(env, "POST", "/admin/notify/test", { channelId: chId });
    } finally {
      globalThis.fetch = origFetch;
    }
    ok("POST /notify/test is 200", testResp.status === 200);
    // Delete the rule + channel.
    ok("POST /notify/rules/delete removes the rule", (await call(env, "POST", "/admin/notify/rules/delete", { id: ruleId })).status === 200);
    ok("POST /notify/channels/delete removes the channel", (await call(env, "POST", "/admin/notify/channels/delete", { id: chId })).status === 200);
  }
}

// 5. credential/key expiry tracker CRUD.
async function testExpiryTracker(): Promise<void> {
  {
    const env = makeEnv();
    ok("GET /expiry is 200 (empty)", (await call(env, "GET", "/admin/expiry")).status === 200);
    // Track an item with a future expiry (a label + kind + ISO date; no secret, redaction-safe).
    const future = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
    const track = await call(env, "POST", "/admin/expiry", { id: "cred-1", label: "BREAK_GLASS_PUBLIC", kind: "credential", expiresAt: future });
    ok("POST /expiry tracks an item (200)", track.status === 200);
    ok("GET /expiry is 200 after tracking", (await call(env, "GET", "/admin/expiry")).status === 200);
    // A malformed item (bad expiresAt) is rejected 400 by the DO re-validation, forwarded through the router.
    const badExpiry = await call(env, "POST", "/admin/expiry", { id: "cred-2", label: "x", kind: "credential", expiresAt: "not-a-date" });
    ok("a malformed expiry item is rejected (400)", badExpiry.status === 400);
    ok("POST /expiry/delete removes the item (200)", (await call(env, "POST", "/admin/expiry/delete", { id: "cred-1" })).status === 200);
  }
}

// 6. drill-evidence log (read + append).
async function testDrillEvidence(): Promise<void> {
  {
    const env = makeEnv();
    ok("GET /drill-evidence is 200 (empty)", (await call(env, "GET", "/admin/drill-evidence")).status === 200);
    const append = await call(env, "POST", "/admin/drill-evidence", { runId: "run-1", kind: "in-account", note: "manual drill passed" });
    ok("POST /drill-evidence appends an entry (200)", append.status === 200);
    ok("GET /drill-evidence is 200 after the append", (await call(env, "GET", "/admin/drill-evidence")).status === 200);
  }
}

// 7. GET /status survives a failing side-channel audit-status DO (engine-src-017-01).
// The audit-status POST is best-effort and side-channel (it records an observed-event diff, never the
// status body), so a DO hiccup on it must degrade that field, not crash the whole status response. We
// drive GET /status against a scheduler whose POST /audit-status throws; the report body is already
// computed by the time that fire-and-forget POST runs, so a wrapped fetch still returns the 200.
async function testStatusSideChannel(SIGNER: string): Promise<void> {
  {
    const env = makeEnvWithFailingAuditStatus({ SIGNER_PRIVATE: SIGNER });
    const status = await call(env, "GET", "/admin/status");
    // RED BEFORE GREEN: with the old unwrapped fetch the throw propagated out of handleAdmin, so call()
    // rejected (no 200, no body). Wrapping it degrades the side-channel and still serves the status read.
    const body = status.status === 200 ? (await status.json() as { signerConfigured?: unknown }) : null;
    ok("[017-01] GET /status is 200 even when the side-channel audit-status DO throws", status.status === 200);
    ok("[017-01] the degraded status body is still well-formed (signerConfigured present)", body !== null && typeof body.signerConfigured === "boolean");
  }
}

// FOLD 2: resolveRollbackTarget must NOT corrupt the known-good on a DOUBLE rollback.
// The hazard: a rollback record stores the abandoned BAD version in toVersion and the reverted-to KNOWN-GOOD
// in fromVersion. A naive resolver that read last.toVersion (or any stale superseded version) for the target
// would deploy the bad version FORWARD on a 2nd rollback and report success. resolveRollbackTarget is
// outcome-aware, so a 2nd rollback resolves the KNOWN-GOOD (we are already on it -> the orchestration no-ops).
function testRollbackTargetFold2(): void {
  {
    // pending in flight -> the version it promoted away from
    ok("[FOLD2] pending -> pending.fromVersion", resolveRollbackTarget({ pending: { fromVersion: "v-good" }, last: null }) === "v-good");
    // applied -> the prior known-good
    ok("[FOLD2] applied -> last.fromVersion (prior known-good)", resolveRollbackTarget({ pending: null, last: { outcome: "applied", fromVersion: "v-good" } }) === "v-good");
    // rolled-back -> last.fromVersion (the reverted-TO known-good, now live), NEVER the bad version in toVersion
    ok("[FOLD2] rolled-back -> last.fromVersion (the known-good), not the bad toVersion", resolveRollbackTarget({ pending: null, last: { outcome: "rolled-back", fromVersion: "v-good" } }) === "v-good");
    // DOUBLE ROLLBACK: after rollback #1 left us on v-good, the resolver yields v-good again so the
    // orchestration short-circuits (already-on-target); it does NOT resolve the abandoned bad version.
    const afterFirstRollback = { pending: null, last: { outcome: "rolled-back", fromVersion: "v-good" } };
    ok("[FOLD2] DOUBLE rollback resolves the known-good, not the abandoned bad version", resolveRollbackTarget(afterFirstRollback) === "v-good");
    // superseded / expired -> NO target (the pending was cleared without a deploy; refuse rather than deploy stale)
    ok("[FOLD2] superseded -> no target (no blind deploy)", resolveRollbackTarget({ pending: null, last: { outcome: "superseded", fromVersion: "v-stale" } }) === "");
    ok("[FOLD2] expired -> no target", resolveRollbackTarget({ pending: null, last: { outcome: "expired", fromVersion: "v-stale" } }) === "");
    // nothing recorded -> no target
    ok("[FOLD2] no record -> no target", resolveRollbackTarget({ pending: null, last: null }) === "");
  }
}

async function main(): Promise<void> {
  // A valid 64-byte signer seed so the SIGNED report arm runs; a second env with no signer exercises the
  // unsigned fail-open arm. (loadSigner takes ed25519 seed(32) || ML-DSA-87 seed(32) = 64 bytes.)
  const SIGNER = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));

  await testTokenAuth();
  await testReports(SIGNER);
  await testPostureCoverage();
  await testRestorabilityGuards();
  await testPointInTimeRto();
  await testNotifications();
  await testExpiryTracker();
  await testDrillEvidence();
  await testStatusSideChannel(SIGNER);
  testRollbackTargetFold2();

  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`ADMIN ROUTER: ${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("ADMIN ROUTER ROUTE VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
