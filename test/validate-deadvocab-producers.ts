// DEAD-VOCABULARY PRODUCERS. The closed-vocabulary members that were DECLARED, documented, and
// had NO PRODUCER: nothing in the engine could ever put them in a pack. Each one is a promise the pack could
// not keep -- the vocabulary tells a support engineer "we will tell you when X happened" and the class was
// empty, which reads as "X did not happen" rather than "nobody ever looked".
//
// EVERY BLOCK BELOW DRIVES THE REAL ENTRY POINT: the DO's own HTTP route (the one the console / the cron /
// the Worker edge actually calls), or the real DO method behind it, with the fault PLANTED IN STORAGE or in
// the request the product itself would make. Nothing here posts a hand-made record into a recorder and
// asserts it comes back: that self-certifying shape is exactly what let this rot (the green suite
// proved the RING could carry the class, never that the PRODUCT could put it there), and a test that would
// still pass with the producer deleted proves nothing at all. So each case additionally asserts the
// NEGATIVE: the legitimate state (a clean ring, an absent knob, a measurement-less drill) records NOTHING,
// which is the noise line, and the line a recorder must not cross.
//
// NO-CUSTODY: a POISON sentinel is planted at every fault site (an email, a token, a raw timestamp string, a
// bucket) and the whole evidence surface is scanned for it byte by byte. Every counter is a closed name and a
// clamped integer; there is no field for a value to travel in.
//
// Run: node test/validate-deadvocab-producers.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage, bindApprovalPrincipals, makeConfig } from "./validate-scheduler-shared.ts";
import { ADMIN_COUNTER_NAMES, ADMIN_COUNTERS_KEY, type AdminCounters } from "../src/admin/diag-records.ts";
import { ADMIN_REFUSALS_KEY, RECENT_ERRORS_KEY, type FaultCountAgg, type RecentErrorEntry, adminRefusalKey } from "../src/sched/sched-fault-ledger.ts";
import { CALLER_HEADER, encodeCaller } from "../src/admin/identity.ts";
import type { RunHistoryEntry } from "../src/sched/types.ts";

declare const process: { exit(code?: number): never };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The sentinels. Each is planted where the fault is, so a recorder that carried ANY of them would be caught.
const POISON_EMAIL = "victim@customer.example";
const POISON_TS = "not-a-timestamp-2026-XX-XX";
const POISON_BUCKET = "customer-private-bucket";
const POISON_TOKEN = "sk-live-DEADBEEFDEADBEEF";

function makeDO(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const stub = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return { storage, stub };
}

async function counters(storage: MockStorage): Promise<AdminCounters> {
  return (await storage.get<AdminCounters>(ADMIN_COUNTERS_KEY)) ?? {};
}
function countOf(c: AdminCounters, name: string): number {
  return c[name]?.count ?? 0;
}

// scanClean proves no sentinel reached the evidence. The counters are {closed name -> {count,lastAt}}: there
// is no field a value could ride in, and this asserts it of the persisted bytes rather than of the type.
function scanClean(label: string, evidence: unknown): void {
  const s = JSON.stringify(evidence ?? {});
  const dirty = [POISON_EMAIL, POISON_TS, POISON_BUCKET, POISON_TOKEN].filter((p) => s.includes(p));
  ok(`${label}: no email, token, bucket or raw timestamp in any byte of the evidence`, dirty.length === 0);
}

const OWNER = { method: "access" as const, email: "owner@example.com", subject: "sub-owner", role: "owner" as const, groups: [] as string[] };
function ownerHeaders(): Record<string, string> {
  return { [CALLER_HEADER]: encodeCaller(OWNER), "content-type": "application/json" };
}
async function seedOwner(storage: MockStorage): Promise<void> {
  await storage.put("role:sub:sub-owner", { subject: "sub-owner", email: OWNER.email, role: "owner", grantedBy: "bootstrap", grantedAt: "2026-07-01T00:00:00.000Z" });
}

function run(runId: string, index: number, startedAt: string, status: "ok" | "failed"): RunHistoryEntry {
  return { runId, index, startedAt, status, durationMs: 1000 } as RunHistoryEntry;
}

// ---------------------------------------------------------------------------------------------------------
// pit-corrupt-run-excluded. THE REAL ENTRY POINT: GET /runs/at, the point-in-time resolver the restore
// timeline calls. A SUCCESSFUL run whose startedAt will not parse is dropped from the resolution, so a run
// that genuinely COVERS the requested instant is invisible and the customer is told their data is not there.
// ---------------------------------------------------------------------------------------------------------
async function testPitCorruptRun(): Promise<void> {
  console.log("\npit-corrupt-run-excluded: a successful run the resolver cannot place on the timeline");
  const T0 = Date.parse("2026-07-01T00:00:00.000Z");
  const at = new Date(T0 + 5 * 86_400_000).toISOString();

  // CLEAN RING FIRST (the noise line): a ring whose rows all parse must record NOTHING, whether or not the
  // query resolves. A recorder that fires here would put a red counter on every healthy account.
  {
    const { storage, stub } = makeDO();
    await storage.put("hist:dp1", [run("r1", 1, new Date(T0).toISOString(), "ok")]);
    const res = await stub.fetch(new Request(`https://do/runs/at?downpipe=dp1&at=${encodeURIComponent(at)}`, { method: "GET" }));
    const body = (await res.json()) as { found: boolean; runId?: string };
    ok("a clean ring resolves the run", body.found === true && body.runId === "r1");
    ok("a clean ring records NOTHING (the exclusion counter must not fire on a healthy account)", countOf(await counters(storage), "pit-corrupt-run-excluded") === 0);
  }

  // THE FAULT: an "ok" run covering T whose startedAt is garbled. It is excluded, the answer flips to "no
  // run exists", and before this the pack could not say why.
  {
    const { storage, stub } = makeDO();
    await storage.put("hist:dp1", [run("r-corrupt", 1, POISON_TS, "ok"), run("r-old", 2, new Date(T0 - 40 * 86_400_000).toISOString(), "failed")]);
    const res = await stub.fetch(new Request(`https://do/runs/at?downpipe=dp1&at=${encodeURIComponent(at)}`, { method: "GET" }));
    const body = (await res.json()) as { found: boolean; excludedCorruptRuns?: number };
    ok("the corrupt row is excluded and the customer is told no run exists (behaviour unchanged)", body.found === false);
    ok("the route reports the exclusion on its own answer", body.excludedCorruptRuns === 1);
    const c = await counters(storage);
    ok("GET /runs/at records pit-corrupt-run-excluded", countOf(c, "pit-corrupt-run-excluded") === 1);
    scanClean("pit-corrupt-run-excluded", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// coverage-inventory-rejected-{shape,over-cap}. THE REAL ENTRY POINT: POST /coverage/inventory, the route the
// console's gap view submits to. A refused inventory means the customer believes they uploaded one and the
// gap view stays empty forever; an over-cap refusal means a big account can NEVER store one.
// ---------------------------------------------------------------------------------------------------------
async function testCoverageInventoryRefusals(): Promise<void> {
  console.log("\ncoverage-inventory-rejected-*: the inventory the customer thinks they uploaded");

  // A VALID inventory records nothing (the noise line).
  {
    const { storage, stub } = makeDO();
    await seedOwner(storage);
    const res = await stub.fetch(new Request("https://do/coverage/inventory", { method: "POST", headers: ownerHeaders(), body: JSON.stringify({ kv: [{ id: "ns-1", name: "prod" }] }) }));
    ok("a valid inventory is stored", res.status === 200);
    ok("a valid inventory records NOTHING", Object.keys(await counters(storage)).length === 0);
  }

  // SHAPE: a group that is not an array of {id}.
  {
    const { storage, stub } = makeDO();
    await seedOwner(storage);
    const res = await stub.fetch(new Request("https://do/coverage/inventory", { method: "POST", headers: ownerHeaders(), body: JSON.stringify({ r2: [{ bucket: POISON_BUCKET }] }) }));
    ok("a mis-shaped inventory is still refused with a 400 (behaviour unchanged)", res.status === 400);
    const c = await counters(storage);
    ok("POST /coverage/inventory records coverage-inventory-rejected-shape", countOf(c, "coverage-inventory-rejected-shape") === 1);
    ok("the over-cap counter is NOT bumped by a shape refusal (the two remedies are opposite)", countOf(c, "coverage-inventory-rejected-over-cap") === 0);
    scanClean("coverage-inventory-rejected-shape", c);
  }

  // OVER-CAP: a per-type list past the ceiling. The submitted ids never ride.
  {
    const { storage, stub } = makeDO();
    await seedOwner(storage);
    const huge = Array.from({ length: 5001 }, (_, i) => ({ id: `${POISON_BUCKET}-${i}` }));
    const res = await stub.fetch(new Request("https://do/coverage/inventory", { method: "POST", headers: ownerHeaders(), body: JSON.stringify({ r2: huge }) }));
    ok("an over-cap inventory is refused WHOLE (behaviour unchanged)", res.status === 400);
    const c = await counters(storage);
    ok("POST /coverage/inventory records coverage-inventory-rejected-over-cap", countOf(c, "coverage-inventory-rejected-over-cap") === 1);
    ok("the shape counter is NOT bumped by an over-cap refusal", countOf(c, "coverage-inventory-rejected-shape") === 0);
    scanClean("coverage-inventory-rejected-over-cap", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// coverage-downpipe-excluded-{unknown-source-type,no-identity-key}. THE REAL ENTRY POINT: GET /coverage, the
// gap view itself. An excluded downpipe covers nothing, so the resource it really does protect is reported
// UNPROTECTED on the screen the customer is audited against.
// ---------------------------------------------------------------------------------------------------------
async function testCoverageExclusions(): Promise<void> {
  console.log("\ncoverage-downpipe-excluded-*: the downpipe the matcher silently dropped");

  // A healthy fleet excludes nothing (the noise line): a matched downpipe must not raise an exclusion.
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp-ok", { config: makeConfig("dp-ok", { source: { type: "kv", binding: "KV_MAIN", namespaceId: "ns-1", include: [], exclude: [] } }), nextRunAt: 0 });
    await storage.put("coverage-inventory", { kv: [{ id: "ns-1" }], r2: [], d1: [], secrets: [] });
    const res = await stub.fetch(new Request("https://do/coverage", { method: "GET" }));
    const body = (await res.json()) as { resources: Array<{ status: string }> };
    ok("the covered resource reads covered", body.resources[0]?.status !== "unprotected");
    ok("a matched downpipe records NOTHING", Object.keys(await counters(storage)).length === 0);
  }

  // NO IDENTITY KEY: a kv source with neither namespaceId nor binding. It matches nothing, so its namespace
  // reads UNPROTECTED -- and nothing said the downpipe had been dropped from matching.
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp-blind", { config: makeConfig("dp-blind", { source: { type: "kv" } as never }), nextRunAt: 0 });
    await storage.put("coverage-inventory", { kv: [{ id: "ns-1" }], r2: [], d1: [], secrets: [] });
    const res = await stub.fetch(new Request("https://do/coverage", { method: "GET" }));
    const body = (await res.json()) as { resources: Array<{ status: string }> };
    ok("the resource reads unprotected (the verdict is unchanged)", body.resources[0]?.status === "unprotected");
    const c = await counters(storage);
    ok("GET /coverage records coverage-downpipe-excluded-no-identity-key", countOf(c, "coverage-downpipe-excluded-no-identity-key") === 1);
    scanClean("coverage-downpipe-excluded-no-identity-key", c);
  }

  // UNKNOWN SOURCE TYPE: a stored source type the matcher does not know (a downgrade, a hand-edited record).
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp-alien", { config: makeConfig("dp-alien", { source: { type: "quantum-store", binding: POISON_BUCKET } as never }), nextRunAt: 0 });
    await storage.put("coverage-inventory", { kv: [{ id: "ns-1" }], r2: [], d1: [], secrets: [] });
    await stub.fetch(new Request("https://do/coverage", { method: "GET" }));
    const c = await counters(storage);
    ok("GET /coverage records coverage-downpipe-excluded-unknown-source-type", countOf(c, "coverage-downpipe-excluded-unknown-source-type") === 1);
    scanClean("coverage-downpipe-excluded-unknown-source-type", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// stored-approval-unparseable-timestamp. THE REAL ENTRY POINT: POST /restore/reserve, the gate-to-write the
// router takes immediately before a destructive apply. A stored approval whose expiresAt will not parse
// NEVER EXPIRES (effectiveStatus only expires on a parseable, past timestamp), so its single-use 24h TTL is
// silently unenforced and the approval stays usable indefinitely.
// ---------------------------------------------------------------------------------------------------------
// The two principals the planted approval record names. They must exist in the DO's own role table, because
// the reserve re-resolves both subjects LIVE before it will hand out a reservation: without them every
// reserve here refuses as an authority lapse and the counter under test is never reached. Both hold
// approver so each half of the spend-time check (maker holds restore.request, checker holds
// restore.approve) resolves, and neither is owner, so the seeding cannot be mistaken for a break-glass.
const APPROVAL_PRINCIPALS = [
  { email: POISON_EMAIL, subject: "sub-a", role: "approver" as const },
  { email: "checker@example.com", subject: "sub-b", role: "approver" as const },
];

async function testStoredApprovalTtl(): Promise<void> {
  console.log("\nstored-approval-unparseable-timestamp: the approval whose TTL cannot be enforced");
  const planHash = "sha384:abc";
  const good = {
    planHash,
    runId: "R1",
    status: "approved",
    requestedBy: POISON_EMAIL,
    requesterSubject: "sub-a",
    approvedBy: "checker@example.com",
    approverSubject: "sub-b",
    requestedAt: "2026-07-01T00:00:00.000Z",
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  };

  // A well-formed approval records nothing (the noise line).
  {
    const { storage, stub } = makeDO();
    await bindApprovalPrincipals(stub, APPROVAL_PRINCIPALS);
    await storage.put(`approval:${planHash}`, good);
    const res = await stub.fetch(new Request("https://do/restore/reserve", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ planHash }) }));
    ok("a well-formed approval reserves", ((await res.json()) as { reserved: boolean }).reserved === true);
    ok("a well-formed approval records NOTHING", countOf(await counters(storage), "stored-approval-unparseable-timestamp") === 0);
  }

  // THE FAULT: the timestamp will not parse, so the record is STILL usable (that is the bug), and now it is
  // recorded. The reserve is deliberately NOT changed -- refusing here would break a real approval on a
  // storage quirk -- so the counter is the only thing that can ever tell an auditor the TTL did not hold.
  {
    const { storage, stub } = makeDO();
    await bindApprovalPrincipals(stub, APPROVAL_PRINCIPALS);
    await storage.put(`approval:${planHash}`, { ...good, expiresAt: POISON_TS });
    const res = await stub.fetch(new Request("https://do/restore/reserve", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ planHash }) }));
    ok("the garbled approval still reserves (behaviour unchanged: the TTL simply never fires)", ((await res.json()) as { reserved: boolean }).reserved === true);
    const c = await counters(storage);
    ok("POST /restore/reserve records stored-approval-unparseable-timestamp", countOf(c, "stored-approval-unparseable-timestamp") === 1);
    scanClean("stored-approval-unparseable-timestamp", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// stored-expiry-unparseable-timestamp. THE REAL ENTRY POINT: POST /expiry/reconcile, the pass the cron driver
// runs every tick. A stored row whose expiresAt will not parse yields NaN days remaining, so no rung is ever
// crossed and it is never warned about: "our destination key expired with zero warning" is this row.
// ---------------------------------------------------------------------------------------------------------
async function testStoredExpiry(): Promise<void> {
  console.log("\nstored-expiry-*: the tracked credential that can never warn");

  // A parseable, approaching item warns and records nothing (the noise line).
  {
    const { storage, stub } = makeDO();
    await storage.put("expiry:key-1", { id: "key-1", label: "Destination key", kind: "key", source: "manual", expiresAt: new Date(Date.now() + 5 * 86_400_000).toISOString() });
    const res = await stub.fetch(new Request("https://do/expiry/reconcile", { method: "POST" }));
    const body = (await res.json()) as { emissions: unknown[] };
    ok("a healthy row still warns", body.emissions.length === 1);
    ok("a healthy row records NOTHING", countOf(await counters(storage), "stored-expiry-unparseable-timestamp") === 0);
  }

  // A NO-EXPIRY item (an absent expiresAt) is a deliberate, honest state and must NOT be counted as a fault.
  {
    const { storage, stub } = makeDO();
    await storage.put("expiry:tok-1", { id: "tok-1", label: "Never-expiring token", kind: "token", source: "observed" });
    await stub.fetch(new Request("https://do/expiry/reconcile", { method: "POST" }));
    ok("a deliberate no-expiry item records NOTHING (absence is not corruption)", countOf(await counters(storage), "stored-expiry-unparseable-timestamp") === 0);
  }

  // THE FAULT: a row that IS dated and whose date will not parse. It stays green forever.
  {
    const { storage, stub } = makeDO();
    await storage.put("expiry:key-2", { id: "key-2", label: "Destination key", kind: "key", source: "manual", expiresAt: POISON_TS });
    const res = await stub.fetch(new Request("https://do/expiry/reconcile", { method: "POST" }));
    const body = (await res.json()) as { emissions: unknown[] };
    ok("the garbled row still warns about nothing (behaviour unchanged)", body.emissions.length === 0);
    const c = await counters(storage);
    ok("POST /expiry/reconcile records stored-expiry-unparseable-timestamp", countOf(c, "stored-expiry-unparseable-timestamp") === 1);
    scanClean("stored-expiry-unparseable-timestamp", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// stored-expiry-write-rejected. THE REAL ENTRY POINT: POST /expiry/observe-attach, the observation the attach
// pipeline makes when it spends an ephemeral Cloudflare token. A refused observation means the credential is
// never enrolled AT ALL, so no warning can EVER fire for it.
// ---------------------------------------------------------------------------------------------------------
async function testExpiryWriteRejected(): Promise<void> {
  console.log("\nstored-expiry-write-rejected: the credential that was never enrolled");

  // A valid observation enrols and records nothing.
  {
    const { storage, stub } = makeDO();
    await stub.fetch(new Request("https://do/expiry/observe-attach", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tokenId: "abc123", expiresOn: new Date(Date.now() + 86_400_000).toISOString(), sourcesAttached: ["KV_MAIN"] }) }));
    const enrolled = [...(await storage.list<unknown>({ prefix: "expiry:" })).keys()];
    ok("a valid observation is enrolled", enrolled.length === 1);
    ok("a valid observation records NOTHING", countOf(await counters(storage), "stored-expiry-write-rejected") === 0);
  }

  // THE FAULT: an id the item validator refuses (a storage-key-unsafe token id). The observation is dropped.
  {
    const { storage, stub } = makeDO();
    await stub.fetch(new Request("https://do/expiry/observe-attach", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tokenId: `../${POISON_TOKEN}/..`, expiresOn: new Date(Date.now() + 86_400_000).toISOString(), sourcesAttached: ["KV_MAIN"] }) }));
    const c = await counters(storage);
    ok("POST /expiry/observe-attach records stored-expiry-write-rejected", countOf(c, "stored-expiry-write-rejected") === 1);
    scanClean("stored-expiry-write-rejected", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// rto-sample-rejected-*. THE REAL ENTRY POINT: POST /restore-test-complete, the callback every drill and
// scheduled restore test makes. "basedOnDrills says 2 but we ran 15 restore tests" is THIS site: the other 13
// completed OK and their measurement was silently unusable, so it never became a sample.
// ---------------------------------------------------------------------------------------------------------
async function testRtoSampleRejects(): Promise<void> {
  console.log("\nrto-sample-rejected-*: the drill measurements the estimate threw away");
  const complete = async (stub: SchedulerDO, body: Record<string, unknown>): Promise<void> => {
    await stub.fetch(new Request("https://do/restore-test-complete", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
  };

  // A GOOD sample is taken and records nothing.
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp1", { config: makeConfig("dp1"), nextRunAt: 0 });
    await complete(stub, { id: "dp1", ok: true, durationMs: 4200, bytesVerified: 1024, recordsVerified: 3 });
    const ds = (await storage.get<{ recoverySamples?: unknown[] }>("dp:dp1"))!;
    ok("a usable measurement becomes a sample", (ds.recoverySamples ?? []).length === 1);
    ok("a usable measurement records NOTHING", Object.keys(await counters(storage)).length === 0);
  }

  // A drill that CLAIMS NO MEASUREMENT (a break-glass posture, a no-run drill) is a legitimate state: it must
  // not fire. This is the noise line, and it is drawn on PRESENCE, not on value.
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp1", { config: makeConfig("dp1"), nextRunAt: 0 });
    await complete(stub, { id: "dp1", ok: true });
    const c = await counters(storage);
    ok("a measurement-less drill records NOTHING (it measured nothing BY DESIGN)", countOf(c, "rto-sample-rejected-non-finite-duration") === 0 && countOf(c, "rto-sample-rejected-non-positive-bytes") === 0);
  }

  // THE FAULT (duration): a broken timer / clock jump. The drill "succeeded"; its sample is dropped.
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp1", { config: makeConfig("dp1"), nextRunAt: 0 });
    await complete(stub, { id: "dp1", ok: true, durationMs: -1, bytesVerified: 4096 });
    const ds = (await storage.get<{ recoverySamples?: unknown[] }>("dp:dp1"))!;
    ok("the unusable sample is still excluded from the estimate (behaviour unchanged)", (ds.recoverySamples ?? []).length === 0);
    const c = await counters(storage);
    ok("POST /restore-test-complete records rto-sample-rejected-non-finite-duration", countOf(c, "rto-sample-rejected-non-finite-duration") === 1);
    ok("the bytes counter is NOT bumped by a duration fault", countOf(c, "rto-sample-rejected-non-positive-bytes") === 0);
    scanClean("rto-sample-rejected-non-finite-duration", c);
  }

  // THE FAULT (bytes): a drill that verified ZERO bytes. It carries no throughput signal.
  {
    const { storage, stub } = makeDO();
    await storage.put("dp:dp1", { config: makeConfig("dp1"), nextRunAt: 0 });
    await complete(stub, { id: "dp1", ok: true, durationMs: 900, bytesVerified: 0 });
    const c = await counters(storage);
    ok("POST /restore-test-complete records rto-sample-rejected-non-positive-bytes", countOf(c, "rto-sample-rejected-non-positive-bytes") === 1);
    ok("the duration counter is NOT bumped by a bytes fault", countOf(c, "rto-sample-rejected-non-finite-duration") === 0);
    scanClean("rto-sample-rejected-non-positive-bytes", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// stored-custom-role-reserved-capability-dropped. THE REAL ENTRY POINT: GET /whoami, the authority resolution
// behind EVERY authenticated request. A stored custom role holding an OWNER-RESERVED capability cannot have
// got there through the product (the create-time validator bars it), so the read-time clamp firing is a
// TAMPER signal -- and it was recorded nowhere.
// ---------------------------------------------------------------------------------------------------------
async function testTamperedCustomRole(): Promise<void> {
  console.log("\nstored-custom-role-reserved-capability-dropped: the tampered custom role");
  const role = (caps: string[]): unknown => ({
    name: "auditor",
    label: "Auditor",
    capabilities: caps,
    surface: {},
    presentation: {},
    landing: "overview",
  });

  // A legitimate custom role (no reserved capability) records nothing.
  {
    const { storage, stub } = makeDO();
    await storage.put("customrole:auditor", role(["posture.read", "downpipe.read"]));
    await storage.put("role:sub:sub-a", { subject: "sub-a", email: POISON_EMAIL, role: "viewer", customRole: "auditor", grantedBy: "owner@example.com", grantedAt: "2026-07-01T00:00:00.000Z" });
    await stub.whoami(POISON_EMAIL, "sub-a", "access", null);
    ok("an untampered custom role records NOTHING", countOf(await counters(storage), "stored-custom-role-reserved-capability-dropped") === 0);
  }

  // THE FAULT: the stored record claims an owner-reserved capability. The clamp drops it (correctly) and the
  // holder does NOT get it -- and now the drop is visible.
  {
    const { storage, stub } = makeDO();
    await storage.put("customrole:auditor", role(["posture.read", "keys.ceremony"]));
    await storage.put("role:sub:sub-a", { subject: "sub-a", email: POISON_EMAIL, role: "viewer", customRole: "auditor", grantedBy: "owner@example.com", grantedAt: "2026-07-01T00:00:00.000Z" });
    const who = await stub.whoami(POISON_EMAIL, "sub-a", "access", null);
    ok("the reserved capability is still DROPPED (the clamp is unchanged)", !(who.capabilities ?? []).includes("keys.ceremony"));
    const c = await counters(storage);
    ok("GET /whoami records stored-custom-role-reserved-capability-dropped", countOf(c, "stored-custom-role-reserved-capability-dropped") === 1);
    scanClean("stored-custom-role-reserved-capability-dropped", c);
  }
}

// ---------------------------------------------------------------------------------------------------------
// {rbac-guardrail, guardrail}. THE REAL ENTRY POINT: POST /roles/delete, the offboarding the people screen
// calls. "Offboarding a departed employee keeps being refused and nobody can say why" -- the guard's refusal
// was a 400 that read, in a pack, exactly like a malformed request.
// ---------------------------------------------------------------------------------------------------------
async function testRbacGuardrailRefusal(): Promise<void> {
  console.log("\n{rbac-guardrail, guardrail}: the policy guardrail that refused in silence");
  const { storage, stub } = makeDO();
  await seedOwner(storage);
  const res = await stub.fetch(new Request("https://do/roles/delete", { method: "POST", headers: ownerHeaders(), body: JSON.stringify({ email: OWNER.email, subject: "sub-owner" }) }));
  ok("the last-Owner removal is still refused (behaviour unchanged)", res.status >= 400);
  const agg = (await storage.get<FaultCountAgg>(ADMIN_REFUSALS_KEY)) ?? {};
  ok("POST /roles/delete records {rbac-guardrail, guardrail}", (agg[adminRefusalKey("rbac-guardrail", "guardrail")]?.count ?? 0) === 1);
  scanClean("{rbac-guardrail, guardrail}", agg);
}

// ---------------------------------------------------------------------------------------------------------
// stored-key-corrupt. THE REAL ENTRY POINT: POST /passkey/login/finish with a STORED credential whose COSE
// public key no longer decodes. The user is told `bad_request` (unchanged, and correct: an internal fault must
// never be oracled back), so the errorId they quote used to be classed `bad-request-shape` -- "you sent
// rubbish" -- about a fault that is entirely the engine's. It is the most misdiagnosed passkey ticket.
// ---------------------------------------------------------------------------------------------------------
async function testStoredKeyCorrupt(): Promise<void> {
  console.log("\nstored-key-corrupt: the engine's own stored credential, misdiagnosed as the user's browser");
  const { storage, stub } = makeDO();
  // The credential id as the browser presents it (base64url), stored under the DO's own canonical key.
  const CRED_ID = "AQIDBA";
  await storage.put(`passkeyCred:${CRED_ID}`, {
    credentialId: CRED_ID,
    email: POISON_EMAIL,
    subject: "sub-a",
    // THE FAULT, planted: the engine's OWN stored COSE public key no longer decodes as base64url.
    cosePublicKey: `%%%not-base64url%%%${POISON_TOKEN}`,
    signCount: 0,
    createdAt: "2026-07-01T00:00:00.000Z",
  });
  // Drive the ceremony the way the browser does: begin mints the challenge, finish presents the assertion.
  const begin = await stub.fetch(new Request("https://do/passkey/login/begin", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: POISON_EMAIL, rpId: "console.example.com" }) }));
  const chal = (await begin.json()) as { challengeId?: string };
  ok("the login ceremony opened", typeof chal.challengeId === "string");
  const finish = await stub.fetch(new Request("https://do/passkey/login/finish", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challengeId: chal.challengeId,
      rpId: "console.example.com",
      origin: "https://console.example.com",
      credential: { id: CRED_ID, response: { clientDataJSON: "e30", authenticatorData: "AAAA", signature: "AAAA" } },
    }),
  }));
  const body = (await finish.json()) as { ok?: boolean; reason?: string };
  ok("the caller is still told the coarse bad_request (the wire contract is unchanged)", body.ok === false && body.reason === "bad_request");
  const ring = (await storage.get<RecentErrorEntry[]>(RECENT_ERRORS_KEY)) ?? [];
  const corrupt = ring.filter((r) => r.reasonClass === "stored-key-corrupt");
  ok("the recentErrors ring classes the errorId as stored-key-corrupt, not bad-request-shape", corrupt.length === 1);
  ok("it is filed against the ceremony stage the user was in", corrupt[0]?.stage === "login/finish");
  scanClean("stored-key-corrupt", ring);
}

async function main(): Promise<void> {
  console.log("DEAD-VOCABULARY PRODUCERS: every block drives the REAL route, with the fault planted in storage\n");
  console.log(`(${ADMIN_COUNTER_NAMES.length} admin counters declared; the ones below had no producer at all)`);
  await testPitCorruptRun();
  await testCoverageInventoryRefusals();
  await testCoverageExclusions();
  await testStoredApprovalTtl();
  await testStoredExpiry();
  await testExpiryWriteRejected();
  await testRtoSampleRejects();
  await testTamperedCustomRole();
  await testRbacGuardrailRefusal();
  await testStoredKeyCorrupt();
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exit(1);
}

await main();
