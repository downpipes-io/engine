// validate-owner-floor-breakglass-escape.ts -- BOUNDARIES AND ACCUMULATION.
//
// THE CLAIM UNDER TEST, written in these words in FIVE places (owner-floor.ts, owner-action.ts,
// change-control.ts, scheduler-do-routing-config.ts, scheduler-do-change-control.ts):
//
//   "NO DEADLOCK: ARM is always immediate and the break-glass owner can always disarm immediately,
//    so the account can never be locked out of its own off switch."
//
// owner-floor.ts leans on that same sentence to declare its TWO RESIDUAL EDGES "both RECOVERABLE via
// the break-glass off-switch (the route guarantees the break-glass can always disarm)", one of which
// is "a time-boxed Owner grant can LAPSE below the floor without a mutation firing this guard".
//
// THE ESCAPE IS DISPOSABLE, AND THE PRODUCT PRESCRIBES DISPOSING OF IT. POST
// /admin/policy/retire-break-glass-token sets a durable latch after which a bare ADMIN_TOKEN never
// resolves to owner, so `isBreakGlass` (method === "token") is never true and the immediate-disarm
// branch is unreachable. The dispose-bootstrap-token posture check tells the operator to do exactly
// this, and its own gate checks only "recovery codes ready OR two owners" -- it does NOT ask whether
// dual control is armed, and it does not ask whether the second Owner's grant is TIME-BOXED.
//
// So this file drives the WHOLE LATTICE rather than the one interesting cell: {break-glass alive or
// retired} x {gate off or on} x {two owners or lapsed to one}, reading the ENGINE's own effective
// owner count and the DO's stored gate flag rather than the HTTP status alone, plus the approve
// attempts that decide whether a queued change can ever clear.
//
// Everything runs against the REAL SchedulerDO and the REAL admin router over an in-memory storage
// double. No estate is contacted.
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Env } from "../src/env.d.ts";

import { MockStorage } from "./mock-storage.ts";

const TEAM = "maelstrom";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "escape-owner-floor-aud";
const KID = "escape-owner-floor-kid";
const TOKEN = "escape-break-glass-token";
const O1 = "owner1@acme.example";
const O2 = "owner2@acme.example";
const O3 = "owner3@acme.example";
const jwtPart = (o: unknown): string => b64urlEncode(new TextEncoder().encode(JSON.stringify(o)));

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ONE keypair and ONE stubbed JWKS for the whole run. handleAdmin caches the Access JWKS at module
// scope, so a per-scenario keypair is verified against the FIRST scenario's cached set and every
// caller after the first 401s. That is an INSTRUMENT fault that would have read as a product refusal.
let KP: CryptoKeyPair | null = null;
async function installJwks(): Promise<CryptoKeyPair> {
  if (KP !== null) return KP;
  const kp = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pub.n, e: pub.e }] };
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected network fetch: ${url}`);
  }) as typeof fetch;
  KP = kp;
  return kp;
}

interface Rig {
  storage: MockStorage;
  call(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response>;
  token(method: "GET" | "POST", path: string, body?: unknown): Promise<Response>;
}

async function makeRig(): Promise<Rig> {
  const kp = await installJwks();
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: TOKEN } as unknown as Env;
  const exp = Math.floor(Date.now() / 1000) + 3600;
  async function tokenFor(email: string): Promise<string> {
    const h = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const b = jwtPart({ iss: ISS, aud: AUD, exp, iat: exp - 3600, email, sub: `sub-of-${email}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${h}.${b}`)));
    return `${h}.${b}.${b64urlEncode(sig)}`;
  }
  const call = async (email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> => {
    const a = await tokenFor(email);
    return handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { "cf-access-jwt-assertion": a, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }),
      env,
    );
  };
  const token = (method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
    handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: { authorization: `Bearer ${TOKEN}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }),
      env,
    );
  return { storage, call, token };
}

// lapseOwner realises owner-floor.ts's OWN residual edge 2 -- a time-boxed Owner grant lapsing -- by
// rewriting the stored grant's expiresAt into the past rather than waiting an hour. Nothing else in the
// keyspace is touched, and the grant was created through the real role-set route.
function lapseOwner(storage: MockStorage, email: string): boolean {
  for (const k of storage.keys("")) {
    const v = storage.rawGet<Record<string, unknown>>(k);
    if (v !== null && typeof v === "object" && v !== undefined && v.email === email && typeof v.expiresAt === "string") {
      storage.rawPut(k, { ...v, expiresAt: new Date(Date.now() - 60_000).toISOString() });
      return true;
    }
  }
  return false;
}

interface Cell {
  blockedAt: string;
  blockedReason: string;
  effectiveOwners: number;
  gateOnBefore: boolean;
  disarmStatus: number;
  disarmQueued: boolean;
  roleSetStatus: number;
  tokenDisarmStatus: number;
  gateOnAfter: boolean;
  selfApproveStatus: number;
  lapsedApproveStatus: number;
}

// drive builds one estate at the named coordinates and returns what the ENGINE did, read back from the
// DO's own gate flag and effective owner count rather than from the HTTP status alone.
async function drive(opts: { retire: boolean; arm: boolean; lapse: boolean; extraOwners?: number }): Promise<Cell> {
  const rig = await makeRig();
  await rig.call(O1, "GET", "/admin/whoami"); // bootstrap O1 as the first Owner
  const grant = await rig.call(O1, "POST", "/admin/roles", { email: O2, role: "owner", expiresAt: new Date(Date.now() + 3600_000).toISOString() });
  if (grant.status >= 400) throw new Error(`seed grant failed ${grant.status}: ${await grant.text()}`);
  // A THIRD-AND-FURTHER Owner is AUTO-GATED even with the toggle off (autoGateOwnerMint: minting an
  // approver-capable identity while a second Owner exists queues, to close the puppet-owner path), so
  // each spare has to be approved by the live second Owner.
  for (let i = 0; i < (opts.extraOwners ?? 0); i++) {
    const r = await rig.call(O1, "POST", "/admin/roles", { email: `spare${i}@acme.example`, role: "owner", expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    const rb = (await r.json()) as { queued?: boolean; id?: string };
    if (rb.queued === true && typeof rb.id === "string") {
      const ap = await rig.call(O2, "POST", `/admin/config/changes/${rb.id}/approve`, {});
      if (ap.status >= 400) throw new Error(`spare owner ${i} approve failed ${ap.status}: ${await ap.text()}`);
    }
  }
  await rig.call(O1, "POST", "/admin/auth/recovery-codes/regenerate");

  // A SET-UP STEP THAT REFUSES IS THE RESULT, not an error: the strand guard refusing one of these is
  // precisely how the unrecoverable cell becomes unreachable.
  let blockedAt = "";
  let blockedReason = "";
  if (opts.retire) {
    const r = await rig.call(O1, "POST", "/admin/policy/retire-break-glass-token");
    if (r.status !== 200) {
      blockedAt = "retire";
      blockedReason = (await r.text()).slice(0, 600);
    }
  }
  if (opts.arm && blockedAt === "") {
    const a = await rig.call(O1, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    if (a.status !== 200) {
      blockedAt = "arm";
      blockedReason = (await a.text()).slice(0, 600);
    }
  }
  if (opts.lapse) {
    if (!lapseOwner(rig.storage, O2)) throw new Error("no time-boxed grant found to lapse");
    for (let i = 0; i < (opts.extraOwners ?? 0); i++) {
      if (!lapseOwner(rig.storage, `spare${i}@acme.example`)) throw new Error("no spare grant found to lapse");
    }
  }

  // The EFFECTIVE owner count, from the engine's own countOwners via whoami's isOnlyOwner. The raw
  // /admin/roles list still carries the lapsed entry, so reading THAT would have graded the lapse as
  // not having happened.
  const who = (await (await rig.call(O1, "GET", "/admin/whoami")).json()) as { isOnlyOwner?: boolean };
  const effectiveOwners = who.isOnlyOwner === true ? 1 : 2;
  const gateBefore = (await (await rig.call(O1, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval?: boolean };

  const d = await rig.call(O1, "POST", "/admin/config/approval-policy", { requireConfigApproval: false });
  const dBody = (await d.json()) as { ownerActionQueued?: boolean; id?: string };
  const rs = await rig.call(O1, "POST", "/admin/roles", { email: O3, role: "owner" });
  const td = await rig.token("POST", "/admin/config/approval-policy", { requireConfigApproval: false });

  // CAN THE QUEUED DISARM EVER CLEAR? The maker trying to approve their own action, and the LAPSED
  // second Owner trying to approve it. Both must refuse for the deadlock to be permanent.
  let selfApproveStatus = 0;
  let lapsedApproveStatus = 0;
  if (dBody.ownerActionQueued === true && typeof dBody.id === "string") {
    selfApproveStatus = (await rig.call(O1, "POST", `/admin/owner-actions/${dBody.id}/approve`)).status;
    lapsedApproveStatus = (await rig.call(O2, "POST", `/admin/owner-actions/${dBody.id}/approve`)).status;
  }
  const gateAfter = (await (await rig.call(O1, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval?: boolean };

  return {
    blockedAt,
    blockedReason,
    effectiveOwners,
    gateOnBefore: gateBefore.requireConfigApproval === true,
    disarmStatus: d.status,
    disarmQueued: dBody.ownerActionQueued === true,
    roleSetStatus: rs.status,
    tokenDisarmStatus: td.status,
    gateOnAfter: gateAfter.requireConfigApproval === true,
    selfApproveStatus,
    lapsedApproveStatus,
  };
}

// driveForced assembles the SAME three conditions by writing the org-policy record directly, bypassing
// the three route guards. It answers a different question from drive(): not "can this state be reached"
// but "if an estate is ALREADY in it, is it stranded". Both answers matter, and conflating them would
// let a prevention be reported as a cure.
async function driveForced(): Promise<{ tokenDisarmStatus: number; disarmStatus: number; roleSetStatus: number; gateOnAfter: boolean; effectiveOwners: number }> {
  const rig = await makeRig();
  await rig.call(O1, "GET", "/admin/whoami");
  await rig.call(O1, "POST", "/admin/roles", { email: O2, role: "owner", expiresAt: new Date(Date.now() + 3600_000).toISOString() });
  await rig.call(O1, "POST", "/admin/auth/recovery-codes/regenerate");
  const pol = rig.storage.rawGet<Record<string, unknown>>("orgpolicy") ?? {};
  rig.storage.rawPut("orgpolicy", { ...pol, requireConfigApproval: true, breakGlassTokenRetired: true });
  lapseOwner(rig.storage, O2);
  const who = (await (await rig.call(O1, "GET", "/admin/whoami")).json()) as { isOnlyOwner?: boolean };
  const d = await rig.call(O1, "POST", "/admin/config/approval-policy", { requireConfigApproval: false });
  const rs = await rig.call(O1, "POST", "/admin/roles", { email: O3, role: "owner" });
  const td = await rig.token("POST", "/admin/config/approval-policy", { requireConfigApproval: false });
  const after = (await (await rig.call(O1, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval?: boolean };
  return {
    tokenDisarmStatus: td.status,
    disarmStatus: d.status,
    roleSetStatus: rs.status,
    gateOnAfter: after.requireConfigApproval === true,
    effectiveOwners: who.isOnlyOwner === true ? 1 : 2,
  };
}

async function main(): Promise<void> {
  console.log("the dual-control no-deadlock escape, and whether retiring the break-glass token destroys it");

  // ---- PART 1. THE STATE IS UNREACHABLE THROUGH THE ROUTES. The three conditions can arrive in any
  // order, so all three entrances are driven, and each must refuse with its own sentence.
  console.log("\n-- part 1: each of the three entrances refuses when it would assemble the combination --");
  const orderRetireFirst = await drive({ retire: true, arm: true, lapse: true });
  ok("retire-then-arm is blocked at the ARM step", orderRetireFirst.blockedAt === "arm");
  ok("...and the sentence names dual control, the retired token and the expiring grant", /dual approval/.test(orderRetireFirst.blockedReason) && /break-glass token is retired/.test(orderRetireFirst.blockedReason) && /Owner grant expires/.test(orderRetireFirst.blockedReason));
  ok("...and it names a remedy that exists: re-grant without an expiry", /without an expiry/.test(orderRetireFirst.blockedReason));
  {
    // Arm first, then retire: the OTHER order, refused at the other entrance.
    const rig = await makeRig();
    await rig.call(O1, "GET", "/admin/whoami");
    await rig.call(O1, "POST", "/admin/roles", { email: O2, role: "owner", expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    await rig.call(O1, "POST", "/admin/auth/recovery-codes/regenerate");
    const a = await rig.call(O1, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("arm-first still succeeds (the guard is not a blanket refusal on arming)", a.status === 200);
    // With the gate armed the retire is itself a GATED OWNER ACTION, so the route answers 202 and the
    // refusal can only happen where the mutation actually runs: at APPROVE time, inside the DO method.
    // That is where the guard sits, which is why BOTH paths are covered by one check rather than by a
    // route-level copy that the approve replay would walk straight past.
    const r = await rig.call(O1, "POST", "/admin/policy/retire-break-glass-token");
    const rBody = (await r.json()) as { ownerActionQueued?: boolean; id?: string };
    ok("arm-then-retire is QUEUED as an owner action (202), not applied", r.status === 202 && rBody.ownerActionQueued === true);
    const ap = await rig.call(O2, "POST", `/admin/owner-actions/${rBody.id}/approve`, {});
    const apTxt = await ap.text();
    ok("...and the second Owner's APPROVE is refused, so the retire never lands", ap.status >= 400);
    ok("...and its sentence names turning Require Approver off, a remedy that is reachable right now", /turn Require Approver off/.test(apTxt));
    const stillLive = await rig.token("POST", "/admin/config/approval-policy", { requireConfigApproval: false });
    ok("...and the break-glass token is STILL ALIVE afterwards (the escape was not spent by the attempt)", stillLive.status === 200);
    // The third entrance: an expiring OWNER grant arriving last.
    const rig2 = await makeRig();
    await rig2.call(O1, "GET", "/admin/whoami");
    await rig2.call(O1, "POST", "/admin/roles", { email: O2, role: "owner" }); // PERMANENT, so retire+arm are allowed
    await rig2.call(O1, "POST", "/admin/auth/recovery-codes/regenerate");
    const r2 = await rig2.call(O1, "POST", "/admin/policy/retire-break-glass-token");
    ok("with every Owner grant permanent, the retire is ALLOWED (differential: the guard keys on the expiry)", r2.status === 200);
    const a2 = await rig2.call(O1, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("and arming is ALLOWED too", a2.status === 200);
    const g = await rig2.call(O1, "POST", "/admin/roles", { email: O3, role: "owner", expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    const gTxt = await g.text();
    ok("granting a TIME-BOXED Owner into that state is refused (the third entrance)", g.status >= 400);
    ok("...and its sentence names granting without an expiry", /without an expiry/.test(gTxt));
    const gp = await rig2.call(O1, "POST", "/admin/roles", { email: O3, role: "owner" });
    ok("a PERMANENT Owner grant into the same state is still accepted (202 queued or 200)", gp.status < 400);
    const go = await rig2.call(O1, "POST", "/admin/roles", { email: "op@acme.example", role: "operator", expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    ok("a time-boxed OPERATOR grant is untouched: only an Owner grant can lapse the Owner count", go.status < 400);
  }

  // ---- PART 2. THE STATE IS STILL FATAL IF AN ESTATE IS ALREADY IN IT. The fix is PREVENTION, not a
  // cure: this part proves the state is still fatal for an estate already in it. Assembled by writing the org-policy
  // record directly, so the three route guards are bypassed exactly as a pre-fix estate bypassed them.
  console.log("\n-- part 2: an estate ALREADY in the combination is stranded, so this fix is prevention and not a cure --");
  const forced = await driveForced();
  console.log(`  forced: disarm=${forced.disarmStatus} roleSet=${forced.roleSetStatus} tokenDisarm=${forced.tokenDisarmStatus} gateAfter=${forced.gateOnAfter} effOwners=${forced.effectiveOwners}`);
  ok("effective owner count is 1", forced.effectiveOwners === 1);
  ok("the attributable owner's disarm is QUEUED (202) for a second Owner that no longer exists", forced.disarmStatus === 202);
  ok("appointing a replacement Owner is ALSO queued (202), so the other exit is closed", forced.roleSetStatus === 202);
  ok("the break-glass escape is GONE (the bare token no longer disarms)", forced.tokenDisarmStatus !== 200);
  ok("the gate is STILL ON afterwards, read from the DO rather than from a status code", forced.gateOnAfter);

  // ---- PART 3. THE INSTRUMENT CAN SEE A PASS. Everything above is a refusal, so a broken rig would
  // score full marks. These cells must NOT refuse.
  console.log("\n-- part 3: positive controls, so the refusals above mean something --");
  const alive = await drive({ retire: false, arm: true, lapse: true });
  ok("with the break-glass ALIVE, arming with an expiring Owner grant is allowed", alive.blockedAt === "");
  ok("the lapse really reduces the ENGINE's own effective owner count to 1", alive.effectiveOwners === 1);
  ok("and the bare token disarms IMMEDIATELY (200): the documented escape, exercised", alive.tokenDisarmStatus === 200);
  ok("and the DO's stored gate flag really goes OFF, not merely a 200", !alive.gateOnAfter);
  ok("the attributable owner's own disarm is still QUEUED (202), so the asymmetry is intact", alive.disarmStatus === 202 && alive.disarmQueued);

  const noGate = await drive({ retire: true, arm: false, lapse: true });
  ok("with the gate off, the retire is allowed and disarm applies immediately (200)", noGate.blockedAt === "" && noGate.disarmStatus === 200);
  ok("with the gate off, appointing a new Owner applies immediately (200)", noGate.roleSetStatus === 200);

  const live2 = await drive({ retire: false, arm: true, lapse: false });
  ok("armed with two live owners: the disarm is queued (202), exactly as designed", live2.disarmStatus === 202);
  ok("and the LIVE second owner CAN approve it, so the queue is not stuck in general", live2.lapsedApproveStatus < 400);
  ok("so the gate is OFF afterwards on that cell", !live2.gateOnAfter);

  // ---- PART 4. DOSE-RESPONSE. The trap is a property of the EFFECTIVE Owner count reaching one, not of
  // how many Owners the estate started with.
  console.log("\n-- part 4: dose-response over the owner count, on the forced state --");
  for (const extra of [0, 1, 2]) {
    const partial = await drive({ retire: false, arm: true, lapse: false, extraOwners: extra });
    const all = await drive({ retire: false, arm: true, lapse: true, extraOwners: extra });
    ok(`with ${2 + extra} owners and none lapsed, the queue can still clear`, partial.lapsedApproveStatus < 400);
    ok(`with ${2 + extra} owners all lapsed to one, only the break-glass clears it`, all.lapsedApproveStatus >= 400 && all.tokenDisarmStatus === 200);
  }

  // ---- PART 5. THE UN-RETIRE ROUTE. A SOURCE SCAN, not an exported list: the failure to catch is an
  // ABSENCE, and an exported list cannot see a member that never joined it.
  console.log("\n-- part 5: the un-retire route --");
  const adminDir = join(new URL(".", import.meta.url).pathname, "..", "src", "admin");
  const adminSrc: string[] = [];
  for (const f of readdirSync(adminDir)) if (f.endsWith(".ts")) adminSrc.push(join(adminDir, f));
  let sendsFalse = 0;
  let sendsTrue = 0;
  for (const f of adminSrc) {
    const lines = readFileSync(f, "utf8").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i]!.trim();
      if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) continue;
      if (!/break-glass-retired/.test(lines[i]!.replace(/\/\/.*$/, ""))) continue;
      for (let j = i; j < Math.min(i + 6, lines.length); j++) {
        const w = lines[j]!.trim();
        if (w.startsWith("//") || w.startsWith("*") || w.startsWith("/*")) continue;
        const code = lines[j]!.replace(/\/\/.*$/, "");
        if (/retired:\s*false/.test(code)) sendsFalse++;
        if (/retired:\s*true/.test(code)) sendsTrue++;
      }
    }
  }
  ok("the router DOES send retired:true, so the scan is on the right lines (a positive control)", sendsTrue > 0);
  ok("NO router line sends retired:false, so the un-retire the DO honours is unreachable from the product", sendsFalse === 0);

  if (failures > 0) process.exitCode = 1;
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-owner-floor-breakglass-escape: ${checks - failures}/${checks}`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
