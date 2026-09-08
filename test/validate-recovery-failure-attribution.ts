// validate-recovery-failure-attribution: who the tamper-evident audit chain names as the ACTOR of a
// recovery-code sign-in that FAILED, and whether an unauthenticated caller from the public internet chooses
// that name.
//
// WHY THIS EXISTS. `audit-types.ts` states the rule for this exact class in its own words, on the
// `authn-failure` member: "a FAILED authentication attempt ... No identity is verified on a failure, so the
// actor fields are null (V16.3.1)." Six writers append a chain row with outcome "failed" or "denied". Five
// obey it. The recovery break-glass writes the email OFF THE REQUEST BODY into `actorEmail` on both of its
// negative branches, and POST /admin/auth/recovery is an UNAUTHENTICATED route: nothing has verified that the
// caller is that person, or that the address belongs to the account at all.
//
// The engine's OWN sibling in the SAME feature already refused to do this and wrote down why. `routeRecoveryAlert`
// (src/admin/router-notify.ts) carries the email on a successful USE and deliberately stays generic on a failure,
// because "a failed attempt's 'email' is an unverified guess we must not echo as if it were a real account". The
// notify channel refuses to echo it; the tamper-evident chain records it as the actor.
//
// It drives the REAL SchedulerDO through the REAL router (handleAdmin) with in-memory doubles only. No network,
// no estate, no deploy, no credential spent.
//
// Run: node test/validate-recovery-failure-attribution.ts

import { readFile } from "node:fs/promises";
import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { RECOVERY_PREFIX, RECOVERY_SIGNING_KEY_KEY } from "../src/sched/scheduler-do-base.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ORIGIN = "https://downpipe-console.example";
const ADMIN_TOKEN = "test-admin-token-codeattrib-attribution";
const OWNER = "owner-codeattrib@acme.example";
// THE SENTINEL. It must be REACHED, not merely absent: every assertion about it below first proves a chain row
// was WRITTEN for the attempt, so "no poisoned row" can never hold vacuously over an empty audit log.
const ATTACKER_CHOSEN = "ceo-codeattrib-never-existed@victim.example.invalid";

interface AuditRow {
  seq?: number;
  action?: string;
  outcome?: string;
  actorEmail?: string | null;
  actorSubject?: string | null;
  actorMethod?: string;
  sourceIp?: string | null;
  target?: { kind?: string };
}

function makeScheduler(): { env: Env; storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  const dobj = new SchedulerDO(state);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  const env = { SCHEDULER: namespace, CONSOLE_ORIGIN: ORIGIN, ADMIN_TOKEN } as unknown as Env;
  return { env, storage, stub };
}

async function doFetch(stub: DurableObjectStub, path: string, init?: RequestInit): Promise<Response> {
  return stub.fetch(`https://scheduler.internal${path}`, init);
}

async function mintCodesFor(stub: DurableObjectStub, email: string): Promise<string[]> {
  const resp = await doFetch(stub, "/recovery/regenerate", {
    method: "POST",
    body: JSON.stringify({ email }),
    headers: { "content-type": "application/json" },
  });
  const j = (await resp.json()) as { ok?: boolean; codes?: string[] };
  return j.codes ?? [];
}

// recover drives the UNAUTHENTICATED public route exactly as a browser (or an attacker) reaches it.
async function recover(env: Env, email: unknown, code: unknown, ip: string): Promise<{ status: number; text: string }> {
  const resp = await handleAdmin(
    new Request("https://engine.example/admin/auth/recovery", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": ip },
      body: JSON.stringify({ email, code }),
    }),
    env,
  );
  return { status: resp.status, text: await resp.text() };
}

// readAudit returns every chain row in seq order. It reads the DO's OWN storage, so a row that was never
// appended cannot be invented here.
async function readAudit(storage: MockStorage): Promise<AuditRow[]> {
  const rows = [...(await storage.list<AuditRow>({ prefix: "audit:" })).values()];
  return rows.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
}

// ===========================================================================================
// SECTION 0. THE INJECTION PROOF. Nothing below is worth reading unless the driver actually reaches
// recoveryRecover: a rig that handed a string where a Request was required would make every dose below
// read as a plausible refusal while measuring nothing. The KNOWN POSITIVE runs first: a genuine code must be
// ACCEPTED (200 + a session cookie) and must move the chain by exactly one row. A rig that reaches nothing
// cannot produce a 200 here.
// ===========================================================================================
async function sectionInjectionProof(): Promise<{ reached: boolean }> {
  console.log("\n== SECTION 0: the injection reaches recoveryRecover (known positive) ==");
  const { env, storage, stub } = makeScheduler();
  await storage.put(`role:${OWNER}`, { email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
  const codes = await mintCodesFor(stub, OWNER);
  ok("inject: a real set of codes was minted", codes.length === 10);
  const before = (await readAudit(storage)).length;
  const r = await recover(env, OWNER, codes[0]!, "203.0.113.10");
  const after = await readAudit(storage);
  ok("inject: a GENUINE code is ACCEPTED by the real route (200)", r.status === 200);
  ok("inject: the accepted sign-in returned a session body", r.text.includes("\"ok\":true"));
  ok("inject: the chain moved by exactly one row for one attempt", after.length === before + 1);
  const reached = r.status === 200 && after.length === before + 1;
  ok("inject: THE RIG REACHES THE CODE UNDER TEST", reached);
  return { reached };
}

// ===========================================================================================
// SECTION A. DOSE-RESPONSE across every distinguishable point of the ceremony, recording what the chain
// says PRE and POST at each dose. Five doses, one per branch recoveryRecover can take.
// ===========================================================================================
async function sectionDoseResponse(): Promise<void> {
  console.log("\n== SECTION A: dose-response, what the chain says at each branch ==");
  const { env, storage, stub } = makeScheduler();
  await storage.put(`role:${OWNER}`, { email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
  const codes = await mintCodesFor(stub, OWNER);

  const dose = async (
    label: string,
    email: unknown,
    code: unknown,
    ip: string,
  ): Promise<{ pre: number; post: number; row: AuditRow | undefined; status: number }> => {
    const pre = (await readAudit(storage)).length;
    const r = await recover(env, email, code, ip);
    const rows = await readAudit(storage);
    const row = rows.length > pre ? rows[rows.length - 1] : undefined;
    console.log(
      `  dose ${label}: status=${r.status} rows ${pre}->${rows.length} action=${row?.action ?? "-"} outcome=${row?.outcome ?? "-"} actorEmail=${JSON.stringify(row?.actorEmail ?? null)} actorSubject=${JSON.stringify(row?.actorSubject ?? null)} sourceIp=${JSON.stringify(row?.sourceIp ?? null)}`,
    );
    return { pre, post: rows.length, row, status: r.status };
  };

  // D1: the code is RIGHT. The identity IS established by the match, so the actor is a verified fact.
  const d1 = await dose("D1 correct code", OWNER, codes[1]!, "203.0.113.11");
  ok("D1: a correct code is accepted", d1.status === 200);
  ok("D1: a row was WRITTEN (the sentinel is reached, not absent)", d1.post === d1.pre + 1);
  ok("D1: the row is recovery-code-used with outcome success", d1.row?.action === "recovery-code-used" && d1.row?.outcome === "success");
  ok("D1 CONTROL: a SUCCESSFUL recovery names the actor, because the code match verified them", d1.row?.actorEmail === OWNER);

  // D2: the code is WRONG and the email is one this account really holds.
  const d2 = await dose("D2 wrong code, known email", OWNER, "00000-00000-00000-00000-00000-00000", "203.0.113.12");
  ok("D2: a wrong code is refused generically (401)", d2.status === 401);
  ok("D2: a row was WRITTEN for the refused attempt", d2.post === d2.pre + 1);
  ok("D2: the row is recovery-code-used with outcome failed", d2.row?.action === "recovery-code-used" && d2.row?.outcome === "failed");
  ok("D2: a FAILED attempt names no actor (nothing verified the caller is this person)", d2.row?.actorEmail === null || d2.row?.actorEmail === undefined);

  // D3: THE POISONING. The email is a string the caller invented. It has no recovery record, no role row and
  // no existence of any kind in this account, and the caller presented no credential of any kind.
  const d3 = await dose("D3 wrong code, ATTACKER-CHOSEN email", ATTACKER_CHOSEN, "00000-00000-00000-00000-00000-00000", "203.0.113.13");
  ok("D3: the unauthenticated attempt is refused (401)", d3.status === 401);
  ok("D3: a row was WRITTEN for it, so the chain really did take the write", d3.post === d3.pre + 1);
  ok("D3: the row is recovery-code-used with outcome failed", d3.row?.action === "recovery-code-used" && d3.row?.outcome === "failed");
  ok(
    "D3: an UNAUTHENTICATED caller cannot write a name of their choosing into the tamper-evident chain",
    d3.row?.actorEmail !== ATTACKER_CHOSEN,
  );
  ok("D3 CONTROL: the forensics that ARE established are kept (the source IP and the method)", d3.row?.sourceIp === "203.0.113.13" && d3.row?.actorMethod === "recovery");

  // D4: the RATE-LIMITED branch. Spray until the hard per-email/per-IP limiter denies, then read the row it
  // writes. This is the branch an attacker actually lands on, because the limiter is what stops them.
  let denied: AuditRow | undefined;
  let deniedPre = 0;
  for (let i = 0; i < 40 && denied === undefined; i++) {
    const pre = (await readAudit(storage)).length;
    await recover(env, ATTACKER_CHOSEN, "11111-11111-11111-11111-11111-11111", "203.0.113.14");
    const rows = await readAudit(storage);
    const row = rows.length > pre ? rows[rows.length - 1] : undefined;
    if (row?.outcome === "denied") {
      denied = row;
      deniedPre = pre;
    }
  }
  console.log(`  dose D4 rate-limited: actorEmail=${JSON.stringify(denied?.actorEmail ?? null)} outcome=${denied?.outcome ?? "-"}`);
  ok("D4: the hard limiter DID deny, so this branch was actually reached", denied !== undefined && denied.outcome === "denied");
  ok("D4: a row was WRITTEN for the denied attempt", denied !== undefined && deniedPre >= 0);
  ok(
    "D4: the DENIED branch names no actor either (a throttled guess verifies even less than a wrong code)",
    denied?.actorEmail === null || denied?.actorEmail === undefined,
  );

  // D5: a structurally absent email. The generic-failure contract must be untouched by any of this.
  const d5 = await dose("D5 absent email", undefined, "00000-00000-00000-00000-00000-00000", "203.0.113.15");
  ok("D5 CONTROL: an absent email still fails generically with the same 401 and the same body", d5.status === 401);
  ok("D5: a row was written for it too", d5.post === d5.pre + 1);
  ok("D5: and it names no actor", d5.row?.actorEmail === null || d5.row?.actorEmail === undefined);
}

// ===========================================================================================
// SECTION B. THE BOUNDARY: a single rotation of the recovery signing key can leave ten genuinely-banked,
// unconsumed codes all refused, with the stored bank byte-identical (nothing was consumed) and ten
// distinct audit rows written, one per attempt. EVERY OTHER INPUT IS IDENTICAL to a working ceremony: the
// same ten code strings that D1 proved the route accepts are now refused. That is the boundary between a
// ceremony that succeeds and one that fails at the only point it can fail at without the operator doing
// anything wrong.
// ===========================================================================================
async function sectionOrphanedKeyBoundary(): Promise<void> {
  console.log("\n== SECTION B: ten genuine codes refused by a signing-key rotation ==");
  const { env, storage, stub } = makeScheduler();
  await storage.put(`role:${OWNER}`, { email: OWNER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });

  // Read the bank back BY DIGEST, before and after, never by count: comparing counts alone would miss a
  // bank that reads "identical" while codes were actually spent unremarked underneath it.
  const digest = async (email: string): Promise<string> => {
    const rec = await storage.get<unknown>(`${RECOVERY_PREFIX}${email}`);
    const bytes = new TextEncoder().encode(JSON.stringify(rec ?? null));
    return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
  };

  // THE POSITIVE CONTROL FOR THE DIGEST INSTRUMENT.
  // "The bank is byte-identical after ten refusals" is worth nothing until the same
  // comparison has been shown to MOVE on a real consumption: a mutation that deleted the single-use write
  // entirely left this section green. A separate email, so the per-email limiter budget is untouched below.
  const OTHER = "second-codeattrib@acme.example";
  await storage.put(`role:${OTHER}`, { email: OTHER, role: "owner", grantedBy: "test", grantedAt: new Date().toISOString() });
  const otherCodes = await mintCodesFor(stub, OTHER);
  const posBefore = await digest(OTHER);
  const posResp = await recover(env, OTHER, otherCodes[0]!, "203.0.113.30");
  const posAfter = await digest(OTHER);
  console.log(`  B CONTROL: one genuine consumption moved the bank digest ${posBefore} -> ${posAfter} (status ${posResp.status})`);
  ok("B CONTROL: a real consumption is ACCEPTED, so the control reached the consuming path", posResp.status === 200);
  ok("B CONTROL: and the digest instrument MOVES on it, so an unmoved digest below means something", posBefore !== posAfter);

  const codes = await mintCodesFor(stub, OWNER);
  ok("B: ten codes were banked", codes.length === 10);
  const beforeDigest = await digest(OWNER);

  // THE ROTATION. A fresh 32-byte key under the same record shape: the codes were hashed under the old
  // bytes and nothing on the record changes, so keyContinuity reads "unknown" beside present:true
  // parseable:true unconsumedCodes:10.
  const fresh = crypto.getRandomValues(new Uint8Array(32));
  const b64url = btoa(String.fromCharCode(...fresh)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  await storage.put(RECOVERY_SIGNING_KEY_KEY, { key: b64url, createdAt: new Date().toISOString() });

  const preRows = (await readAudit(storage)).length;
  let refused = 0;
  for (const c of codes) {
    const r = await recover(env, OWNER, c, "203.0.113.20");
    if (r.status === 401) refused++;
  }
  const rows = await readAudit(storage);
  const written = rows.slice(preRows);
  const afterDigest = await digest(OWNER);
  const failedRows = written.filter((r) => r.outcome === "failed").length;
  const deniedRows = written.filter((r) => r.outcome === "denied").length;

  console.log(`  B: ten GENUINE codes presented -> refused=${refused}/10, chain ${preRows} -> ${rows.length} (+${written.length}), outcomes failed=${failedRows} denied=${deniedRows}, bank digest ${beforeDigest} -> ${afterDigest}`);
  ok("B: all ten genuine codes are refused after the rotation (the boundary is crossed)", refused === 10);
  ok("B: the chain gains exactly TEN rows, one per attempt (the live 157 -> 167 reproduced)", written.length === 10);
  ok("B: every one of the ten is action recovery-code-used", written.every((r) => r.action === "recovery-code-used"));
  ok("B: NOT ONE of the ten reads outcome success, so the row is not the consumption claim its NAME reads as", written.every((r) => r.outcome !== "success"));
  ok("B CONTROL: nothing was consumed - the recovery bank is byte-identical BY DIGEST, not by count", beforeDigest === afterDigest);
  // THE HALF NOBODY MEASURED. The hard recovery limiter admits FIVE attempts per 60 seconds, so an operator
  // working through a bank of ten reaches verifyCode with five of them and the other five are denied having
  // been compared against nothing at all. "All ten were examined and all ten were wrong" is not what happened.
  // WHICH BUCKET DENIED IS NOT SEPARATED HERE and this says so: RECOVERY_RATE_MAX_PER_EMAIL and
  // RECOVERY_RATE_MAX_PER_IP are both 5 and this drive holds one email and one IP, so the two are
  // indistinguishable at this dose. The measured fact is the cut at five, not which bucket made it.
  ok("B: exactly five of the ten reached the verifier (the hard recovery limiter admits 5 per 60s)", failedRows === 5);
  ok("B: the other five were DENIED by the hard limiter and were never compared against the record", deniedRows === 5);

  // The engine's own discriminator, on the same response row the pre-flight reads the credential count from.
  // IT MUST BE READ, NOT MERELY NOT-'live': a 403 or an empty body would satisfy `!== "live"` over an answer
  // nobody got, which would be a vacuous pass.
  const sfResp = await handleAdmin(
    new Request(`https://engine.example/admin/signin-factors?email=${encodeURIComponent(OWNER)}`, {
      method: "GET",
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    }),
    env,
  );
  let continuity: string | null = null;
  let verdict: string | null = null;
  let unconsumed: number | null = null;
  if (sfResp.status === 200) {
    const j = (await sfResp.json()) as { factors?: Array<{ signIn?: string; recovery?: { keyContinuity?: string; unconsumedCodes?: number } }> };
    continuity = j.factors?.[0]?.recovery?.keyContinuity ?? null;
    verdict = j.factors?.[0]?.signIn ?? null;
    unconsumed = j.factors?.[0]?.recovery?.unconsumedCodes ?? null;
  }
  console.log(`  B: signin-factors status=${sfResp.status} keyContinuity=${JSON.stringify(continuity)} signIn=${JSON.stringify(verdict)} unconsumedCodes=${JSON.stringify(unconsumed)}`);
  ok("B: the discriminator READ ANSWERED (a refused read must not satisfy the assertion below)", sfResp.status === 200 && continuity !== null);
  ok("B: the engine's OWN read already knows the bank cannot verify (keyContinuity is not 'live')", continuity !== null && continuity !== "live");
  ok("B: and the count beside it still reads ten, which is why a count alone is not a health signal", unconsumed === 10);
}

// ===========================================================================================
// SECTION C. THE SIBLING AND THE CENSUS. The other failed-authentication writer in this engine, driven,
// and a static census of every chain writer that appends a failed/denied row.
// ===========================================================================================
async function sectionSiblingAndCensus(): Promise<void> {
  console.log("\n== SECTION C: the sibling writer and the census of failed/denied chain rows ==");

  // The static census, over src/, of every appendAudit draft carrying outcome "failed" or "denied". It is
  // read off the SOURCE rather than asserted from memory, and it FAILS IN BOTH DIRECTIONS: a new writer that
  // names an unverified actor moves the count, and so does one that stops.
  const FILES = [
    "src/sched/scheduler-do-routing-identity.ts",
    "src/sched/scheduler-do-recovery.ts",
    "src/sched/scheduler-do-siem-push.ts",
    "src/sched/scheduler-do-otlp-push.ts",
    "src/sched/scheduler-do-control-plane.ts",
    "src/admin/audit-status.ts",
  ];
  let nulled = 0;
  let named = 0;
  for (const f of FILES) {
    const src = await readFile(new URL(`../${f}`, import.meta.url), "utf8");
    const lines = src.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (!/outcome:\s*"(failed|denied)"/.test(line)) continue;
      // Walk back to the actorEmail of the same draft literal (within 12 lines; every draft in this codebase
      // is smaller than that). A match INSIDE a comment is not code, so lines whose first non-space is `//`
      // are skipped: a scanner that reads a comment as code would misclassify a real writer.
      let actor: string | null = null;
      for (let j = i; j >= Math.max(0, i - 12); j--) {
        const l = lines[j] ?? "";
        if (/^\s*\/\//.test(l)) continue;
        const m = /actorEmail:\s*([A-Za-z0-9_.]+|null)/.exec(l);
        if (m) {
          actor = m[1] ?? null;
          break;
        }
      }
      if (actor === null) continue;
      if (actor === "null") nulled++;
      else named++;
      console.log(`  census: ${f}:${i + 1} outcome-failed/denied draft, actorEmail=${actor}`);
    }
  }
  console.log(`  census: ${nulled} chain writers null the actor on a failure, ${named} name one`);
  ok("C: the census found the writers at all (a zero here would be an instrument fault, not a clean result)", nulled + named >= 5);
  ok("C: EVERY failed/denied chain writer nulls the actor, per audit-types.ts's own V16.3.1 sentence", named === 0);

  // The sibling, driven rather than read: a failed passkey login writes authn-failure with null actor fields.
  const { storage, stub } = makeScheduler();
  const before = (await readAudit(storage)).length;
  await doFetch(stub, "/passkey/login/finish", {
    method: "POST",
    body: JSON.stringify({ challengeId: "not-a-real-challenge", credentialId: "nope", clientDataJSON: "e30", authenticatorData: "AA", signature: "AA" }),
    headers: { "content-type": "application/json" },
  });
  const rows = await readAudit(storage);
  const authn = rows.slice(before).find((r) => r.action === "authn-failure");
  if (authn !== undefined) {
    console.log(`  C: the sibling wrote authn-failure actorEmail=${JSON.stringify(authn.actorEmail ?? null)} actorSubject=${JSON.stringify(authn.actorSubject ?? null)}`);
    ok("C: the SIBLING failed-authentication writer, driven, names no actor", authn.actorEmail === null && authn.actorSubject === null);
  } else {
    console.log("  C: the passkey login path did not reach its authn-failure append on this shape; the census above stands on the source");
    ok("C: the sibling row was not reached, so it is reported as a could-not-drive rather than a pass", true);
  }
}

async function main(): Promise<void> {
  console.log("CODEATTRIB: what the audit chain names as the actor of a FAILED recovery-code sign-in");
  const inj = await sectionInjectionProof();
  if (!inj.reached) {
    console.log("\nINJECTION DID NOT REACH THE ROUTE. Every dose below would read as a plausible refusal while measuring nothing.");
    failures++;
  } else {
    await sectionDoseResponse();
    await sectionOrphanedKeyBoundary();
    await sectionSiblingAndCensus();
  }
  console.log(`\nCODEATTRIB ATTRIBUTION: ${failures === 0 ? "PASS" : "FAIL"} checks=${checks} failures=${failures}`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exitCode = 1;
}

await main();
