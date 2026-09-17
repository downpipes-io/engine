// Validates the ENGINE half of the console availability gaps.
//
// Two gaps are refuted on an ENGINE DEFECT, not on weak evidence, and this suite drives the DEFECT
// rather than the recorder.
//
//   The frozen route table holds "POST /auth/recovery-codes/regenerate" -- the gap's own stated WORST
//   case -- and the key was DEAD. The table is looked up in the hub's dispatch loop; /admin/auth/*
//   RETURNS at the pre-auth edge 214 lines earlier, before `sub` (the string the table is keyed on) is
//   even computed. Handing noteAdminWriteRefusal a hand-written string proves the FUNCTION works, but no
//   request on earth could produce that string at that seam, so nothing was ever recorded. THIS suite
//   drives the REAL ROUTER.
//
//   And even when the row fires, `do-fault` alone does not answer the ticket. "I regenerated my
//   recovery codes, it errored, and now NEITHER old nor new codes work" turns on ONE fact: were the old
//   codes already invalidated engine-side? The regenerate PUTS a fresh record over the email's existing
//   one, so the old set verifies before that put and is dead after it, and the two failures either side
//   of it have OPPOSITE remedies, though they present as the same opaque 500 and the same silence.
//
//   The console gates its update-channel row on the engine's `configured` flag, which is the ENGINE'S
//   VERDICT and not the operator's INTENT: checkUpdates answers configured:false for an unparseable
//   UPDATE_CHANNEL_URL, a non-https one, and an UPDATE_SIGNER_PUBLIC that will not parse. In all three
//   both env vars are SET. So a truncated paste of the pinned signer key records nothing and produces a
//   pack byte-identical to a healthy verified channel. The engine carries channelIntended (env presence)
//   and the CLOSED channelFault it already held and used to drop.
//
// THE BAR IS DISCRIMINATION. Each state is driven for real and its row is compared against every other state's.
// Two states that must be told apart and produce one row is a FAILURE here, and so is a row on a legitimate state.
//
// Run with `npx tsx test/validate-availability-r3-engine.ts`.

import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { checkUpdates, UPDATE_CHANNEL_FAULTS } from "../src/admin/updates.ts";
import { ADMIN_REFUSALS_KEY, type AdminRefusals } from "../src/admin/diag-records.ts";
import { AUTH_SIGNAL_NAMES, AUTH_SIGNALS_KEY } from "../src/admin/auth-signals.ts";
import { RECOVERY_PREFIX } from "../src/sched/scheduler-do-limits.ts";
import { AUDIT_PREFIX } from "../src/admin/audit.ts";
import { b64urlEncode } from "../src/crypto/bytes.ts";
import { MockStorage } from "./mock-storage.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function eq(label: string, actual: unknown, expected: unknown): void {
  ok(`${label} (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`, actual === expected);
}
function section(title: string): void {
  console.log(`\n-- ${title} --`);
}

const TOKEN = "r3-admin-token";

// FailingStorage is MockStorage with ONE targeted fault: a put whose key matches `failPut` throws. It is the
// whole experiment, because the fault's POSITION relative to the recovery-record put is the discriminator.
// A blanket failure would prove nothing: it would also break the recorder that is under test.
class FailingStorage extends MockStorage {
  failPut: ((key: string) => boolean) | null = null;
  override async put<T>(key: string, value: T): Promise<void> {
    if (this.failPut?.(key) === true) throw new Error("storage refused the write");
    return super.put(key, value);
  }
}

function makeDo(storage: MockStorage): SchedulerDO {
  return new SchedulerDO({ storage } as unknown as DurableObjectState);
}

function makeEnv(dobj: SchedulerDO, extra?: Partial<Env>): Env {
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

// The refusal aggregate as the PACK reads it: "<surface>:<reason>" -> {count, lastAt}, straight off DO storage.
async function refusalRows(storage: MockStorage): Promise<string[]> {
  const agg = (await storage.get<AdminRefusals>(ADMIN_REFUSALS_KEY)) ?? {};
  return Object.keys(agg).sort();
}

// ---------------------------------------------------------------------------------------------------------
section("the regenerate refusal is reachable THROUGH THE ROUTER (the surface was dead vocabulary)");
// ---------------------------------------------------------------------------------------------------------
{
  const storage = new MockStorage();
  const env = makeEnv(makeDo(storage), {});
  // The bare-token break-glass carries NO per-user email, and recovery codes are a per-user credential, so the
  // route refuses it 403. That is a REAL refusal of a REAL request at the REAL seam: no hand-written path string,
  // no direct call to the recorder. Before the recorder was hoisted over the pre-auth edge, this request could not
  // produce a row by any means, because the route table is keyed on a string this request never reaches.
  const resp = await handleAdmin(
    new Request("https://engine.example/admin/auth/recovery-codes/regenerate", {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
      body: "{}",
    }),
    env,
  );
  eq("the route still answers exactly as it did (403, per-user credential)", resp.status, 403);
  const rows = await refusalRows(storage);
  ok("the gap's WORST-CASE surface now records through the router", rows.includes("recovery-codes-regenerate:forbidden"));
  ok("and it is the ONLY row: nothing else on the pre-auth edge fired", rows.length === 1);
}

// NOISE. The pre-auth edge is the sign-in front door. A recorder over it that fired on ordinary sign-in traffic
// would be worse than no recorder: it is the hottest unauthenticated path in the product.
{
  const storage = new MockStorage();
  const env = makeEnv(makeDo(storage), {});
  const ceremony = await handleAdmin(
    new Request("https://engine.example/admin/auth/login/begin", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }),
    env,
  );
  ok(`a fumbled WebAuthn ceremony (${ceremony.status}) is not a governance write and records NOTHING`, (await refusalRows(storage)).length === 0);

  const recovery = await handleAdmin(
    new Request("https://engine.example/admin/auth/recovery", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "nobody@example.com", code: "wrong" }) }),
    env,
  );
  ok(`a rejected recovery-code SIGN-IN (${recovery.status}) records NOTHING: it is a sign-in, not a refused admin write`, (await refusalRows(storage)).length === 0);

  const unknown = await handleAdmin(new Request("https://engine.example/admin/auth/not-a-route", { method: "POST" }), env);
  ok(`an unknown /admin/auth path (${unknown.status}) records NOTHING: the surface is a frozen table`, (await refusalRows(storage)).length === 0);
}

// ---------------------------------------------------------------------------------------------------------
section("WHICH SIDE OF THE INVALIDATION LINE the failed regenerate died on");
// ---------------------------------------------------------------------------------------------------------
//
// The states, driven through the REAL DO over REAL storage with the REAL recovery crypto:
//
//   (1) never attempted                    -> no signal at all
//   (2) applied                            -> no failure signal; a FRESH record is stored
//   (3) failed BEFORE the store            -> recovery-regenerate-mint-failed;    the STORED RECORD IS UNCHANGED
//   (4) failed AFTER the store             -> recovery-regenerate-old-codes-lost; the STORED RECORD IS REPLACED
//
// (3) and (4) are the gap's worst case and its innocent twin. They were the same 500, the same absence of a row,
// and opposite remedies: "keep using the codes you have" against "you hold no codes at all".
{
  const EMAIL = "owner@example.com";
  const RECOVERY_KEY = `${RECOVERY_PREFIX}${EMAIL}`;
  const signals = async (s: MockStorage): Promise<string[]> =>
    Object.keys((await s.get<Record<string, { count: number }>>(AUTH_SIGNALS_KEY)) ?? {})
      .filter((n) => n.startsWith("recovery-regenerate-"))
      .sort();

  // (1) NEVER ATTEMPTED.
  {
    const storage = new FailingStorage();
    ok("(1) never attempted: no regenerate signal, and no recovery record", (await signals(storage)).length === 0 && !storage.has(RECOVERY_KEY));
  }

  // (2) APPLIED. The healthy path, which must stay silent (a row on a working regenerate is noise).
  const applied = new FailingStorage();
  {
    const dobj = makeDo(applied);
    // The body is {email} only. The DO surface interface declares recoveryRegenerate's body as {email, ip}, and
    // the implementation defaults an absent/unrecognised `method` to "passkey", so passing it explicitly drove
    // the identical path: same actor method, same audit attribution, same invalidation boundary. The boundary is
    // what these four states discriminate on, and it does not read `method` at all.
    const out = await dobj.recoveryRegenerate({ email: EMAIL });
    ok("(2) applied: the caller gets its fresh plaintext set", out.ok === true && out.codes.length > 0);
    ok("(2) applied: NO failure signal fires (a regenerate that worked is not a fault)", (await signals(applied)).length === 0);
    ok("(2) applied: a record is stored", applied.has(RECOVERY_KEY));
  }
  const baseline = JSON.stringify(applied.raw().get(RECOVERY_KEY));

  // (3) FAILED BEFORE THE STORE. The put of the new record itself is refused, so nothing was overwritten and the
  // operator's EXISTING codes still verify. (The classic real cause is an unusable in-DO signing key, which throws
  // in the mint a line earlier; the boundary under test is the same one.)
  const preStore = new FailingStorage();
  {
    // Seed the SAME prior record, so "was it overwritten?" is a byte comparison and not an inference.
    await preStore.put(RECOVERY_KEY, JSON.parse(baseline) as unknown);
    const before = JSON.stringify(preStore.raw().get(RECOVERY_KEY));
    const dobj = makeDo(preStore);
    preStore.failPut = (k) => k === RECOVERY_KEY;
    let threw = false;
    try {
      await dobj.recoveryRegenerate({ email: EMAIL });
    } catch {
      threw = true;
    }
    preStore.failPut = null;
    ok("(3) pre-store: the route still fails exactly as it did (the caller sees its 500)", threw);
    const s = await signals(preStore);
    ok("(3) pre-store: records recovery-regenerate-mint-failed", s.includes("recovery-regenerate-mint-failed"));
    ok("(3) pre-store: and NOT old-codes-lost", !s.includes("recovery-regenerate-old-codes-lost"));
    ok("(3) pre-store: THE OLD RECORD IS UNTOUCHED -- the operator's existing codes still work", JSON.stringify(preStore.raw().get(RECOVERY_KEY)) === before);
  }

  // (4) FAILED AFTER THE STORE. The record LANDED (the old codes are dead) and the audit append then failed, so the
  // caller got a 500 instead of the fresh plaintext. The operator holds NEITHER set. THE GAP'S WORST CASE.
  const postStore = new FailingStorage();
  {
    await postStore.put(RECOVERY_KEY, JSON.parse(baseline) as unknown);
    const before = JSON.stringify(postStore.raw().get(RECOVERY_KEY));
    const dobj = makeDo(postStore);
    postStore.failPut = (k) => k.startsWith(AUDIT_PREFIX);
    let threw = false;
    try {
      await dobj.recoveryRegenerate({ email: EMAIL });
    } catch {
      threw = true;
    }
    postStore.failPut = null;
    ok("(4) post-store: the route fails identically to (3) -- the caller sees the SAME 500", threw);
    const s = await signals(postStore);
    ok("(4) post-store: records recovery-regenerate-old-codes-lost", s.includes("recovery-regenerate-old-codes-lost"));
    ok("(4) post-store: and NOT mint-failed", !s.includes("recovery-regenerate-mint-failed"));
    ok(
      "(4) post-store: THE OLD RECORD IS GONE -- neither old nor new codes work, which is the ticket verbatim",
      JSON.stringify(postStore.raw().get(RECOVERY_KEY)) !== before && postStore.has(RECOVERY_KEY),
    );
  }

  // THE DISCRIMINATION ASSERTION. Four states, four different rows.
  const rows = [
    JSON.stringify(await signals(new FailingStorage())), // (1)
    JSON.stringify(await signals(applied)), // (2)
    JSON.stringify(await signals(preStore)), // (3)
    JSON.stringify(await signals(postStore)), // (4)
  ];
  ok("the two SILENT states (never attempted, applied) are the same silence, which is correct", rows[0] === rows[1]);
  ok("and the two FAILURES are distinct from that silence AND from each other", new Set([rows[0], rows[2], rows[3]]).size === 3);

  // The names must be in the engine's own closed vocabulary, or the DO drops them on the floor and the whole
  // exercise is theatre. (recordAuthSignalSerial drops an out-of-vocabulary name and counts a vocab-drop instead.)
  for (const n of ["recovery-regenerate-mint-failed", "recovery-regenerate-old-codes-lost"]) {
    ok(`${n} is a member of AUTH_SIGNAL_NAMES (an unknown name is DROPPED by the DO)`, (AUTH_SIGNAL_NAMES as readonly string[]).includes(n));
  }
}

// ---------------------------------------------------------------------------------------------------------
section("a MISCONFIGURED channel is not an UNCONFIGURED one (the emit was keyed on the wrong boolean)");
// ---------------------------------------------------------------------------------------------------------
//
// The console keys its update-channel row on channelIntended (env presence), so every state below must be
// distinguishable HERE, in the engine's own verdict, before the console can record it.
{
  // MANGLED is a signer key that will not parse: parseVerifier rejects on LENGTH, which is exactly the shape a
  // truncated / whitespace-mangled paste of the base64url blob arrives in. GOOD_KEY is a well-formed one
  // (Ed25519(32) || ML-DSA-87(2592)), so the channel gets PAST the key check and the FETCH is what fails -- the
  // pair this gap turns on, and a test that used a bad key for both would have proved nothing.
  const MANGLED = "aaaa";
  const GOOD_KEY = b64urlEncode(new Uint8Array(32 + 2592));
  const never = async (_u: string): Promise<Uint8Array | null> => null;

  const states: Array<{ name: string; env: Partial<Env>; fetch?: (u: string) => Promise<Uint8Array | null> }> = [
    { name: "unconfigured (the customer wants no updates)", env: {} },
    { name: "URL set, signer key ABSENT", env: { UPDATE_CHANNEL_URL: "https://update.downpipes.io/channel.json" } },
    { name: "signer key set, URL ABSENT", env: { UPDATE_SIGNER_PUBLIC: GOOD_KEY } },
    { name: "URL unparseable", env: { UPDATE_CHANNEL_URL: "not a url", UPDATE_SIGNER_PUBLIC: GOOD_KEY } },
    { name: "URL not https", env: { UPDATE_CHANNEL_URL: "http://updates.example/channel.json", UPDATE_SIGNER_PUBLIC: GOOD_KEY } },
    { name: "MANGLED PASTE of the pinned signer key", env: { UPDATE_CHANNEL_URL: "https://update.downpipes.io/channel.json", UPDATE_SIGNER_PUBLIC: MANGLED } },
    { name: "channel unreachable", env: { UPDATE_CHANNEL_URL: "https://update.downpipes.io/channel.json", UPDATE_SIGNER_PUBLIC: GOOD_KEY }, fetch: never },
  ];

  const seen: Record<string, string> = {};
  for (const st of states) {
    const r = await checkUpdates(st.env as Env, st.fetch ?? never);
    seen[st.name] = `${String(r.channelIntended)}|${String(r.channelFault)}`;
  }

  ok("UNCONFIGURED is the ONE state that is not intended: it records nothing, and nothing is what it deserves", seen["unconfigured (the customer wants no updates)"] === "false|undefined");
  for (const [name, v] of Object.entries(seen)) {
    if (name.startsWith("unconfigured")) continue;
    ok(`INTENDED: ${name}`, v.startsWith("true|"));
  }
  eq("the MANGLED PASTE -- the state that produced a healthy-looking pack -- names the key", seen["MANGLED PASTE of the pinned signer key"], "true|key-config");
  eq("a URL that will not parse names the URL", seen["URL unparseable"], "true|url-config");
  eq("a non-https URL names the URL", seen["URL not https"], "true|url-config");
  eq("a half-configured channel says WHICH half (key absent)", seen["URL set, signer key ABSENT"], "true|key-config");
  eq("a half-configured channel says WHICH half (URL absent)", seen["signer key set, URL ABSENT"], "true|url-config");
  eq("a channel that cannot be reached is not a signature failure", seen["channel unreachable"], "true|fetch-failed");

  // The mangled key and the unreachable host are the pair the ticket confuses ("the console never told us an
  // update was available"), and they must never be one row.
  ok(
    "a mangled signer key and an unreachable channel are DIFFERENT rows",
    seen["MANGLED PASTE of the pinned signer key"] !== seen["channel unreachable"],
  );
  ok(
    "and a MISCONFIGURED channel is a different row from an UNCONFIGURED one, which is the whole gap",
    seen["MANGLED PASTE of the pinned signer key"] !== seen["unconfigured (the customer wants no updates)"],
  );

  // The fault is a member of the closed set, always. A free string here would be the leak.
  for (const [name, v] of Object.entries(seen)) {
    const fault = v.split("|")[1] ?? "";
    ok(`${name}: the fault is a CLOSED member (or honestly absent), never text`, fault === "undefined" || (UPDATE_CHANNEL_FAULTS as readonly string[]).includes(fault));
  }
}

// ---------------------------------------------------------------------------------------------------------
section("no-custody: a sentinel planted in the channel config reaches no closed field");
// ---------------------------------------------------------------------------------------------------------
{
  const SENTINEL = "acct-9f3-secret-BUCKET-someone@maelstrom.au";
  const r = await checkUpdates(
    { UPDATE_CHANNEL_URL: `https://update.downpipes.io/${SENTINEL}.json`, UPDATE_SIGNER_PUBLIC: SENTINEL } as unknown as Env,
    async () => null,
  );
  // `reason` is prose and stays prose (it is rendered to the operator and is NOT what the console records; the
  // console classifies channelFault). What must be clean is the CLOSED field the pack carries.
  const closed = JSON.stringify({ channelIntended: r.channelIntended, channelFault: r.channelFault });
  ok("the sentinel appears nowhere in the closed channel fields", !closed.includes("acct-9f3") && !closed.includes("maelstrom"));
  ok("negative control: the sentinel IS detectable when actually present", JSON.stringify({ x: SENTINEL }).includes("maelstrom"));
}

console.log(failures === 0 ? "\nAVAILABILITY ENGINE PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
