// A WINDOW WITH TWO FAILURES MUST REPORT THE WORSE ONE, not the earlier one.
//
// The scheduled restore test runs drill.ts in windowed mode. measureWindow DRAINS every per-record failure
// (so the cursor advances past a bad record and coverage keeps rotating) and CLASSIFIES each one, then names
// a single reason for the whole window. It used to keep the FIRST reason in cursor order.
//
// RED BEFORE GREEN, measured over a real sealed six-record archive, not argued. Put a transient 503 on one
// segment object and flip a bit inside another, so one record fails availability and one fails its AEAD tag:
//
//   503 on seg[0], corrupt seg[1]  ->  failures=2, reason "destination access error", replicaFallback TRUE
//   503 on seg[1], corrupt seg[0]  ->  failures=2, reason "integrity check failed",   replicaFallback false
//
// The same damaged archive, the same two faults, opposite verdicts, decided purely by which record the cursor
// reached first. And the cursor ROTATES every tick, so the verdict would flip between ticks on its own. On the
// first ordering the result carries a replica-fallback-eligible reason, so withRunDestFallback
// (admin/router-sources.ts, wired at admin/router-pipelines.ts) walks to the next destination and the tamper
// on THIS copy is never reported: a false negative on tamper detection, not merely a wrong sentence.
//
// The rule now applied is worseRestoreReason (restore-reasons.ts): a failure that genuinely failed a check
// beats one that merely could not reach the bytes, first-seen wins within a class. It is DERIVED from
// isReplicaFallbackReason rather than restating a severity list, so the two cannot drift.
//
// Structure: three positive controls first (healthy, corruption alone, a 503 alone), so a failure below is
// the defect and not the harness; the attack second, in BOTH orderings; then the rule itself, including a
// property over every ordered pair of the classifier's reason vocabulary.
//
// Run:  node test/validate-drill-window-precedence.ts
// In-memory doubles only; no network, no deploy, no cost.
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { runDrill } from "../src/admin/drill.ts";
import { isReplicaFallbackReason, worseRestoreReason, REASON_INTEGRITY, REASON_FRESHNESS, REASON_FRESHNESS_UNVERIFIABLE, REASON_OBJECT_MISSING, REASON_DESTINATION_ACCESS, REASON_RECOVERY_CHECK } from "../src/restore-reasons.ts";
import { flipBit } from "./memdest.ts";
import type { Env } from "../src/env.d.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_drill";
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } },
    identity: concat(xk.secretKey, seed),
  };
}

function adapter(store: Map<string, Uint8Array>, throwOn: string | null) {
  return {
    async get(key: string) {
      if (throwOn !== null && key === throwOn) throw new Error(`GET ${key}: status 503`);
      const b = store.get(key);
      if (!b) return null;
      return {
        arrayBuffer: async () => {
          const out = new ArrayBuffer(b.byteLength);
          new Uint8Array(out).set(b);
          return out;
        },
        etag: `${key.length}`,
        httpEtag: `"${key.length}"`,
      } as never;
    },
    async put() { throw new Error("the drill must never write"); },
    async head() { return null; },
    async list() { return { objects: [], truncated: false }; },
    async delete() {},
    createMultipartUpload: async () => { throw new Error("not implemented"); },
    resumeMultipartUpload: () => { throw new Error("not implemented"); },
  } as never;
}

function corruptSeg(store: Map<string, Uint8Array>, segKey: string): void {
  const copy = new Uint8Array(store.get(segKey)!);
  flipBit(copy, 5 + 16); // past the 5-byte header + 16-byte nonce, into the AEAD ciphertext body
  store.set(segKey, copy);
}

let bad = 0;
let checks = 0;
const ok = (label: string, cond: boolean) => { checks++; console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`); if (!cond) bad++; };

async function main(): Promise<void> {
  const signerPrivateB64 = b64urlEncode(rand(64));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  // Six distinct KV records, so the archive holds several segment objects.
  const records = Array.from({ length: 6 }, (_, i) => ({
    sourceType: "kv",
    name: `key:${i}`,
    value: utf8(`value-number-${i}-${"x".repeat(40 + i)}`),
    namespace: NS,
  }));

  const archive = await buildArchive({
    downpipeId: "dp_drill", downpipeName: "drill-test", cadence: "3600s", runId: RUN_ID,
    master: rand(32), recipients: [bg.entry, op.entry], signer, records,
    windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null,
    randomNonce: () => rand(16), randomSalt: () => rand(16),
  });

  const seed = () => new Map<string, Uint8Array>(archive as unknown as Map<string, Uint8Array>);
  const segKeys = [...seed().keys()].filter((k) => k.startsWith("seg/") && k.endsWith(".seg"));
  console.log(`  ..   the sealed archive holds ${segKeys.length} segment object(s)`);
  ok("PRECONDITION: the archive holds at least TWO distinct segment objects", segKeys.length >= 2);
  if (segKeys.length < 2) { console.error("PRECONDITION FAILED: the attack needs two distinct segment objects"); if (bad + 1 > 0) process.exitCode = 1; process.exit(1); }

  const envFor = (store: Map<string, Uint8Array>, throwOn: string | null) => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2", DEST_R2: adapter(store, throwOn),
    SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
  } as unknown as Env);

  const WINDOW = records.length + 4; // one window covering every record

  // ---- POSITIVE CONTROL 1: a healthy archive verifies ----
  {
    const r = await runDrill(envFor(seed(), null), RUN_ID, null, { cursor: 0, window: WINDOW });
    ok("CONTROL A: a healthy archive over a full window is ok, with no reason", r.ok === true && r.reason === undefined);
  }

  // ---- POSITIVE CONTROL 2: corruption ALONE reads as integrity and does NOT fall back ----
  {
    const s = seed(); corruptSeg(s, segKeys[1]!);
    const r = await runDrill(envFor(s, null), RUN_ID, null, { cursor: 0, window: WINDOW });
    ok("CONTROL B: a corrupt segment ALONE reports the integrity reason", r.reason === REASON_INTEGRITY);
    ok("CONTROL B: that reason does NOT trigger the replica fallback", isReplicaFallbackReason(r.reason) === false);
  }

  // ---- POSITIVE CONTROL 3: a transient fetch fault ALONE reads as availability and DOES fall back ----
  {
    const r = await runDrill(envFor(seed(), segKeys[0]!), RUN_ID, null, { cursor: 0, window: WINDOW });
    ok("CONTROL C: a 503 segment fetch ALONE reports an availability reason", r.reason !== undefined && r.reason !== REASON_INTEGRITY);
    ok("CONTROL C: that reason DOES trigger the replica fallback (correctly)", isReplicaFallbackReason(r.reason) === true);
    console.log(`  ..   CONTROL C reason = ${JSON.stringify(r.reason)}`);
  }

  // ---- THE ATTACK: both faults in ONE window, both orders ----
  console.log("-- THE ATTACK: one transient 503 segment AND one genuinely corrupt segment, same window --");
  for (const [a, b] of [[0, 1], [1, 0]] as const) {
    const s = seed(); corruptSeg(s, segKeys[b]!);
    const r = await runDrill(envFor(s, segKeys[a]!), RUN_ID, null, { cursor: 0, window: WINDOW });
    const fellBack = isReplicaFallbackReason(r.reason);
    console.log(`  ..   503 on seg[${a}], corrupt seg[${b}] -> failures=${r.failedRecordCount} firstFailedIndex=${r.firstFailedIndex} reason=${JSON.stringify(r.reason)} replicaFallback=${fellBack}`);
    ok(`ATTACK[503 seg${a} / corrupt seg${b}]: BOTH records failed, so a real integrity finding IS present`, (r.failedRecordCount ?? 0) >= 2);
    ok(`ATTACK[503 seg${a} / corrupt seg${b}]: the genuine integrity failure WINS the reported reason`, r.reason === REASON_INTEGRITY);
    ok(`ATTACK[503 seg${a} / corrupt seg${b}]: the replica fallback does NOT fire, so the tamper is not masked`, fellBack === false);
  }

  // ---- THE RULE ITSELF, unit-level ----
  // worseRestoreReason is derived from isReplicaFallbackReason rather than restating a severity list, so
  // these assertions are about the DERIVATION, not about a hand-written table that could drift from it.
  console.log("-- the rule: worseRestoreReason --");
  ok("rule: the first reason seen is taken when there is nothing to compare against", worseRestoreReason(null, REASON_DESTINATION_ACCESS) === REASON_DESTINATION_ACCESS);
  ok("rule: undefined behaves as no reason yet", worseRestoreReason(undefined, REASON_INTEGRITY) === REASON_INTEGRITY);
  ok("rule: a finding BEATS an availability fault seen earlier", worseRestoreReason(REASON_DESTINATION_ACCESS, REASON_INTEGRITY) === REASON_INTEGRITY);
  ok("rule: an availability fault does NOT displace a finding seen earlier", worseRestoreReason(REASON_INTEGRITY, REASON_DESTINATION_ACCESS) === REASON_INTEGRITY);
  ok("rule: a freshness verdict is a finding too, and beats an availability fault", worseRestoreReason(REASON_RECOVERY_CHECK, REASON_FRESHNESS) === REASON_FRESHNESS);
  ok("rule: BEHAVIOUR PRESERVED, first-seen still wins between two availability faults", worseRestoreReason(REASON_DESTINATION_ACCESS, REASON_RECOVERY_CHECK) === REASON_DESTINATION_ACCESS);
  ok("rule: BEHAVIOUR PRESERVED, first-seen still wins between two findings", worseRestoreReason(REASON_INTEGRITY, REASON_FRESHNESS) === REASON_INTEGRITY);
  // freshness-unverifiable is fallback-ELIGIBLE (the RUNLOG is written per destination, so a replica can
  // remedy it). It is therefore an availability fault for this rule, and must not displace a finding.
  ok("rule: freshness-could-not-run is fallback-eligible, so it does NOT displace a finding", worseRestoreReason(REASON_INTEGRITY, REASON_FRESHNESS_UNVERIFIABLE) === REASON_INTEGRITY);
  ok("rule: a finding beats freshness-could-not-run seen earlier", worseRestoreReason(REASON_FRESHNESS_UNVERIFIABLE, REASON_INTEGRITY) === REASON_INTEGRITY);
  // The derivation property, stated as a property rather than a case: for every pair of reasons the
  // classifier can produce, the winner is never fallback-eligible when either input is not.
  {
    const vocab = [REASON_INTEGRITY, REASON_FRESHNESS, REASON_FRESHNESS_UNVERIFIABLE, REASON_OBJECT_MISSING, REASON_DESTINATION_ACCESS, REASON_RECOVERY_CHECK, "engine not fully configured"];
    let held = true;
    for (const a of vocab) {
      for (const b of vocab) {
        const w = worseRestoreReason(a, b);
        if ((!isReplicaFallbackReason(a) || !isReplicaFallbackReason(b)) && isReplicaFallbackReason(w)) held = false;
      }
    }
    ok(`rule: PROPERTY over all ${vocab.length * vocab.length} ordered pairs, the winner is never fallback-eligible when either input is a finding`, held);
  }

  console.log(bad === 0 ? "\nALL WINDOW-PRECEDENCE VALIDATIONS PASS" : `\n${bad} FAILURE(S)`);
  if (bad > 0) process.exitCode = 1;
  if (bad > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
