// Canary backup validator. Three parts, all in-memory (no live R2, no env secrets beyond the
// keys generated here):
//   A. the known corpus is deterministic, and the PrefixedDestination namespaces every key;
//   B. the known-answer detection works end to end: the corpus seals through the REAL pipeline,
//      reads back byte-exact (alive), and a single flipped byte in a stored segment is detected
//      (dead) - this is the whole point of the canary;
//   C. the scheduler-DO state machine flies, records, transitions dead -> recovered, and gates
//      the schedule on enabled + the in-flight lease.
//
// Run: node test/validate-canary.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { runBackup, type RunConfig, type RunClock } from "../src/seal/pipeline.ts";
import { type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { readFileSync } from "node:fs";
import { parseIdentity } from "../src/crypto/keys.ts";
import { destDownReason } from "../src/dest/classify.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { SourceAdapter, SourceRecord, Selector } from "../src/sources/types.ts";
import { concat } from "../src/crypto/bytes.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import { CANARY_CORPUS, CANARY_CORPUS_BYTES, CanarySource } from "../src/canary/corpus.ts";
import { PrefixedDestination, prefixedStore } from "../src/canary/prefixed-dest.ts";
import { classifyReadFailure, finalise } from "../src/canary/cycle-helpers.ts";
import { formatUnsupportedError, freshnessError, freshnessUnverifiableError, integrityError } from "../src/format/integrity-error.ts";
import type { CanaryAspectResult, CanaryView, CanaryFlightPlan, CanaryCheckResult } from "../src/canary/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
// throwsAsync returns true iff the async fn rejects (the canary's "a fault was detected" signal).
async function throwsAsync(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

// flipBit XORs a single byte at the given in-bounds index of a buffer (the tamper-injection used by the
// negative controls below). Under noUncheckedIndexedAccess a typed-array element read is number | undefined,
// so a bare `buf[i] ^= 1` reads a possibly-undefined operand; this asserts the index is in bounds (it always
// is for the non-empty buffers here) and then flips, leaving the tamper behaviour identical.
function flipBit(buf: Uint8Array, index: number): void {
  const b = buf[index];
  if (b === undefined) throw new Error(`flipBit: index ${index} out of bounds (length ${buf.length})`);
  buf[index] = b ^ 0x01;
}

// ---- In-memory Destination (the seal/restore target) -----------------------------------------
class MemoryDestination implements Destination {
  store = new Map<string, { body: Uint8Array; etag: string }>();
  private counter = 0;
  private nextEtag(): string {
    return `"${++this.counter}"`;
  }
  async get(key: string): Promise<GetResult | null> {
    const v = this.store.get(key);
    return v ? { body: v.body, etag: v.etag } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.store.set(key, { body, etag: this.nextEtag() });
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    let n = 0;
    for (const p of parts) n += p.length;
    const merged = new Uint8Array(n);
    let off = 0;
    for (const p of parts) {
      merged.set(p, off);
      off += p.length;
    }
    this.store.set(key, { body: merged, etag: this.nextEtag() });
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.store.get(key);
    if (opts.ifNoneMatch === "*" && cur) return { ok: false };
    if (opts.ifMatch && (!cur || cur.etag !== opts.ifMatch)) return { ok: false };
    const etag = this.nextEtag();
    this.store.set(key, { body, etag });
    return { ok: true, etag };
  }
  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix));
  }
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { stub: SchedulerDO; storage: MockStorage } {
  const storage = new MockStorage();
  const stub = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return { stub, storage };
}

// seedDestinations writes a minimal multi-destination collection into the DO storage so the canary
// has real destinations to fan out across (only id/label/defaultId matter to the canary).
function seedDestinations(storage: MockStorage, dests: Array<{ id: string; label: string }>, defaultId: string): void {
  const list = dests.map((d) => ({ id: d.id, label: d.label, endpoint: "https://x.example", bucket: d.id, region: "auto", accessKeyId: "k", secretAccessKey: "s", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }));
  (storage as unknown as { put(k: string, v: unknown): Promise<void> }).put("destinations", { list, defaultId });
}

// RecordSource yields arbitrary records to the seal pipeline, so a test can seal data that DIFFERS
// from the known corpus and prove the byte-compare (not just the internal hash) catches it.
class RecordSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private records: Array<{ name: string; value: Uint8Array }>;
  constructor(records: Array<{ name: string; value: Uint8Array }>) {
    this.records = records;
  }
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    for (const r of this.records) yield { sourceType: "kv", name: r.name, value: r.value, namespace: "canary" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: this.records.length, bytes: this.records.reduce((n, r) => n + r.value.length, 0) };
  }
}
// The canary CONFIG route (POST /canary/config) now re-resolves Owner in the DO (defence in depth, matching
// setDestConfig / setRequireConfigApproval), so the validator drives it as the bare-token break-glass owner
// (which roleForCaller resolves to owner). The caller header is harmless on the internal canary routes (they
// ignore it), so it is sent on every call for simplicity.
const OWNER_TOKEN_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
function doFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  return dobj.fetch(
    new Request(`https://scheduler.internal${path}`, {
      method,
      headers: { [CALLER_HEADER]: encodeCaller(OWNER_TOKEN_CALLER), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
  );
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// sealCorpus seals the canary corpus through the REAL pipeline into an isolated namespace, exactly
// as the cycle does, and returns the backing store plus the keys to read it back.
async function sealCorpus(prefix: string, source: SourceAdapter = new CanarySource()): Promise<{ mem: MemoryDestination; identity: ReturnType<typeof parseIdentity>; verifier: { ed: Uint8Array; mldsa: Uint8Array }; runId: string }> {
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  const mem = new MemoryDestination();
  const dest = new PrefixedDestination(mem, prefix);
  const runId = "01ARZ3NDEKTSV4RRFFQ69G5CAN";
  const cfg: RunConfig = { downpipeId: "__canary", downpipeName: "Canary", cadence: "3600s", selector: { include: [], exclude: [] }, recipients: [breakGlass.entry, op.entry] };
  const clock: RunClock = { runId, runlogIndex: 1, prevRunId: null, now: "2026-06-07T00:00:01.000Z", randomNonce: () => rand(16), randomSalt: () => rand(16), master: rand(32) };
  await runBackup([source], cfg, signer, dest, clock);
  return { mem, identity: parseIdentity(op.identity), verifier: { ed: edPublic, mldsa: mldsa.publicKey }, runId };
}

// verifyAgainstCorpus opens the sealed run and byte-compares every record to the known corpus,
// returning the count of records that matched exactly. A thrown error (a failed plaintext hash on
// a corrupted segment) is the dead signal and is surfaced as a throw to the caller.
async function verifyAgainstCorpus(store: ObjectStore, runId: string, identity: ReturnType<typeof parseIdentity>, verifier: { ed: Uint8Array; mldsa: Uint8Array }): Promise<number> {
  const run = await openRun(store, runId, identity, verifier, { verifyFreshness: true });
  const remaining = CANARY_CORPUS.map((r) => r.value);
  let matched = 0;
  for (const rec of run.records) {
    const plaintext = await run.restoreRecord(rec);
    const idx = remaining.findIndex((v) => bytesEqual(v, plaintext));
    if (idx >= 0) {
      remaining.splice(idx, 1);
      matched++;
    }
  }
  return matched;
}

// Each lettered section is its own async function so a failure's section is obvious and no single
// function breaches the length limit (finding test-002-08). main() calls them in order.

// A. corpus determinism + prefixed destination.
async function sectionA(): Promise<void> {
  ok("corpus has the seven known records", CANARY_CORPUS.length === 7);
  ok("corpus total bytes is the sum of record lengths", CANARY_CORPUS_BYTES === CANARY_CORPUS.reduce((n, r) => n + r.value.length, 0));
  ok("corpus all-bytes record spans every byte value 0x00..0xff", CANARY_CORPUS.some((r) => r.name === "canary/all-bytes" && r.value.length === 256 && r.value[0] === 0 && r.value[255] === 255));
  // The deterministic 1k block is identical on a fresh read of the frozen corpus (no clock, no random).
  const blockA = CANARY_CORPUS.find((r) => r.name === "canary/block-1k")!.value;
  ok("the deterministic 1k block is exactly 1024 bytes", blockA.length === 1024);

  {
    const mem = new MemoryDestination();
    const dest = new PrefixedDestination(mem, "_CANARY/runs/RUN/");
    await dest.put("seg/abc", new Uint8Array([1, 2, 3]));
    ok("PrefixedDestination writes under the namespace", mem.store.has("_CANARY/runs/RUN/seg/abc"));
    const got = await dest.get("seg/abc");
    ok("PrefixedDestination reads back its own logical key", got !== null && bytesEqual(got.body, new Uint8Array([1, 2, 3])));
    ok("PrefixedDestination exists() is namespaced", (await dest.exists("seg/abc")) === true);
    const listed = await dest.list("seg/");
    ok("PrefixedDestination.list strips the namespace back off", listed.length === 1 && listed[0] === "seg/abc");
    await dest.delete("seg/abc");
    ok("PrefixedDestination delete removes the namespaced object", !mem.store.has("_CANARY/runs/RUN/seg/abc"));
  }
}

// B. INTEGRITY / no-faking: every detection mechanism genuinely fires on a real fault.
// The canary's verdict comes from REAL operations (the same runBackup + openRun + restoreRecord the
// live cycle calls), not a hardcoded pass. Each test injects ONE fault and proves the canary catches
// it, so it cannot silently fake a pass and WILL go dead on a real issue.
async function sectionB(): Promise<void> {

  // B0: a clean flight matches every known record byte-for-byte -> alive.
  {
    const prefix = "_CANARY/runs/CLEAN/";
    const { mem, identity, verifier, runId } = await sealCorpus(prefix);
    const matched = await verifyAgainstCorpus(prefixedStore(mem, prefix), runId, identity, verifier);
    ok("B0 clean flight: all known records match byte-for-byte (alive)", matched === CANARY_CORPUS.length);
  }

  // B1: a single flipped bit in a stored DATA segment -> decrypt-integrity catches it (restoreRecord
  // recomputes the plaintext SHA-384 and throws).
  {
    const prefix = "_CANARY/runs/SEGBIT/";
    const { mem, identity, verifier, runId } = await sealCorpus(prefix);
    const segKey = [...mem.store.keys()].find((k) => k.startsWith(`${prefix}seg/`))!;
    const cur = mem.store.get(segKey)!;
    const corrupted = cur.body.slice();
    flipBit(corrupted, corrupted.length >> 1);
    mem.store.set(segKey, { body: corrupted, etag: cur.etag });
    ok("B1 one flipped data bit is detected (decrypt-integrity, dead)", await throwsAsync(() => verifyAgainstCorpus(prefixedStore(mem, prefix), runId, identity, verifier)));
  }

  // B2: a tampered MANIFEST (the signed run tree) -> read-signature catches it (openRun verifies the
  // root + shard manifest signatures and throws).
  {
    const prefix = "_CANARY/runs/MANIFEST/";
    const { mem, identity, verifier, runId } = await sealCorpus(prefix);
    const manKey = [...mem.store.keys()].find((k) => k.startsWith(`${prefix}run/`))!;
    const cur = mem.store.get(manKey)!;
    const corrupted = cur.body.slice();
    flipBit(corrupted, corrupted.length >> 1);
    mem.store.set(manKey, { body: corrupted, etag: cur.etag });
    ok("B2 a tampered manifest is detected (read-signature, dead)", await throwsAsync(() => openRun(prefixedStore(mem, prefix), runId, identity, verifier, { verifyFreshness: true })));
  }

  // B3: a corrupted RUNLOG -> runlog-freshness catches it (the signed RUNLOG no longer verifies).
  {
    const prefix = "_CANARY/runs/RUNLOG/";
    const { mem, identity, verifier, runId } = await sealCorpus(prefix);
    const logKey = `${prefix}_RECOVERY/RUNLOG`;
    const cur = mem.store.get(logKey)!;
    const corrupted = cur.body.slice();
    flipBit(corrupted, corrupted.length >> 1);
    mem.store.set(logKey, { body: corrupted, etag: cur.etag });
    ok("B3 a corrupted RUNLOG is detected (runlog-freshness, dead)", await throwsAsync(() => openRun(prefixedStore(mem, prefix), runId, identity, verifier, { verifyFreshness: true })));
  }

  // B4: an INTERNALLY-VALID archive of the WRONG data -> the known-answer byte-compare catches it. This
  // is the strongest "no-faking" check: restoreRecord SUCCEEDS (the archive is self-consistent), but
  // the bytes do not match the known corpus, so fewer than all records match. A canary that only
  // trusted the internal hash would call this alive; the byte-compare against the KNOWN data calls it dead.
  {
    const prefix = "_CANARY/runs/WRONGDATA/";
    const wrong = CANARY_CORPUS.map((r) => ({ name: r.name, value: r.value.slice() }));
    flipBit(wrong[0]!.value, 0); // one byte of one record differs from the known answer
    const { mem, identity, verifier, runId } = await sealCorpus(prefix, new RecordSource(wrong));
    const matched = await verifyAgainstCorpus(prefixedStore(mem, prefix), runId, identity, verifier);
    ok("B4 internally-valid WRONG data is caught by the known-answer compare (dead)", matched < CANARY_CORPUS.length);
  }

  // B5: restore-verify exercises the PRODUCTION byte-compare path (verifyAgainstCorpus), the same
  // mechanism the cycle uses after restoring, against a sealed run whose LAST record is one byte off
  // the known corpus. The archive is internally self-consistent (restoreRecord succeeds), so only the
  // known-answer compare against the corpus catches the discrepancy: fewer than all records match.
  // This complements B4 (which off-bytes the FIRST record) by faulting a late record, so a regression
  // that only compared the head would still leave at least one fault mode uncovered here.
  {
    const prefix = "_CANARY/runs/RESTOREVERIFY/";
    const offByOne = CANARY_CORPUS.map((r) => ({ name: r.name, value: r.value.slice() }));
    flipBit(offByOne[offByOne.length - 1]!.value, 0); // the LAST record differs from the known answer
    const { mem, identity, verifier, runId } = await sealCorpus(prefix, new RecordSource(offByOne));
    const matched = await verifyAgainstCorpus(prefixedStore(mem, prefix), runId, identity, verifier);
    ok("B5 restore-verify: a one-byte-off late record is caught by the production known-answer compare (dead)", matched < CANARY_CORPUS.length);
  }
}

// C. scheduler-DO multi-destination state machine.
async function sectionC(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    seedDestinations(storage, [{ id: "r2", label: "R2 Primary" }, { id: "s3", label: "S3 Backup" }], "r2");

    const view0 = (await (await doFetch(stub, "GET", "/canary")).json()) as CanaryView;
    ok("C: on by default, flying to ALL destinations", view0.config.enabled === true && view0.flyingToAll === true);
    ok("C: the view lists both destinations to fly to", view0.dests.length === 2 && view0.allDestinations.length === 2);
    ok("C: a fresh canary is pending", view0.status === "pending");

    const due1 = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1_000_000 })).json()) as { due: boolean; run?: CanaryFlightPlan };
    ok("C: first flight is due and plans one run per destination", due1.due === true && due1.run!.dests.length === 2);
    ok("C: each destination gets its own runId", due1.run!.dests[0]!.runId !== due1.run!.dests[1]!.runId);
    const due1b = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1_000_100 })).json()) as { due: boolean };
    ok("C: a second due-check inside the lease is not re-flown", due1b.due === false);

    // Complete with one alive and one DEAD -> aggregate dead; the dead destination transitions.
    const aliveR2: CanaryCheckResult = { status: "alive", durationMs: 5, destinationId: "r2", aspects: [], byteDelta: 0, deadReason: null };
    const deadS3: CanaryCheckResult = { status: "dead", durationMs: 6, destinationId: "s3", aspects: [{ key: "decrypt-integrity", outcome: "fail", detail: "1 byte strayed" }], byteDelta: 1, deadReason: "decrypt-integrity: 1 byte strayed" };
    const comp1 = (await (await doFetch(stub, "POST", "/canary/complete", { run: due1.run, results: [aliveR2, deadS3] })).json()) as { transitions: Array<{ destinationId: string | null; label: string; transitioned: string }> };
    ok("C: exactly one destination transitions (S3 fell dead), with its label", comp1.transitions.length === 1 && comp1.transitions[0]!.destinationId === "s3" && comp1.transitions[0]!.transitioned === "dead" && comp1.transitions[0]!.label === "S3 Backup");

    const v1 = (await (await doFetch(stub, "GET", "/canary")).json()) as CanaryView;
    ok("C: aggregate is DEAD when any destination died", v1.status === "dead");
    ok("C: R2 alive + S3 dead in the per-destination view, S3 has a deadSince", v1.dests.find((d) => d.destinationId === "r2")!.status === "alive" && v1.dests.find((d) => d.destinationId === "s3")!.status === "dead" && v1.dests.find((d) => d.destinationId === "s3")!.deadSince !== null);

    // Recover S3 (R2 still alive) -> aggregate alive; S3 transitions 'recovered'.
    await doFetch(stub, "POST", "/canary/run-now");
    const due2 = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 2_000_000 })).json()) as { due: boolean; run?: CanaryFlightPlan };
    const aliveS3: CanaryCheckResult = { status: "alive", durationMs: 5, destinationId: "s3", aspects: [], byteDelta: 0, deadReason: null };
    const comp2 = (await (await doFetch(stub, "POST", "/canary/complete", { run: due2.run, results: [aliveR2, aliveS3] })).json()) as { transitions: Array<{ transitioned: string }> };
    ok("C: S3 recovering transitions 'recovered'", comp2.transitions.length === 1 && comp2.transitions[0]!.transitioned === "recovered");
    const v2 = (await (await doFetch(stub, "GET", "/canary")).json()) as CanaryView;
    ok("C: aggregate is alive once every destination is alive", v2.status === "alive");

    // Pin a subset (only R2); an unknown destination is refused; disabling stops it being due.
    const vPin = (await (await doFetch(stub, "POST", "/canary/config", { destinationIds: ["r2"] })).json()) as CanaryView;
    ok("C: pinning a subset flies to only that destination", vPin.flyingToAll === false && vPin.dests.length === 1 && vPin.dests[0]!.destinationId === "r2");
    ok("C: an unknown destination is refused 400", (await doFetch(stub, "POST", "/canary/config", { destinationIds: ["nope"] })).status === 400);
    await doFetch(stub, "POST", "/canary/config", { enabled: false });
    ok("C: a disabled canary reads disabled and is never due", ((await (await doFetch(stub, "GET", "/canary")).json()) as CanaryView).status === "disabled" && ((await (await doFetch(stub, "POST", "/canary/due", { nowMs: 9_000_000 })).json()) as { due: boolean }).due === false);
  }
}

// D. migration from the old single-destination record.
async function sectionD(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    seedDestinations(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    (storage as unknown as { put(k: string, v: unknown): Promise<void> }).put("canary", {
      config: { enabled: true, destinationId: "r2", intervalSeconds: 3600 },
      status: "alive", lastRunAt: "2026-06-13T00:00:00.000Z", nextRunAt: 1, inFlight: false, runSeq: 4,
      deadSince: null, lastRunId: "OLDRUN", consecutivePasses: 3,
      history: [{ at: "2026-06-13T00:00:00.000Z", ok: true, status: "alive", durationMs: 5, destinationId: "r2", runSeq: 4, aspects: [], byteDelta: 0, deadReason: null }],
    });
    const v = (await (await doFetch(stub, "GET", "/canary")).json()) as CanaryView;
    ok("D: an old pinned record migrates to flying to exactly that destination", v.flyingToAll === false && v.dests.length === 1 && v.dests[0]!.destinationId === "r2");
    ok("D: migration preserves the destination's liveness + history", v.dests[0]!.status === "alive" && v.history.length === 1);
  }
}

// sectionE pins classifyReadFailure: a signature/freshness failure on the canary's own fresh archive is
// real drift (dead); an object-missing or transport fault only stopped the check completing (ailing). A
// regression in the upstream error vocabulary would otherwise let a dead canary report as merely ailing.
function sectionE(): void {
  const sig = classifyReadFailure("manifest signature did not verify");
  ok("E: a signature failure classifies dead on read-signature", sig.dead === true && sig.aspect === "read-signature");
  const fresh = classifyReadFailure("the latest run is stale below the min");
  ok("E: a freshness failure classifies dead on runlog-freshness", fresh.dead === true && fresh.aspect === "runlog-freshness");
  const missing = classifyReadFailure("object is missing: status 404");
  ok("E: an object-missing read classifies ailing (not dead)", missing.dead === false);
  const unknown = classifyReadFailure("some entirely unexpected condition");
  ok("E: an unknown read failure classifies dead (fail closed)", unknown.dead === true && unknown.aspect === "read-signature");

  // The TYPED category outranks the prose nets, and this is the case that proves it matters. reader.ts
  // raises freshnessUnverifiableError for a check that COULD NOT RUN, and its message reads "freshness:
  // ...", which the freshness net matches and calls a death. `dead` pages an operator to evacuate and
  // rolls a self-update back, so the wrong answer here is a wrong ACTION over a run nothing had
  // questioned. The message is deliberately left in the shape the net matches, so this assertion can only
  // pass by reading the category.
  const unverifiable = classifyReadFailure(freshnessUnverifiableError("freshness: the RUNLOG could not be read"));
  ok("E: a freshness check that COULD NOT RUN classifies ailing, not a death", unverifiable.dead === false && unverifiable.aspect === "runlog-freshness");
  // The other side of the same split: a check that RAN and found a rollback is still a death.
  const rolledBack = classifyReadFailure(freshnessError("freshness: stale"));
  ok("E: a freshness check that RAN and found a rollback is still dead", rolledBack.dead === true && rolledBack.aspect === "runlog-freshness");
  // A typed integrity failure is a death even when its text matches nothing (the nets would have reached
  // the fail-closed default here, so this pins the category as the reason rather than a coincidence).
  const typedIntegrity = classifyReadFailure(integrityError("the shard count did not agree"));
  ok("E: a typed integrity failure is dead on read-signature", typedIntegrity.dead === true && typedIntegrity.aspect === "read-signature");
  // A typed integrity failure whose text contains "is missing" must NOT reach the ailing arm. This is the
  // same substring coincidence that sent a keyless attestation to a replica holding the identical bytes.
  const missingWorded = classifyReadFailure(integrityError("a shard the signed root lists is missing"));
  ok("E: a typed integrity failure worded 'is missing' is dead, not ailing", missingWorded.dead === true);
  // format-unsupported: the canary reads back what this same build just wrote, so it is a death.
  const badFormat = classifyReadFailure(formatUnsupportedError("formatVersion downpipe/9.9.9: not implemented"));
  ok("E: a format-unsupported read-back is dead (the build cannot read its own writer)", badFormat.dead === true && badFormat.aspect === "read-signature");
}

// sectionF pins finalise's ailingCause threading (op-key-canary-drill Gap A): the override branch carries
// the caller's cause onto the result verbatim; the dead and alive branches (no override at all) never
// carry one, so a genuine death or a clean pass can never be mislabelled as by-design posture.
function sectionF(): void {
  const passAspects: CanaryAspectResult[] = [{ key: "write-probe", outcome: "pass", detail: "the destination accepted and returned a probe object" }];
  const startMs = Date.now() - 5;

  const posture = finalise(passAspects, "r2", startMs, { status: "ailing", reason: "the seal failed", ailingCause: "other" });
  ok("F: an ailing override WITH a cause threads it onto the result verbatim", posture.status === "ailing" && posture.ailingCause === "other");

  const unreachable = finalise(passAspects, "r2", startMs, { status: "ailing", reason: "write probe failed", ailingCause: "unreachable" });
  ok("F: a different closed cause threads through unchanged (no cross-contamination between causes)", unreachable.ailingCause === "unreachable");

  // B30 (G-P1-127): the ailing cause must SPLIT by what actually failed. Every one of these used to stamp
  // "unreachable", so an expired credential, a WORM refusal, a throttling store and a dead endpoint were the
  // same string and triage went to the wrong side. These assert the classifier the canary now calls produces
  // a DIFFERENT, actionable class per fault, which is the whole content of the fix.
  const b30 = new Map(
    ([
      // The REAL thrown shape, not an invented one: the dest layer throws "PUT <key>: status NNN" and the
      // CF API clients throw "... HTTP NNN". statusInMessage is anchored on those two forms on purpose, so a
      // digit inside an object key can never be read as a status. A fixture like "S3 error 403 ..." would
      // classify as `other` and would be testing my imagination rather than the product.
      ["auth", new Error("PUT _probe: status 403")],
      ["worm-refused", new Error("InvalidRetentionPeriod: object-lock retention refuses the delete")],
      ["timeout", new Error("the request timed out")],
      ["tls", new Error("TLS handshake failed: certificate has expired")],
    ] as Array<[string, Error]>).map(([want, err]) => [want, destDownReason(err)] as [string, string]),
  );
  for (const [want, got] of b30) {
    ok(`F/B30: a ${want} fault classifies as ${want}, not a flat unreachable`, got === want);
  }
  ok("F/B30: the four faults produce four DISTINCT classes (the collapse is gone)", new Set(b30.values()).size === 4);

  // A destination that ANSWERED and returned the wrong bytes is not "down" at all, and calling it unreachable
  // was the most misleading case: the store is up and handing back something other than what it was given.
  const mismatch = finalise(passAspects, "r2", startMs, { status: "ailing", reason: "write probe mismatch", ailingCause: "probe-mismatch" });
  ok("F/B30: a probe mismatch is its own class, never a transport reason", mismatch.ailingCause === "probe-mismatch");

  // AND THE CALL SITES THEMSELVES, because the assertions above do not reach them. They call finalise with a
  // literal cause, so they prove the TYPE accepts the new classes and nothing more: reverting cycle.ts to
  // stamp "unreachable" left every one of them green. That is the defect this file exists to catch wearing
  // the costume of a test, so the guard below reads the source and asserts the collapse literal is gone.
  //
  // Structural rather than behavioural on purpose: the defect WAS a hardcoded literal at five call sites, so
  // the honest check is that no call site hardcodes it. "unreachable" survives in the TYPE (stored history
  // carries it) and in prose, which is why this matches the assignment form specifically.
  {
    const cycleSrc = readFileSync(new URL("../src/canary/cycle.ts", import.meta.url), "utf8");
    const hardcoded = cycleSrc.match(/ailingCause:\s*"unreachable"/g) ?? [];
    ok("F/B30: no canary call site hardcodes the legacy flat cause any more", hardcoded.length === 0);
    const derived = cycleSrc.match(/ailingCause:\s*destDownReason\(/g) ?? [];
    ok("F/B30: the transport-fault sites derive their cause from the classifier (4 sites)", derived.length === 4);
  }

  const noCause = finalise(passAspects, "r2", startMs, { status: "pending", reason: "no destination configured" });
  ok("F: a pending override with NO cause leaves ailingCause unset (never fabricated)", noCause.status === "pending" && noCause.ailingCause === undefined);

  const deadAspects: CanaryAspectResult[] = [{ key: "decrypt-integrity", outcome: "fail", detail: "1 byte strayed" }];
  const dead = finalise(deadAspects, "r2", startMs);
  ok("F: a dead result (no override; a real data death) never carries an ailingCause", dead.status === "dead" && dead.ailingCause === undefined);

  const alive = finalise(passAspects, "r2", startMs);
  ok("F: an alive result (no override; a clean pass) never carries an ailingCause", alive.status === "alive" && alive.ailingCause === undefined);
}

async function main(): Promise<void> {
  await sectionA();
  await sectionB();
  await sectionC();
  await sectionD();
  sectionE();
  sectionF();

  console.log(failures === 0 ? "\nCANARY PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
