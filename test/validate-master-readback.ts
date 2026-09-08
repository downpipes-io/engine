// Prove the mechanism BOTH halves of the operational-key reduction rest on: a run can be read back,
// decrypted and hash-checked using ONLY the per-run master the seal path already holds, with NO
// recipient private key present anywhere. That is what lets verify-at-seal (seal/verify-at-seal.ts)
// and the hourly canary (canary/cycle.ts) reach the keyed decrypt tier on a BREAK-GLASS-ONLY engine,
// which before this change was structurally impossible: both loaded OPERATIONAL_PRIVATE, and without
// it verify-at-seal returned Tier-0 and the canary finalised ailing "no-read-back-key" every flight.
//
// It also pins the two properties that make the change safe rather than merely convenient:
//
//  1. The CAPSULE path still works and recovers IDENTICAL plaintext, so the master fallback is a true
//     equivalent rather than a weaker check wearing the same verdict. (Which opener each production call
//     site chooses is asserted by the verify-at-seal and canary validators, not here.) That ordering is
//     load-bearing: openRunWithMaster is HANDED the master and never touches a wrap, so preferring it
//     would have silently deleted the only recurring proof that a run's recipient wrap actually opens,
//     and a corrupt wrap would then seal, verify at the full tier and attest clean while being
//     permanently unrecoverable.
//
//  2. A WRONG or ZEROISED master FAILS CLOSED. The master is zeroised by the seal path's own finally,
//     so an ordering slip anywhere in that chain would hand this code a buffer of zeros. The run key
//     commitment (format/reader.ts, checked inside openRunWith) must reject it rather than producing a
//     wrong-but-plausible read.
//
// Run: node test/validate-master-readback.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { concat, b64urlEncode } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { openRun, openRunWithMaster, type ObjectStore } from "../src/format/reader.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { type RunClock, type RunConfig, runBackup } from "../src/seal/pipeline.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"}   ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// The corpus is deliberately shaped like the canary's: a handful of small, known records, so a
// byte-for-byte comparison after read-back is the assertion rather than a hash equality alone.
const CORPUS: { name: string; value: Uint8Array }[] = [
  { name: "alpha", value: new TextEncoder().encode("the quick brown fox") },
  { name: "beta", value: new TextEncoder().encode("jumps over the lazy dog") },
  { name: "gamma", value: rand(4096) },
];

class CorpusSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  async *crawl(_selector: Selector): AsyncIterable<SourceRecord> {
    for (const r of CORPUS) yield { sourceType: "kv", name: r.name, value: r.value, namespace: "corpus" };
  }
  async estimate(_selector: Selector): Promise<{ records: number; bytes: number }> {
    return { records: CORPUS.length, bytes: CORPUS.reduce((a, r) => a + r.value.length, 0) };
  }
}

class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    await this.put(key, concat(...parts));
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.tags.get(key);
    if (opts.ifNoneMatch === "*" && cur !== undefined) return { ok: false };
    if (opts.ifMatch !== undefined && cur !== opts.ifMatch) return { ok: false };
    await this.put(key, body);
    return { ok: true, etag: this.tags.get(key) as string };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
    this.tags.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

class MapStore implements ObjectStore {
  // Not a parameter property: `node --experimental-strip-types` (how the validate suite runs every
  // validator) rejects those outright, and this file is wired into `npm run validate`.
  private map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object is missing: ${key}`);
    return v;
  }
}

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

async function sealCorpus(dest: MemDest, signer: Signer, recipients: RecipientEntry[], master: Uint8Array): Promise<void> {
  const cfg: RunConfig = {
    downpipeId: "dp-master-readback",
    downpipeName: "master read-back",
    cadence: "3600s",
    selector: { include: [], exclude: [] },
    recipients,
  };
  const clock: RunClock = {
    runId: RUN_ID,
    runlogIndex: 1,
    prevRunId: null,
    now: "2026-07-26T00:00:00.000Z",
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
    master,
  };
  await runBackup([new CorpusSource()], cfg, signer, dest, clock);
}

// restoreAll opens a run through the supplied opener and returns every record's plaintext, so the two
// open paths can be compared byte-for-byte rather than by verdict.
async function restoreAll(open: () => Promise<{ records: unknown[]; restoreRecord: (r: never) => Promise<Uint8Array> }>): Promise<Uint8Array[]> {
  const run = await open();
  const out: Uint8Array[] = [];
  for (const rec of run.records) out.push(await run.restoreRecord(rec as never));
  return out;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// matchesCorpus compares a restored set to the known corpus by exact bytes, order-independently (record
// names are stored only as keyed MACs, exactly as the canary's own comparison does).
function matchesCorpus(restored: Uint8Array[]): boolean {
  if (restored.length !== CORPUS.length) return false;
  const remaining = CORPUS.map((r) => r.value);
  for (const got of restored) {
    const i = remaining.findIndex((want) => sameBytes(want, got));
    if (i < 0) return false;
    remaining.splice(i, 1);
  }
  return remaining.length === 0;
}

async function main(): Promise<void> {
  const signer: Signer = await loadSigner(b64urlEncode(concat(rand(32), rand(32))));
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");

  console.log("A break-glass-only run reads back from its OWN per-run master (no recipient private anywhere):");
  {
    // The recipient set is break-glass ONLY: exactly the strict posture, where the engine holds no
    // private that can open this archive at rest. The only key in scope is the master the seal just used.
    const dest = new MemDest();
    const master = rand(32);
    await sealCorpus(dest, signer, [breakGlass.entry], master);
    const store = new MapStore(dest.map);

    const restored = await restoreAll(() => openRunWithMaster(store, RUN_ID, master, verifier, { verifyFreshness: true, allowStale: true }) as never);
    ok("every record decrypts and its plaintext hash re-checks", restored.length === CORPUS.length);
    ok("every restored record is byte-identical to the corpus", matchesCorpus(restored));
  }

  console.log("The CAPSULE path is preserved and recovers identical plaintext (the fallback is a true equivalent):");
  {
    // Both recipients present, which is the default posture. Production prefers openRun here precisely so
    // the recipient-wrap decapsulation stays exercised on every run; this asserts the master path is not
    // quietly different, so a break-glass-only estate is not getting a weaker check under the same verdict.
    const dest = new MemDest();
    const master = rand(32);
    await sealCorpus(dest, signer, [breakGlass.entry, operational.entry], master);
    const store = new MapStore(dest.map);

    const viaCapsule = await restoreAll(() => openRun(store, RUN_ID, parseIdentity(operational.identity), verifier, { verifyFreshness: true, allowStale: true }) as never);
    const viaMaster = await restoreAll(() => openRunWithMaster(store, RUN_ID, master, verifier, { verifyFreshness: true, allowStale: true }) as never);

    ok("the operational recipient wrap opens the run", matchesCorpus(viaCapsule));
    ok("the master opens the same run", matchesCorpus(viaMaster));
    ok("both paths recover byte-identical plaintext, record for record", viaCapsule.length === viaMaster.length && viaCapsule.every((b, i) => sameBytes(b, viaMaster[i] as Uint8Array)));

    // The break-glass wrap is the one no automated path in EITHER posture exercises, because the engine
    // has never held that private and cannot. Proving it here, offline, is the honest counterpart to the
    // product claim: only attended verification proves it against a real archive in production.
    const viaBreakGlass = await restoreAll(() => openRun(store, RUN_ID, parseIdentity(breakGlass.identity), verifier, { verifyFreshness: true, allowStale: true }) as never);
    ok("the break-glass wrap opens the same run (offline proof; no in-account path exercises this)", matchesCorpus(viaBreakGlass));
  }

  console.log("A WRONG or ZEROISED master FAILS CLOSED (the run key commitment, not a wrong-but-plausible read):");
  {
    const dest = new MemDest();
    const master = rand(32);
    await sealCorpus(dest, signer, [breakGlass.entry], master);
    const store = new MapStore(dest.map);

    // A zeroised master is the exact failure an ordering slip in the seal path would produce: the caller's
    // finally runs before the verification instead of after. It must be refused, not silently mis-verified.
    // refusedBy returns WHICH check rejected the master. Asserting merely "it threw" would stay green if
    // the key commitment were deleted from openRunWith, because a wrong master also fails later on an AEAD
    // tag once the derived keys are wrong. Pinning the commitment message is what makes these real controls.
    const refusedBy = async (m: Uint8Array): Promise<string> => {
      try {
        await openRunWithMaster(store, RUN_ID, m, verifier, { verifyFreshness: true, allowStale: true });
        return "NOT REFUSED";
      } catch (e) {
        return (e as Error).message;
      }
    };
    const commitment = /key commitment does not match the run master/;

    const zeroMsg = await refusedBy(new Uint8Array(32));
    ok("an all-zero master is refused BY THE KEY COMMITMENT", commitment.test(zeroMsg));

    const wrongMsg = await refusedBy(rand(32));
    ok("an unrelated random master is refused BY THE KEY COMMITMENT", commitment.test(wrongMsg));

    // A single flipped bit is the tightest case: the commitment is a MAC over the master, so near-misses
    // must fail exactly as hard as a wholly wrong key.
    const nearMiss = new Uint8Array(master);
    nearMiss[0] = (nearMiss[0] as number) ^ 0x01;
    ok("a master differing by ONE BIT is refused BY THE KEY COMMITMENT", commitment.test(await refusedBy(nearMiss)));
  }

  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`MASTER-READBACK FAIL (${failures} assertion(s) failed)`);
    process.exit(1);
  }
  console.log("MASTER-READBACK PASS (break-glass-only reads back from its own run master; the capsule path is preserved and equivalent; a wrong master fails closed)");
}

await main();
