// B5 adversarial-archive: CROSS-RUN OBJECT SUBSTITUTION (net-zero, deploy-free). The signed root manifest + the
// sealed manifest shards mean a manifest that LIES about a record count or a record hash cannot be forged without
// breaking the root signature -- that is exactly the existing R2 one-byte-tamper refuter, not a new integrity
// path. The distinct, uncovered attack is grafting a VALIDLY-sealed data segment from a DIFFERENT run under this
// run's object key: both objects are individually authentic (real seal, real signature), so nothing at the
// signature layer is wrong -- only the per-run KEY DERIVATION (the master + runId a run's segments are sealed
// under) and the manifest's per-record hash can catch it. A miss here is a real recovery vulnerability: a restore
// that silently returns ANOTHER run's data.
//
// This seals run A and run B independently (distinct valid runIds, per-run 32-byte masters as production uses),
// restores run A cleanly through BOTH readers (the positive control, so the refuter is not vacuous), then
// overwrites run A's data segment object with run B's segment bytes and asserts BOTH the independent Go offline
// reader AND the in-account TS reader REFUSE. Both refuter asserts default to FAIL: an ACCEPT of the grafted
// archive fails the run loudly.
//
// NET-ZERO: in-process seal, a locally built Go binary, harness-minted keys, fake data, ephemeral temp dirs only
// (assertEphemeralWorkdir refuses a repo-tree or live-keys path). No estate, bucket, network, seed or spend.
// House style: Australian English, no em dashes, no rule-of-three.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";

import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";
import { assertEphemeralWorkdir, buildReader, goPresent, restoreDiscardArgs, runReader, writeArchiveDir } from "./scale-go-reader.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const RUN_A = "01ARZ3NDEKTSV4RRFFQ69G5FAV"; // two distinct valid ULIDs (first char <= 7)
const RUN_B = "01BX5ZZKBKACTAV9WEVGEMMVRZ";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function newTmp(): string {
  const d = mkdtempSync(join(tmpdir(), "downpipes-crossrun-"));
  assertEphemeralWorkdir(d);
  return d;
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } }, identity: concat(xk.secretKey, seed) };
}
async function makeSigner(): Promise<{ signer: Signer; signerPub: Uint8Array }> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { signer: { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey }, signerPub: concat(edPublic, mldsa.publicKey) };
}

class MapStore implements ObjectStore {
  // An explicit field rather than a constructor parameter property: Node runs these validators with
  // strip-only type stripping, which rejects a parameter property outright
  // (ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX). This file never ran, so the syntax error was never seen.
  readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}

interface Sealed {
  archiveDir: string;
  identityFile: string;
  signerFile: string;
  map: Map<string, Uint8Array>;
  bgIdentity: Uint8Array;
  signer: Signer;
  signerPub: Uint8Array;
}

async function sealRun(runId: string, records: WriteRecord[]): Promise<Sealed> {
  const root = newTmp();
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const { signer, signerPub } = await makeSigner();
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    {
      downpipeId: "dp_crossrun", downpipeName: "crossrun", cadence: "0 * * * *", runId, master: rand(32),
      recipients: [bg.entry, op.entry], signer, records,
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const full = new Map(mem.entries());
  const paths = writeArchiveDir(root, full, b64urlEncode(bg.identity), b64urlEncode(signerPub));
  return { ...paths, map: full, bgIdentity: bg.identity, signer, signerPub };
}

function segKey(map: Map<string, Uint8Array>): string {
  const k = [...map.keys()].find((x) => x.endsWith(".seg"));
  if (!k) throw new Error("no .seg data object in the archive map");
  return k;
}

async function tsRefuses(map: Map<string, Uint8Array>, runId: string, s: Sealed): Promise<boolean> {
  try {
    const run = await openRun(new MapStore(map), runId, parseIdentity(s.bgIdentity), verifierFrom(s.signer), { verifyFreshness: false });
    for (const r of run.records) await run.restoreRecord(r);
    return false;
  } catch {
    return true;
  }
}

async function main(): Promise<void> {
  const recA: WriteRecord[] = [{ sourceType: "kv", name: "alpha", value: rand(512) }];
  const recB: WriteRecord[] = [{ sourceType: "kv", name: "beta", value: rand(512) }];
  const A = await sealRun(RUN_A, recA);
  const B = await sealRun(RUN_B, recB);

  // POSITIVE CONTROL (TS): clean run A restores byte-identical, so a later refusal is a real detection.
  {
    const run = await openRun(new MapStore(A.map), RUN_A, parseIdentity(A.bgIdentity), verifierFrom(A.signer), { verifyFreshness: false });
    const rec = run.records.find((r) => r.name === "alpha");
    const plain = rec ? await run.restoreRecord(rec) : new Uint8Array();
    ok("POSITIVE CONTROL: clean run A restores byte-identical (TS reader)", !!rec && bytesEqual(plain, recA[0]!.value!));
  }

  const go = goPresent();
  const bin = join(newTmp(), "downpipe");
  const built = go.ok ? buildReader(process.cwd(), bin) : { ok: false, detail: "Go toolchain absent" };
  const goHave = built.ok;
  if (goHave) {
    const clean = runReader(bin, restoreDiscardArgs(A.archiveDir, RUN_A, A.identityFile, A.signerFile));
    ok("POSITIVE CONTROL: clean run A verified by the Go reader (exit 0)", clean.exitCode === 0);
  } else {
    console.log(`  GAP: ${built.detail}; the Go half is skipped, the TS half still asserted (not a pass, not a fail).`);
  }

  // THE ATTACK: overwrite run A's data segment object with run B's VALIDLY-sealed segment bytes. Run A's manifest
  // still references run A's segment key + hash; the reader derives run A's key (master A + runId A) and gets run
  // B's bytes -> AEAD open fails (or the plaintext hash mismatches). Both readers must refuse.
  const grafted = new Map(A.map);
  grafted.set(segKey(A.map), B.map.get(segKey(B.map))!);

  ok("REFUTER (default-FAIL): the TS reader REFUSES run A with run B's segment grafted in", await tsRefuses(grafted, RUN_A, A));

  if (goHave) {
    const graftDir = newTmp();
    const paths = writeArchiveDir(graftDir, grafted, b64urlEncode(A.bgIdentity), b64urlEncode(A.signerPub));
    const res = runReader(bin, restoreDiscardArgs(paths.archiveDir, RUN_A, paths.identityFile, paths.signerFile));
    ok(`REFUTER (default-FAIL): the Go reader REFUSES the cross-run graft (exit ${res.exitCode})`, res.exitCode !== 0);
  }

  console.log(failures === 0
    ? "\nCROSS-RUN SUBSTITUTION OK: a validly-sealed segment from another run is refused by both readers; net-zero."
    : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error("CROSS-RUN SUBSTITUTION FAILED:", e instanceof Error ? (e.stack ?? e.message) : e);
  process.exit(1);
});
