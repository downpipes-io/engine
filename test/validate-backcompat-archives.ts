// The engine reads every released archive-format generation (a cross-repository compatibility rule,
// rules 3, 21 and 22).
//
// WHAT IT READS. The sibling Go reader repo keeps one sealed fixture archive per archive-format generation a
// released engine has written, under downpipe/internal/format/testdata/released/<generation>/. Each holds the
// destination objects (archive/), the throwaway break-glass identity and signer public key in the reader's
// labelled key-file format, and expected.json: every record's source type, name, size and plaintext SHA-384,
// recorded by the sealing engine from the source data before it sealed anything. The Go reader's own gate
// (cmd/downpipe/released_generations_test.go) reads the same directories.
//
// WHAT IS GRADED, for every generation directory and every run in it, through the engine's own read path:
//   1. openRun (src/format/reader.ts), the chokepoint the restore routes reach through openVerifiedRun: the
//      hybrid root signature, the recovery bundle, every shard hash, the Merkle root, the master capsule and
//      the RUNLOG freshness check, with the min-index pin set to the highest index the fixture holds.
//   2. The chain: an older run opens only with allowStale, and without it the freshness check refuses.
//   3. restoreRecord for every record, hashed and compared with expected.json by source type and name, with
//      the record count and the incompleteness markers compared too.
//   4. attestKeyless (src/format/keyless.ts), the keyless restorability attestation the drill runs: signed and
//      complete for every run, and not rolled back for the latest run only.
//   5. TOLERANCE of _RECOVERY/RUNLOG.sig.pending, the object a newer engine writes before each RUNLOG body:
//      with a junk copy of it beside the RUNLOG, openRun and attestKeyless still pass the latest run, and the
//      engine's signature resume (resolveRunlogSignature) finds the archive's own .sig verified and leaves it.
//   6. NEGATIVE CONTROLS, in memory, never on the committed files: one byte flipped in the middle of the
//      largest data segment must fail restoreRecord for the one record that owns it, and one byte flipped in
//      the latest run's root signature must make openRun refuse and attestKeyless report the signature bad.
// A new generation directory is picked up with no change here.
//
// SIBLING POSTURE, the same as validate-slice.ts. The sibling is found through DOWNPIPES_DOWNPIPE_ROOT,
// DOWNPIPES_DOWNPIPE, DOWNPIPE_WORKTREE or DOWNPIPE_REPO, then beside this checkout. When no sibling is found,
// or the sibling holds no released generation, this reports CANNOT-CHECK and never a pass: with
// REQUIRE_DOWNPIPE=1 it refuses at exit 2, and without it the skip is declared (VERDICT SKIPPED), so an
// engine-only checkout can still deploy. A sibling behind its own origin/main is refused through the shared
// sibling-freshness helper, with its escape hatch.
//
// Run: node test/validate-backcompat-archives.ts
//

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { b64urlDecode, hexEncode } from "../src/crypto/bytes.ts";
import { parseIdentity, parseVerifier } from "../src/crypto/keys.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import type { ShardRecord } from "../src/format/manifest.ts";
import { type ObjectStore, openRun } from "../src/format/reader.ts";
import { RUNLOG_SIG_PENDING_KEY, resolveRunlogSignature } from "../src/seal/pipeline.ts";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const REQUIRE_DOWNPIPE = process.env.REQUIRE_DOWNPIPE === "1";
const RELEASED = "internal/format/testdata/released";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// cannotCheck ends the run without a verdict on the archives: never a pass.
function cannotCheck(why: string): never {
  console.log(`\nCANNOT-CHECK backcompat-archives: ${why}`);
  if (REQUIRE_DOWNPIPE) {
    verdictSkipped(`REFUSED, exit 2: ${why} REQUIRE_DOWNPIPE=1 was set, so this is CANNOT-CHECK rather than a skip.`);
    process.exit(2);
  }
  verdictSkipped(`CANNOT-CHECK, not a pass: ${why}`);
  process.exit(0);
}

function findDownpipe(): string | null {
  const candidates = [
    process.env.DOWNPIPES_DOWNPIPE_ROOT,
    process.env.DOWNPIPES_DOWNPIPE,
    process.env.DOWNPIPE_WORKTREE,
    process.env.DOWNPIPE_REPO,
    resolve(HERE, "../downpipe"),
    resolve(HERE, "../../downpipe"),
    resolve(HERE, "../../../downpipe"),
  ].filter((c): c is string => typeof c === "string" && c !== "");
  return candidates.find((c) => existsSync(resolve(c, "cmd/downpipe/main.go"))) ?? null;
}

interface ExpectedRecord {
  sourceType: string;
  name: string;
  size: number;
  plaintextSha384: string;
  incompleteMarker?: string;
}
interface Expected {
  generation: string;
  formatVersion: string;
  engineVersion: string;
  runs: { runId: string; runlogIndex: number; latest: boolean; records: ExpectedRecord[] }[];
}

// readKeyFile reads one labelled key file (`<label> <base64url>`), the format the Go reader writes and reads.
function readKeyFile(path: string, label: string): Uint8Array {
  const parts = readFileSync(path, "utf8").trim().split(/\s+/);
  if (parts.length !== 2 || parts[0] !== label) throw new Error(`${path} is not a ${label} key file`);
  return b64urlDecode(parts[1]!);
}

// dirStore serves the fixture's archive/ tree as the ObjectStore the reader reads, with an optional in-memory
// overlay the negative controls damage instead of the committed files.
function dirStore(archive: string, overlay: Map<string, Uint8Array> = new Map()): ObjectStore {
  return {
    async get(key: string): Promise<Uint8Array> {
      const hit = overlay.get(key);
      if (hit) return hit;
      const p = join(archive, key);
      if (!existsSync(p)) throw new Error(`object ${key} is missing`);
      return new Uint8Array(readFileSync(p));
    },
  };
}

function flipped(bytes: Uint8Array, offset: number): Uint8Array {
  const out = new Uint8Array(bytes);
  out[offset] = out[offset]! ^ 0x01;
  return out;
}

async function refuses(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

async function gradeGeneration(dir: string, gen: string): Promise<void> {
  console.log(`\n-- ${gen} --`);
  const exp = JSON.parse(readFileSync(join(dir, "expected.json"), "utf8")) as Expected;
  ok(`${gen}: expected.json names this generation`, exp.generation === gen);
  ok(`${gen}: expected.json lists at least one run`, Array.isArray(exp.runs) && exp.runs.length > 0);
  const identity = parseIdentity(readKeyFile(join(dir, "identity.key"), "downpipe-identity-v1"));
  const verifier = parseVerifier(readKeyFile(join(dir, "signer.pub"), "downpipe-signer-public-v1"));
  const archive = join(dir, "archive");
  const store = dirStore(archive);
  const maxIndex = Math.max(...exp.runs.map((r) => r.runlogIndex));
  // Which record, in which run, owns each segment object, for the segment negative control below.
  const owner = new Map<string, { runId: string; rec: ShardRecord }>();

  for (const r of exp.runs) {
    const label = `${gen} run ${r.runId}`;
    if (!r.latest) {
      ok(`${label}: an older run is refused without allowStale (the RUNLOG names a later run)`, await refuses(() => openRun(store, r.runId, identity, verifier, { verifyFreshness: true, checkRecoveryBundle: true, minRunlogIndex: maxIndex })));
    }
    let run: Awaited<ReturnType<typeof openRun>>;
    try {
      run = await openRun(store, r.runId, identity, verifier, { verifyFreshness: true, checkRecoveryBundle: true, minRunlogIndex: maxIndex, allowStale: !r.latest });
    } catch (e) {
      ok(`${label}: openRun verifies the signed root, the bundle, every shard and the freshness chain (${(e as Error).message})`, false);
      continue;
    }
    try {
      ok(`${label}: openRun verifies the signed root, the bundle, every shard and the freshness chain`, true);
      ok(`${label}: the freshness check ran and ${r.latest ? "names this run the latest" : "names a later run"} (index ${run.freshness?.runlogIndex}, max ${run.freshness?.maxIndexForDownpipe})`, run.freshness !== null && run.freshness.checked === true && run.freshness.isLatestForDownpipe === r.latest && run.freshness.maxIndexForDownpipe === maxIndex);
      ok(`${label}: the run holds ${r.records.length} records, the number the engine sealed`, run.records.length === r.records.length);
      const byKey = new Map(r.records.map((x) => [`${x.sourceType}\u0000${x.name}`, x]));
      let matched = 0;
      const wrong: string[] = [];
      for (const rec of run.records) {
        for (const seg of rec.segments) owner.set(seg.object, { runId: r.runId, rec });
        const want = byKey.get(`${rec.sourceType}\u0000${rec.name}`);
        if (!want) {
          wrong.push(`${rec.sourceType} ${rec.name} (not in expected.json)`);
          continue;
        }
        let value: Uint8Array;
        try {
          value = await run.restoreRecord(rec);
        } catch (e) {
          wrong.push(`${rec.sourceType} ${rec.name} (restoreRecord threw: ${(e as Error).message})`);
          continue;
        }
        const got = hexEncode(await sha384(value));
        if (got !== want.plaintextSha384 || value.length !== want.size || (rec.incompleteMarker ?? "") !== (want.incompleteMarker ?? "")) {
          wrong.push(`${rec.sourceType} ${rec.name}`);
          continue;
        }
        matched++;
      }
      ok(`${label}: restoreRecord returns every record with the size, plaintext SHA-384 and marker the engine recorded (${matched}/${r.records.length})${wrong.length ? `; wrong: ${wrong.join(", ")}` : ""}`, matched === r.records.length && wrong.length === 0);
    } finally {
      run.dispose();
    }
    const att = await attestKeyless(store, r.runId, verifier, { allowStale: !r.latest, minRunlogIndex: maxIndex });
    // notRolledBack holds only for the latest run of a downpipe: an older run attests signed and complete,
    // and reports the later run it is behind.
    ok(`${label}: the keyless attestation reports the signature valid and the run complete, and ${r.latest ? "not rolled back" : "behind a later run"}${att.reason ? ` (${att.reason})` : ""}`, att.signatureValid && att.complete && att.notRolledBack === r.latest);
  }

  // TOLERANCE: a junk pending signature beside the RUNLOG changes nothing a reader or the resume decides.
  const latestRun = exp.runs.find((x) => x.latest) ?? exp.runs[exp.runs.length - 1]!;
  const junk = new TextEncoder().encode("not-a-signature");
  const pendingOverlay = new Map([[RUNLOG_SIG_PENDING_KEY, junk]]);
  ok(`${gen}: openRun reads past a junk ${RUNLOG_SIG_PENDING_KEY} and opens the latest run`, !(await refuses(async () => (await openRun(dirStore(archive, pendingOverlay), latestRun.runId, identity, verifier, { verifyFreshness: true, checkRecoveryBundle: true, minRunlogIndex: maxIndex })).dispose())));
  const pendAtt = await attestKeyless(dirStore(archive, pendingOverlay), latestRun.runId, verifier, { minRunlogIndex: maxIndex });
  ok(`${gen}: the keyless attestation is unchanged with the pending object present`, pendAtt.signatureValid && pendAtt.complete && pendAtt.notRolledBack);
  const memDest = new MemoryDestination();
  const runlogBytes = new Uint8Array(readFileSync(join(archive, "_RECOVERY/RUNLOG")));
  const runlogSigBytes = new Uint8Array(readFileSync(join(archive, "_RECOVERY/RUNLOG.sig")));
  await memDest.put("_RECOVERY/RUNLOG", runlogBytes);
  await memDest.put("_RECOVERY/RUNLOG.sig", runlogSigBytes);
  await memDest.put(RUNLOG_SIG_PENDING_KEY, junk);
  const state = await resolveRunlogSignature(memDest, runlogBytes, verifier);
  const sigAfter = await memDest.get("_RECOVERY/RUNLOG.sig");
  ok(`${gen}: the signature resume finds the released RUNLOG verified (${state}) and leaves its .sig as it was`, state === "verified" && sigAfter !== null && Buffer.compare(Buffer.from(sigAfter.body), Buffer.from(runlogSigBytes)) === 0);

  // NEGATIVE CONTROL 1: one byte flipped in the middle of the largest data segment, in memory.
  const segs = [...owner.keys()].map((k) => ({ k, size: statSync(join(archive, k)).size })).sort((a, b) => b.size - a.size);
  const victim = segs[0];
  ok(`${gen}: the negative control found a data segment to damage`, victim !== undefined);
  if (victim) {
    const own = owner.get(victim.k)!;
    const overlay = new Map([[victim.k, flipped(new Uint8Array(readFileSync(join(archive, victim.k))), Math.floor(victim.size / 2))]]);
    const ownRun = exp.runs.find((x) => x.runId === own.runId)!;
    const damaged = await openRun(dirStore(archive, overlay), own.runId, identity, verifier, { verifyFreshness: true, minRunlogIndex: maxIndex, allowStale: !ownRun.latest });
    try {
      ok(`${gen}: one flipped byte in ${victim.k.slice(0, 16)}... fails restoreRecord for ${own.rec.sourceType} ${own.rec.name}`, await refuses(() => damaged.restoreRecord(own.rec)));
    } finally {
      damaged.dispose();
    }
  }

  // NEGATIVE CONTROL 2: one byte flipped in the latest run's root signature, in memory.
  const latest = exp.runs.find((x) => x.latest) ?? exp.runs[exp.runs.length - 1]!;
  const sigKey = `run/${latest.runId}/root.manifest.json.sig`;
  const sigOverlay = new Map([[sigKey, flipped(new Uint8Array(readFileSync(join(archive, sigKey))), 0)]]);
  ok(`${gen}: one flipped byte in the latest root signature makes openRun refuse`, await refuses(() => openRun(dirStore(archive, sigOverlay), latest.runId, identity, verifier, { verifyFreshness: true, minRunlogIndex: maxIndex })));
  const badAtt = await attestKeyless(dirStore(archive, sigOverlay), latest.runId, verifier, { minRunlogIndex: maxIndex });
  ok(`${gen}: the keyless attestation reports that signature as not valid`, badAtt.signatureValid === false);
}

async function main(): Promise<void> {
  const downpipe = findDownpipe();
  if (downpipe === null) {
    cannotCheck("no downpipe checkout was found (set DOWNPIPES_DOWNPIPE_ROOT, or clone downpipe beside this engine), so no released-generation fixture was read.");
  }
  reportSiblings([{ name: "downpipe", path: downpipe }], { gate: "backcompat-archives" });
  requireFreshSiblings([{ name: "downpipe", path: downpipe }], {
    gate: "backcompat-archives",
    consequence: "it would grade this engine against an older fixture set than the one that ships",
    exit: (code: number) => {
      verdictSkipped(`REFUSED, exit ${code}: the downpipe checkout is behind its own origin/main, so nothing was concluded`);
      process.exit(code);
    },
  });
  const root = resolve(downpipe, RELEASED);
  const gens = existsSync(root) ? readdirSync(root, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort() : [];
  if (gens.length === 0) {
    cannotCheck(`the downpipe checkout at ${downpipe} holds no released generation under ${RELEASED}, so there is nothing to read.`);
  }
  console.log(`\nbackcompat-archives: ${gens.length} released generation(s) in ${root}: ${gens.join(", ")}`);
  for (const gen of gens) await gradeGeneration(join(root, gen), gen);

  console.log(failures === 0 ? `\nPASS backcompat-archives: ${checks} checks over ${gens.length} generation(s)` : `\nFAIL backcompat-archives: ${failures} of ${checks} checks failed`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
