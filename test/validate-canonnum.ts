// Canonical-numeric gate (SPEC 11.3) parity with the Go reference, covering three related
// anti-rollback / byte-compat defects:
//
//   ENG-M6 / DP-L5: validateCanonicalCounts must resolve a dotted field by walking the
//   parsed JSON structurally (like Go resolvePath), not by scanning the source text for the
//   leaf name. A leaf-name collision (a sibling or ancestor object with the same leaf key)
//   must resolve the CORRECT field in both directions: a benign decoy must not cause a
//   false-reject, and a benign decoy must not MASK an out-of-range real value.
//
//   ENG-M3: the freshness parseRunlog must apply the canonical-numeric gate to each RUNLOG
//   line's index/recordCount, mirroring Go ParseRunlog (validateCounts per line). A signed
//   RUNLOG carrying an out-of-range or non-canonical index (e.g. 1e400 -> Infinity) must be
//   rejected, so it cannot defeat the anti-rollback min-pin.
//
//   XC-M3: the shard read path must apply the gate to the preamble's recordCountInShard and
//   each record's plaintextSize, mirroring Go shard.go. parseShard (reader.ts) is not
//   exported, so the shard field gate is proven here against validateCanonicalCounts using
//   the exact field names the reader call sites pass; the reader wiring is exercised by the
//   existing reader/pipeline round-trip tests.
//
// Run: node test/validate-canonnum.ts

import { validateCanonicalCounts } from "../src/format/canonnum.ts";
import { parseRunlog, type RunlogEntry } from "../src/format/writer.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { checkRunlogFreshness } from "../src/format/freshness.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import type { RootManifest } from "../src/format/manifest.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// rejects asserts that fn throws (a canonical-numeric violation is reported, not swallowed).
function rejects(label: string, fn: () => void): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  ok(label, threw);
}

// accepts asserts that fn does NOT throw (a canonical value passes the gate).
function accepts(label: string, fn: () => void): void {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  ok(label, !threw);
}

// rejectsWith asserts that fn throws AND the thrown message carries a substring. The gate stacks
// several guards (string, non-number, non-integer, negative, over-ceiling); pinning the message
// proves the SPECIFIC guard fired, so a guard whose throw is removed (and a later guard catches
// the same input with a different message) or whose message is blanked is a detectable change.
function rejectsWith(label: string, fn: () => void, sub: string): void {
  let msg = "(no throw)";
  try {
    fn();
  } catch (e) {
    msg = e instanceof Error ? e.message : String(e);
  }
  const pass = msg !== "(no throw)" && msg.includes(sub);
  ok(`${label} (message contains ${JSON.stringify(sub)})`, pass);
  if (!pass) console.log(`        got ${JSON.stringify(msg)}`);
}

// ---------------------------------------------------------------------------------------
// Canonical-number checks on a single top-level field (parity with Go checkCanonicalCount).
// ---------------------------------------------------------------------------------------
accepts("canonical integer accepted", () => validateCanonicalCounts('{"n":318}', "n"));
accepts("zero accepted", () => validateCanonicalCounts('{"n":0}', "n"));
accepts("max canonical (2^53-1) accepted", () => validateCanonicalCounts(`{"n":${2 ** 53 - 1}}`, "n"));
accepts("missing field permitted", () => validateCanonicalCounts('{"other":1}', "n"));
accepts("null field permitted", () => validateCanonicalCounts('{"n":null}', "n"));

rejects("in-range value as string rejected", () => validateCanonicalCounts('{"n":"318"}', "n"));
rejects("over-ceiling (2^53) number rejected", () => validateCanonicalCounts('{"n":9007199254740993}', "n"));
rejects("over-ceiling as string rejected", () => validateCanonicalCounts('{"n":"9007199254740993"}', "n"));
rejects("fractional number rejected", () => validateCanonicalCounts('{"n":1.5}', "n"));
rejects("exponent form (1e400 -> Infinity) rejected", () => validateCanonicalCounts('{"n":1e400}', "n"));
rejects("negative number rejected", () => validateCanonicalCounts('{"n":-3}', "n"));
rejects("negative zero rejected", () => validateCanonicalCounts('{"n":-0}', "n"));
rejects("boolean rejected", () => validateCanonicalCounts('{"n":true}', "n"));

// Each rejection carries the reason for the guard that fired (parity with Go's distinct
// checkCanonicalCount messages). Pinning the message catches a guard whose throw is removed (so a
// later, broader guard catches the same input under a different reason) or whose message is
// blanked. Each input isolates one guard: a string is caught by the string guard before the
// number guards; a boolean by the non-number guard before the integer guard; a fractional by the
// integer guard before the range guard; a negative by the non-negative guard; an unparseable
// document by the parse guard.
rejectsWith("string form reason", () => validateCanonicalCounts('{"n":"5"}', "n"), "string form is reserved");
rejectsWith("non-number (boolean) reason", () => validateCanonicalCounts('{"n":true}', "n"), "not boolean");
rejectsWith("non-integer reason", () => validateCanonicalCounts('{"n":1.5}', "n"), "is not an integer");
rejectsWith("non-negative reason", () => validateCanonicalCounts('{"n":-3}', "n"), "non-negative integer");
rejectsWith("over-ceiling reason", () => validateCanonicalCounts('{"n":9007199254740993}', "n"), "out of canonical range");
rejectsWith("unparseable JSON reason", () => validateCanonicalCounts("not json", "n"), "could not parse");

// ---------------------------------------------------------------------------------------
// resolvePath walks the parsed structure (Go resolvePath); these pin the per-segment guard
// (cur === null || typeof cur !== "object" || Array.isArray(cur)) that stops the walk at a
// non-object instead of indexing into it. A path that walks THROUGH a JSON null, and one that
// walks through a missing nested object, must each be PERMITTED (the field is simply absent), not
// throw: indexing null or undefined would throw, so the guard removal is caught. A path that
// would step into a STRING value must also stop (the field is absent), not read a JavaScript
// property off the primitive: requesting ".constructor" under a string leaf stays permitted,
// because the structural walk never descends into a non-object scalar.
// ---------------------------------------------------------------------------------------
accepts("walk through a JSON null is permitted, not a throw", () => validateCanonicalCounts('{"a":null}', "a.b"));
accepts("walk through a missing nested object is permitted, not a throw", () => validateCanonicalCounts('{"a":{}}', "a.b.c"));
accepts("walk does not descend into a string value (a.constructor under a string leaf stays permitted)", () => validateCanonicalCounts('{"a":"hello"}', "a.constructor"));

// ---------------------------------------------------------------------------------------
// ENG-M6 / DP-L5: leaf-name collision resolves the correct field structurally.
// The pre-fix substring scan matched the FIRST textual occurrence of the leaf key anywhere
// in the document, so a sibling/ancestor decoy with the same leaf name was inspected
// instead of the intended dotted path.
// ---------------------------------------------------------------------------------------

// False-reject direction: a benign string decoy on a sibling path must NOT make the real
// (in-range number) target be rejected. The text scan would hit x.runlogIndex first.
accepts(
  "collision: decoy x.runlogIndex string does not false-reject freshness.runlogIndex",
  () => validateCanonicalCounts('{"x":{"runlogIndex":"99"},"freshness":{"runlogIndex":3}}', "freshness.runlogIndex"),
);
accepts(
  "collision: nested meta.shardCount string does not false-reject top-level shardCount",
  () => validateCanonicalCounts('{"meta":{"shardCount":"text"},"shardCount":2}', "shardCount"),
);

// Masking direction: a benign decoy must NOT mask an out-of-range real value. The text scan
// would hit the benign meta.shardCount=1 first and pass, missing the real over-ceiling
// top-level shardCount that Go rejects.
rejects(
  "collision: benign decoy does not mask an over-ceiling top-level shardCount",
  () => validateCanonicalCounts('{"meta":{"shardCount":1},"shardCount":9007199254740993}', "shardCount"),
);
rejects(
  "collision: benign decoy does not mask a string-form freshness.runlogIndex",
  () => validateCanonicalCounts('{"x":{"runlogIndex":3},"freshness":{"runlogIndex":"7"}}', "freshness.runlogIndex"),
);

// The dotted path is resolved structurally: a value present only at the top level is NOT
// reached when a nested path is requested (no leaf-name fallthrough).
accepts(
  "dotted path missing nested object is permitted, not matched at top level",
  () => validateCanonicalCounts('{"runlogIndex":"99"}', "freshness.runlogIndex"),
);

// ---------------------------------------------------------------------------------------
// XC-M3: shard preamble recordCountInShard and record plaintextSize field gate. These are
// the exact field names reader.ts parseShard passes to validateCanonicalCounts.
// ---------------------------------------------------------------------------------------
const goodPreamble = '{"kind":"preamble","formatVersion":"downpipe/0.1.0","runId":"R","shardId":"00000","recordCountInShard":2}';
accepts("shard preamble: canonical recordCountInShard accepted", () => validateCanonicalCounts(goodPreamble, "recordCountInShard"));
rejects(
  "shard preamble: recordCountInShard as string rejected",
  () => validateCanonicalCounts('{"kind":"preamble","recordCountInShard":"2"}', "recordCountInShard"),
);
rejects(
  "shard preamble: over-ceiling recordCountInShard rejected",
  () => validateCanonicalCounts('{"kind":"preamble","recordCountInShard":9007199254740993}', "recordCountInShard"),
);

const goodRecord = '{"kind":"record","sourceType":"kv","name":"k","plaintextSize":318}';
accepts("shard record: canonical plaintextSize accepted", () => validateCanonicalCounts(goodRecord, "plaintextSize"));
rejects(
  "shard record: plaintextSize as string rejected (Go rejects, exit 6)",
  () => validateCanonicalCounts('{"kind":"record","plaintextSize":"318"}', "plaintextSize"),
);
rejects(
  "shard record: fractional plaintextSize rejected",
  () => validateCanonicalCounts('{"kind":"record","plaintextSize":1.5}', "plaintextSize"),
);

// ---------------------------------------------------------------------------------------
// ENG-M3: parseRunlog applies the gate per line (index, recordCount).
// ---------------------------------------------------------------------------------------
function runlogBytes(...entryJSON: string[]): Uint8Array {
  return utf8(entryJSON.map((e) => e + "\n").join(""));
}
const cleanEntry = '{"index":1,"runId":"R1","downpipeId":"dp","time":"t","recordCount":1,"prevRunId":null,"status":"active"}';

accepts("parseRunlog: canonical entry parses", () => {
  const entries = parseRunlog(runlogBytes(cleanEntry));
  if (entries.length !== 1 || entries[0]!.index !== 1) throw new Error("unexpected parse result");
});
rejects(
  "parseRunlog: out-of-range index (1e400 -> Infinity) rejected",
  () => parseRunlog(runlogBytes('{"index":1e400,"runId":"R1","downpipeId":"dp","time":"t","recordCount":1,"prevRunId":null,"status":"active"}')),
);
rejects(
  "parseRunlog: index as string rejected",
  () => parseRunlog(runlogBytes('{"index":"5","runId":"R1","downpipeId":"dp","time":"t","recordCount":1,"prevRunId":null,"status":"active"}')),
);
rejects(
  "parseRunlog: over-ceiling recordCount rejected",
  () => parseRunlog(runlogBytes('{"index":1,"runId":"R1","downpipeId":"dp","time":"t","recordCount":9007199254740993,"prevRunId":null,"status":"active"}')),
);
// A poison index on a SIBLING entry (not the run under restore) must still be rejected:
// this is the exact freshness exploit the gate closes (the sibling inflates the global max
// that the anti-rollback min-pin compares against).
rejects(
  "parseRunlog: poison index on a sibling entry rejected",
  () =>
    parseRunlog(
      runlogBytes(
        cleanEntry,
        '{"index":1e400,"runId":"R2","downpipeId":"dp","time":"t","recordCount":1,"prevRunId":"R1","status":"active"}',
      ),
    ),
);

// ---------------------------------------------------------------------------------------
// ENG-M3 end-to-end: a VALIDLY SIGNED RUNLOG whose sibling entry carries an out-of-range
// index must still be rejected by checkRunlogFreshness, proving the gate fires after the
// signature check and defeats the anti-rollback bypass (without the gate, the Infinity max
// made the min-pin comparison always false).
// ---------------------------------------------------------------------------------------
async function freshnessRejectsPoisonedSignedRunlog(): Promise<void> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };

  // Build NDJSON by hand so a sibling entry can carry a non-canonical index, then sign the
  // exact bytes so the signature verifies but the per-line gate must still reject it.
  const here: RunlogEntry = { index: 1, runId: "R1", downpipeId: "dp", time: "t", recordCount: 1, prevRunId: null, status: "active" };
  const hereLine = canonicalJSON(here);
  const poisonLine = utf8('{"index":1e400,"runId":"R2","downpipeId":"dp","time":"t","recordCount":1,"prevRunId":"R1","status":"active"}');
  const runlog = concat(hereLine, utf8("\n"), poisonLine, utf8("\n"));
  const sig = await hybridSign(ed.privateKey, mldsa.secretKey, runlog);

  const store: ObjectStore = {
    get: async (k: string) => {
      if (k === "_RECOVERY/RUNLOG") return runlog;
      if (k === "_RECOVERY/RUNLOG.sig") return utf8(b64urlEncode(sig));
      throw new Error(`missing ${k}`);
    },
  };
  const root = { downpipeId: "dp", freshness: { prevRunId: null, runlogIndex: 1 } } as unknown as RootManifest;

  let threw = false;
  try {
    await checkRunlogFreshness(store, "R1", root, verifier, { minRunlogIndex: 5 });
  } catch {
    threw = true; // parseRunlog throws on the poison line; the freshness path surfaces it
  }
  ok("freshness: signed RUNLOG with a poison sibling index is rejected (anti-rollback intact)", threw);

  // Control: the same shape with a CANONICAL sibling index below the pin must report the
  // pin failure (ok:false) rather than the Infinity bypass that previously returned silently.
  const cleanSibling = canonicalJSON({ index: 2, runId: "R2", downpipeId: "dp", time: "t", recordCount: 1, prevRunId: "R1", status: "active" } satisfies RunlogEntry);
  const cleanLog = concat(hereLine, utf8("\n"), cleanSibling, utf8("\n"));
  const cleanSig = await hybridSign(ed.privateKey, mldsa.secretKey, cleanLog);
  const cleanStore: ObjectStore = {
    get: async (k: string) => {
      if (k === "_RECOVERY/RUNLOG") return cleanLog;
      if (k === "_RECOVERY/RUNLOG.sig") return utf8(b64urlEncode(cleanSig));
      throw new Error(`missing ${k}`);
    },
  };
  const res = await checkRunlogFreshness(cleanStore, "R1", root, verifier, { minRunlogIndex: 5 });
  ok("freshness: canonical RUNLOG below the min-pin is reported below-pin (not silently passed)", res.ok === false && res.reason === "below the min-runlog-index pin");
}

// ---------------------------------------------------------------------------------------
// HI-05: rollbackDetected must be an UNCONDITIONAL signal, independent of allowStale/ok -- a
// detected chain anomaly, or a breach of the out-of-band minRunlogIndex pin, is positive proof the
// RUNLOG object read back does not reflect the true state, which allowStale (an informational
// "proceed despite a flagged problem" override) must never mask. Every REAL production caller
// (attestKeyless's default, verify-at-seal.ts, restore-verify.ts, replicate.ts, reconcile-pass.ts)
// passes allowStale:true, so without this, ok alone can never surface either signal and the
// anti-rollback check is defeated by a clean whole-document replay (test/validate-reader.ts's
// runRollbackPinAttestation drives that end to end); this test isolates the two signals directly.
// ---------------------------------------------------------------------------------------
async function freshnessRollbackDetectedIsUnconditional(): Promise<void> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };
  const root = { downpipeId: "dp", freshness: { prevRunId: null, runlogIndex: 1 } } as unknown as RootManifest;

  // A genuine chain anomaly: R1 and a sibling both carry index 1, a duplicate the account-global
  // counter can never legitimately reissue -- canonical values (not the out-of-range 1e400 poison
  // above), so this is squarely detectChainAnomaly's own signal, not the canonical-numeric gate.
  const r1 = { index: 1, runId: "R1", downpipeId: "dp", time: "t", recordCount: 1, prevRunId: null, status: "active" } satisfies RunlogEntry;
  const dupSibling = { index: 1, runId: "R2", downpipeId: "dp", time: "t", recordCount: 1, prevRunId: "R1", status: "active" } satisfies RunlogEntry;
  const anomalyLog = concat(canonicalJSON(r1), utf8("\n"), canonicalJSON(dupSibling), utf8("\n"));
  const anomalySig = await hybridSign(ed.privateKey, mldsa.secretKey, anomalyLog);
  const anomalyStore: ObjectStore = {
    get: async (k: string) => {
      if (k === "_RECOVERY/RUNLOG") return anomalyLog;
      if (k === "_RECOVERY/RUNLOG.sig") return utf8(b64urlEncode(anomalySig));
      throw new Error(`missing ${k}`);
    },
  };

  // allowStale:true is what every real production caller passes -- the exact configuration the
  // finding's exploit runs under, so this is the load-bearing assertion.
  const anomalyRes = await checkRunlogFreshness(anomalyStore, "R1", root, verifier, { allowStale: true });
  ok("freshness: a chain anomaly still reports ok:true under allowStale (masked, unchanged)", anomalyRes.ok === true);
  ok("freshness: a chain anomaly sets rollbackDetected:true regardless of allowStale (HI-05)", anomalyRes.rollbackDetected === true);

  // Control: the SAME allowStale:true call over a clean (non-anomalous, unpinned) document must NOT
  // set rollbackDetected -- the field must not become a blanket "allowStale was set" flag.
  const cleanLog = concat(canonicalJSON(r1), utf8("\n"));
  const cleanSig = await hybridSign(ed.privateKey, mldsa.secretKey, cleanLog);
  const cleanStore: ObjectStore = {
    get: async (k: string) => {
      if (k === "_RECOVERY/RUNLOG") return cleanLog;
      if (k === "_RECOVERY/RUNLOG.sig") return utf8(b64urlEncode(cleanSig));
      throw new Error(`missing ${k}`);
    },
  };
  const cleanRes = await checkRunlogFreshness(cleanStore, "R1", root, verifier, { allowStale: true });
  ok("freshness: a clean, unpinned document does not set rollbackDetected", cleanRes.rollbackDetected === false);

  // The min-runlog-index pin is the SAME unconditional signal: below the pin sets
  // rollbackDetected:true even though ok stays masked true by allowStale.
  const pinRes = await checkRunlogFreshness(cleanStore, "R1", root, verifier, { allowStale: true, minRunlogIndex: 5 });
  ok("freshness: below the min-runlog-index pin reports ok:true under allowStale (masked, unchanged)", pinRes.ok === true);
  ok("freshness: below the min-runlog-index pin sets rollbackDetected:true regardless of allowStale (HI-05)", pinRes.rollbackDetected === true);
}

async function main(): Promise<void> {
  await freshnessRejectsPoisonedSignedRunlog();
  await freshnessRollbackDetectedIsUnconditional();

  console.log(failures === 0 ? "\nCANONNUM TESTS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
