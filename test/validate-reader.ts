// The second-reader proof: the engine's TypeScript reader opens the Go reference's
// conformance archives end to end (signature, capsule, key commitment, shard hashes,
// Merkle root, per-record plaintext hash) and either recovers the values the vectors pin
// (positives) or rejects at the documented phase (negatives). The corpus is the
// downpipe conformance suite re-vendored at the commit in test/vectors/VECTORS_COMMIT.
// Run with `node test/validate-reader.ts` after `npm install`.
//
// The harness is discovery-driven: it scans every vector directory's expect.json and
// dispatches purely on that file's declared outcome (mode, phase, runId, options), so it
// never names a vector and never carries the record values in code. Adding or removing a
// vector in a re-vendor is exercised with no edit to this test. It proves conformance by
// RECOVER + REJECT only. It never re-emits or byte-compares the capsule, root, signature
// or RUNLOG, because those draw fresh ML-KEM and signature randomness on each regeneration
// and so are a reader corpus, not a writer-reproducible one (see test/vectors/README.md).
//
// Each negative is driven straight from the vendored corpus, including the five structural
// negatives (single-half-signature, secrets-with-compression, mixed-codec, unknown-major,
// deleted-shard): the engine reader already enforces the codec, secrets and major gates,
// the canonical-numeric check and the bundle verify, so every negative is rejected from the
// vendored bytes and every positive opens. A vector the Go reader handles that this reader
// cannot recover or reject is therefore a real reader gap and is reported as a FAIL, not
// papered over.
//
// Beyond the open/reject check, the harness asserts the expected Outcome labels and segment
// counts wherever the vector declares them (README "Labels" and "segCount" fields):
//
//   - labels.breakGlassVerified: for a positive, the identity's derived fingerprint must
//     match the break-glass recipient in the signed root, proving the reader routes through
//     the correct capsule wrap.
//   - labels.signatureResult: for a negative, the thrown error must match the class that
//     the declared signatureResult implies (absent => store read failure before verify;
//     invalid/wrong-signer => signature verification failure). A regression that crashes
//     before reaching the signature gate, or silently swallows a missing sig file, will
//     change the error class and the assertion will catch it.
//   - labels.recoveryBundleVerified: for a negative, the thrown error must identify the
//     recovery bundle as the rejection site.
//   - segCount: the archive's seg/ tree must contain exactly the declared number of .seg
//     objects, proving the dedup (one shared non-secret segment) and the secrets-never-
//     dedup (one segment per record) rules at the storage layer.

import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { openRun, attestKeyless, type ObjectStore, type KeylessAttestation } from "../src/format/reader.ts";
import { parseIdentity, parseVerifier } from "../src/crypto/keys.ts";
import { identityFingerprint, recipientFingerprint, recipientSetHash } from "../src/crypto/capsule.ts";
import type { HybridRecipientPrivate, HybridRecipientPublic } from "../src/crypto/kem.ts";
import { hybridSign, type HybridVerifier } from "../src/crypto/sign.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { b64urlDecode, b64urlEncode, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { deriveMK, deriveManifestWrapKey } from "../src/crypto/derive.ts";
import { sealStream } from "../src/crypto/stream.ts";
import { frame } from "../src/format/container.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { MAGIC_DPE } from "../src/format/version.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import type { RootManifest, Recipient, ShardRecord } from "../src/format/manifest.ts";
import { checkRunlogFreshness, type FreshnessOptions } from "../src/format/freshness.ts";
import { drainIntegrityFaultLedger } from "../src/format/integrity-fault-ledger.ts";
import type { RunlogEntry } from "../src/format/writer.ts";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, "vectors");
// The Go suite's default run id, used whenever a vector does not pin its own.
const DEFAULT_RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

// DeepMutable drops readonly from a shape's own properties recursively (through nested objects,
// arrays and tuples). The shipped manifest interfaces (RootManifest, ShardRecord, Segment, ...) are
// readonly so the production write path can only assemble them through Mutable<T> locals; this test
// suite, by contrast, builds a known-good manifest or record and then mutates ONE field to drive a
// negative control (a re-signed one-field tamper, an out-of-range packed slice, a wrong codec). The
// builders below return DeepMutable<T> so those deliberate single-field mutations type-check without
// loosening the shipped readonly shapes; a DeepMutable<T> is still assignable wherever the readonly T
// is wanted (openRun, signedStore), so nothing downstream changes.
type DeepMutable<T> = T extends readonly unknown[]
  ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
  : T extends object
    ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
    : T;

// A read-only ObjectStore backed by a vector's archive/ directory.
class DirStore implements ObjectStore {
  private base: string;
  constructor(base: string) {
    this.base = base;
  }
  async get(key: string): Promise<Uint8Array> {
    return new Uint8Array(await readFile(join(this.base, key)));
  }
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function text(path: string): Promise<string> {
  return new TextDecoder().decode(await readFile(path));
}

interface Keys {
  identity: HybridRecipientPrivate;
  verifier: HybridVerifier;
}

// The conformance vectors store the keys as raw base64url (no labelled prefix).
async function loadKeys(dir: string): Promise<Keys> {
  const identity = parseIdentity(b64urlDecode((await text(join(dir, "identity.key"))).trim()));
  const verifier = parseVerifier(b64urlDecode((await text(join(dir, "signer.pub"))).trim()));
  return { identity, verifier };
}

// VectorLabels mirrors the labels field in expect.json (README "Labels"). A label is
// asserted only when present in the vector; absent means the harness does not check it.
interface VectorLabels {
  signatureResult?: string;          // "absent" | "invalid" | "wrong-signer"
  breakGlassVerified?: boolean;
  recoveryBundleVerified?: boolean;
}

// The shape of one expect.json entry, whether it is the top-level expectation or an
// also[] entry. The labels and segCount fields are now fully typed and asserted wherever
// the vector declares them.
interface VectorExpect {
  mode: "positive" | "negative";
  runId?: string | null;
  options?: { allowStale?: boolean; minRunlogIndex?: number; checkRecoveryBundle?: boolean } | null;
  records?: Array<{ name: string; valueB64: string }>;
  phase?: "open" | "restore";
  exitCode?: number;
  labels?: VectorLabels;
  // segCount is the number of .seg objects the archive must contain. It proves the
  // dedup (shared non-secret segment) and secrets-never-dedup rules at the storage layer.
  segCount?: number;
  also?: VectorExpect[];
}

type OpenOpts = { verifyFreshness?: boolean; checkRecoveryBundle?: boolean } & FreshnessOptions;

// buildOpts builds the openRun options from a vector's options block under
// exactOptionalPropertyTypes: every field is added by a conditional spread so an absent
// option is never assigned `undefined` (which the strict flag rejects). verifyFreshness is
// turned on whenever an options block is present and there is a freshness-relevant field,
// so allowStale and minRunlogIndex take effect; freshness defaults off otherwise. The
// checkRecoveryBundle flag is forwarded when the options block sets it.
function buildOpts(options: VectorExpect["options"], forceFreshness = false): OpenOpts {
  if (!options && !forceFreshness) return {};
  const hasFreshness = forceFreshness || !!(options && (options.allowStale !== undefined || options.minRunlogIndex !== undefined));
  return {
    ...(hasFreshness ? { verifyFreshness: true } : {}),
    ...(options?.allowStale ? { allowStale: true } : {}),
    ...(typeof options?.minRunlogIndex === "number" ? { minRunlogIndex: options.minRunlogIndex } : {}),
    ...(options?.checkRecoveryBundle ? { checkRecoveryBundle: true } : {}),
  };
}

// countSegFiles returns the number of .seg objects under archive/seg/ for a given archive
// directory. It is a filesystem count, not a reader output: it proves the dedup and
// secrets-never-dedup rules at the storage layer (the reader sees one or two segments per
// record, but the archive must physically contain the declared number of unique seg/ files).
// Returns 0 when the seg/ subdirectory does not exist or is empty.
async function countSegFiles(archiveDir: string): Promise<number> {
  const segDir = join(archiveDir, "seg");
  let entries: string[];
  try {
    entries = await readdir(segDir, { recursive: true });
  } catch {
    return 0;
  }
  return entries.filter((e) => e.endsWith(".seg")).length;
}

// signatureErrorClass classifies a thrown error into the three signature outcomes the
// conformance spec defines. It does not match on exact message text so minor wording
// changes in the reader do not break the harness; it matches on the structural signal
// (file-not-found for absent; verification-or-decode-failure for invalid/wrong-signer).
//
// absent: the .sig file was not present in the archive. The DirStore.get call throws an
//         OS-level "no such file or directory" error before the reader can attempt to
//         verify the bytes.
// invalid/wrong-signer: the .sig file was present but was either not decodeable as
//         base64url, or hybridVerify returned false, so the reader threw "root signature
//         did not verify" or a decode error. A vector that encodes the sig file as garbage
//         bytes (e.g. "@@not-base64@@") also lands here, because the failure is still about
//         the signature material being invalid, not about the file being absent.
//         Both "invalid" and "wrong-signer" reach the same class; the distinction is about
//         which key the signer used, not about which code path fires.
function signatureErrorClass(err: unknown): "absent" | "signature-failure" | "other" {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  // ENOENT / "no such file" / "cannot find" all indicate the file was missing.
  if (msg.includes("enoent") || msg.includes("no such file") || msg.includes("cannot find")) {
    return "absent";
  }
  // "root signature did not verify" is the reader's invariant for a present-but-bad sig.
  if (msg.includes("signature") && msg.includes("verify")) {
    return "signature-failure";
  }
  // A corrupted sig file (non-base64url content) causes a decode error before hybridVerify
  // is reached. This is still a signature-class failure: the file existed but the signature
  // material was invalid, so the reader correctly rejected the archive.
  if (msg.includes("base64") || msg.includes("invalid character") || msg.includes("decode")) {
    return "signature-failure";
  }
  return "other";
}

// exitCodeClass returns a brief description of what a conforming reader MUST check at
// each exit code (SPEC 14.3), used to derive the expected error class for negative vectors
// that do not carry a labels block. This is informational only; the meaningful assertions
// are in assertNegativeRejected and the label checkers.
function exitCodeLabel(exitCode: number | undefined): string {
  switch (exitCode) {
    case 2: return "unverified (crypto/signature/structure failure)";
    case 3: return "incomplete (missing shard or record count mismatch)";
    case 4: return "plaintext hash mismatch";
    case 5: return "stale/freshness failure";
    case 6: return "usage error (format violation)";
    default: return "unknown";
  }
}

// assertPositive opens a run and proves every pinned record restores byte-for-byte. It is
// the single positive oracle, shared by top-level positives and by also[] positive entries
// (the dedup and stale-run recoveries), so multi-chunk, multi-segment, packed, gzip,
// secrets, empty, master-capsule and break-glass are all checked by the same path the
// reader uses in production. The record names and values come only from the vector.
//
// In addition to byte-correct restore, it asserts the Outcome labels and segCount wherever
// the vector declares them. These are negative controls: if the reader were replaced with a
// stub that opens everything and returns empty bytes, the label assertions would catch it.
// assertPositiveLabels asserts the Outcome labels a positive vector declares: breakGlassVerified (the
// identity is the break-glass key, so its fingerprint must match the break-glass recipient in the signed
// root) and segCount (the dedup / secrets-never-dedup rules, counted from the archive's seg/ tree on disk).
// These are negative controls: an open-everything stub would not produce the right fingerprint or seg count.
async function assertPositiveLabels(label: string, archiveDir: string, identity: HybridRecipientPrivate, run: Awaited<ReturnType<typeof openRun>>, expect: VectorExpect): Promise<void> {
  if (expect.labels?.breakGlassVerified !== undefined) {
    const idFP = await identityFingerprint(identity);
    const bgRecipient = run.root.recipients.find((r) => r.role === "break-glass");
    const bgFP = bgRecipient?.fingerprint ?? null;
    const gotVerified = bgFP !== null && idFP === bgFP;
    ok(
      `${label}: labels.breakGlassVerified=${expect.labels.breakGlassVerified} (identity FP matches break-glass recipient)`,
      gotVerified === expect.labels.breakGlassVerified,
    );
    if (gotVerified !== expect.labels.breakGlassVerified) {
      console.log(`       identity FP: ${idFP}`);
      console.log(`       breakGlass FP: ${bgFP ?? "(no break-glass recipient found)"}`);
    }
  }

  if (expect.segCount !== undefined) {
    const got = await countSegFiles(archiveDir);
    ok(`${label}: segCount=${expect.segCount} (archive has exactly ${expect.segCount} .seg file${expect.segCount !== 1 ? "s" : ""})`, got === expect.segCount);
    if (got !== expect.segCount) {
      console.log(`       found ${got} .seg file${got !== 1 ? "s" : ""} in ${archiveDir}/seg/`);
    }
  }
}

async function assertPositive(label: string, dir: string, expect: VectorExpect): Promise<void> {
  const archiveDir = join(dir, "archive");
  const store = new DirStore(archiveDir);
  const { identity, verifier } = await loadKeys(dir);
  const runId = expect.runId ?? DEFAULT_RUN_ID;
  const opts = buildOpts(expect.options ?? null);

  let run;
  try {
    run = await openRun(store, runId, identity, verifier, opts);
  } catch (e) {
    ok(`${label}: run opens and verifies`, false);
    console.log(`       open threw: ${(e as Error).message}`);
    return;
  }
  ok(`${label}: run opens and verifies`, true);

  await assertPositiveLabels(label, archiveDir, identity, run, expect);

  for (const want of expect.records ?? []) {
    const rec = run.records.find((r) => r.name === want.name);
    ok(`${label}: record ${want.name} present`, !!rec);
    if (!rec) continue;
    try {
      const got = await run.restoreRecord(rec);
      ok(`${label}: record ${want.name} restores byte-correct`, eqBytes(got, b64urlDecode(want.valueB64)));
    } catch (e) {
      ok(`${label}: record ${want.name} restores byte-correct`, false);
      console.log(`       restore threw: ${(e as Error).message}`);
    }
  }
}

// assertNegativeRejected drives one negative straight from the vendored corpus and asserts
// the reader throws at the vector's declared phase. The phase decides where the rejection
// must land; no vector name and no exit-code-to-gate table appears here. For freshness
// negatives (exit 5) it threads verifyFreshness (and any minRunlogIndex pin) so the
// freshness gate runs; for bundle-check negatives it threads checkRecoveryBundle; otherwise
// it opens with no optional gates so the SPEC 8.3 chain, the structural gate or the AEAD
// failure is what fires.
//
// Beyond checking that the reader throws, it asserts the thrown error matches the expected
// class: a signature outcome label (absent/invalid/wrong-signer) proves the reader reaches
// and fails at the signature gate, not at an earlier or later point; a
// recoveryBundleVerified:false label proves the reader reaches the bundle gate. These
// assertions serve as negative controls: a stub that throws "something went wrong" for every
// negative would be caught because its errors would not match the expected class.
async function assertNegativeRejected(label: string, dir: string, expect: VectorExpect): Promise<void> {
  const archiveDir = join(dir, "archive");
  const store = new DirStore(archiveDir);
  const { identity, verifier } = await loadKeys(dir);
  const runId = expect.runId ?? DEFAULT_RUN_ID;
  // Freshness gates default off; bundle check defaults off. Build opts from the vector's
  // options block, forcing verifyFreshness on for exit-5 (stale) vectors.
  const opts: OpenOpts = buildOpts(expect.options ?? null, expect.exitCode === 5);

  if (expect.phase !== "restore") {
    let threw = false;
    let thrownErr: unknown;
    try {
      await openRun(store, runId, identity, verifier, opts);
    } catch (e) {
      threw = true;
      thrownErr = e;
    }
    ok(`${label}: rejected at open (expected: exit ${expect.exitCode ?? "?"}, ${exitCodeLabel(expect.exitCode)})`, threw);

    if (threw && thrownErr !== undefined) {
      assertErrorClass(label, thrownErr, expect);
    }
    return;
  }

  // phase === restore: the run must open, then the first failing record's restore throws.
  let run;
  try {
    run = await openRun(store, runId, identity, verifier, opts);
  } catch (e) {
    ok(`${label}: opens then rejected at restore`, false);
    console.log(`       open unexpectedly threw: ${(e as Error).message}`);
    return;
  }
  let restoreThrew = false;
  let restoreErr: unknown;
  for (const rec of run.records) {
    try {
      await run.restoreRecord(rec);
    } catch (e) {
      restoreThrew = true;
      restoreErr = e;
      break;
    }
  }
  ok(`${label}: opens then rejected at restore (expected: exit ${expect.exitCode ?? "?"}, ${exitCodeLabel(expect.exitCode)})`, restoreThrew);

  if (restoreThrew && restoreErr !== undefined) {
    assertErrorClass(label, restoreErr, expect);
  }
}

// assertErrorClass asserts that the thrown error matches the expected class derived from
// the vector's labels and exitCode. It is called after a throw is confirmed, so the
// "was it rejected" check has already passed; this function only asserts WHAT was rejected.
function assertErrorClass(label: string, err: unknown, expect: VectorExpect): void {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();

  // labels.signatureResult: assert the error class matches the declared outcome.
  const sigResult = expect.labels?.signatureResult;
  if (sigResult !== undefined) {
    const cls = signatureErrorClass(err);
    if (sigResult === "absent") {
      ok(
        `${label}: labels.signatureResult=absent (error is a missing-file failure, not a verification failure)`,
        cls === "absent",
      );
      if (cls !== "absent") {
        console.log(`       error class: ${cls}, message: ${(err instanceof Error ? err.message : String(err)).slice(0, 120)}`);
      }
    } else if (sigResult === "invalid" || sigResult === "wrong-signer") {
      // Both "invalid" and "wrong-signer" fire at hybridVerify returning false, producing the
      // same "root signature did not verify" message. The harness groups them as one class
      // because the distinction is which key the signer used, not which code path fires.
      ok(
        `${label}: labels.signatureResult=${sigResult} (error is a signature verification failure, not a missing-file failure)`,
        cls === "signature-failure",
      );
      if (cls !== "signature-failure") {
        console.log(`       error class: ${cls}, message: ${(err instanceof Error ? err.message : String(err)).slice(0, 120)}`);
      }
    }
  }

  // labels.recoveryBundleVerified: when false on a negative, the error must come from the
  // bundle gate, not from the run chain. The bundle gate fires before the signature check,
  // so a bundle error message must mention SHA384SUMS or "recovery bundle".
  const bundleVerified = expect.labels?.recoveryBundleVerified;
  if (bundleVerified === false) {
    const isBundleError = msg.includes("sha384sums") || msg.includes("recovery bundle") || msg.includes("bundle");
    ok(
      `${label}: labels.recoveryBundleVerified=false (error identifies the recovery bundle as the rejection site)`,
      isBundleError,
    );
    if (!isBundleError) {
      console.log(`       message: ${(err instanceof Error ? err.message : String(err)).slice(0, 120)}`);
    }
  }

  // exitCode-based class check for vectors without a labels block. These are lighter
  // assertions that catch gross mis-classification (e.g. a freshness error surfaced as
  // "plaintext hash mismatch" would fail the exit-5 pattern check).
  if (sigResult === undefined && bundleVerified === undefined && expect.exitCode !== undefined) {
    assertExitCodeClass(label, msg, expect.exitCode);
  }
}

// assertExitCodeClass checks the error message against the structural pattern expected for
// a given exit code. It is a best-effort check: it catches obvious mis-routing (a stale-
// run rejection surfacing as a plaintext-hash message, for example) without over-fitting on
// the exact wording of any individual error. Vectors that already carry a labels block are
// checked by assertErrorClass's label path instead, so this only runs for unlabelled
// negatives. Each exit code's structural pattern is a named predicate over the (lower-cased) message, so
// the switch only routes; the predicate carries the wording it accepts.

// Exit 5: the RUNLOG is absent, stale, rolled back, below the pinned index.
function looksLikeFreshnessError(msg: string): boolean {
  return msg.includes("freshness") || msg.includes("stale") || msg.includes("runlog") || msg.includes("rollback") || msg.includes("chain");
}
// Exit 2's narrower freshness probe (the original exit-2 negative control: freshness/stale/runlog only),
// kept distinct so widening the exit-5 probe never tightens the exit-2 "is NOT a freshness error" check.
function looksLikeFreshnessErrorExit2(msg: string): boolean {
  return msg.includes("freshness") || msg.includes("stale") || msg.includes("runlog");
}
// Exit 4 / exit 2 share this signal: the recovered plaintext hash disagrees with the signed record.
function looksLikePlaintextError(msg: string): boolean {
  return msg.includes("plaintext hash");
}
// Exit 3: a missing shard (store.get ENOENT) or a record count mismatch.
function looksLikeIncompleteError(msg: string): boolean {
  return (
    msg.includes("enoent") ||
    msg.includes("no such file") ||
    (msg.includes("records") && msg.includes("declares")) ||
    msg.includes("hash does not match the signed root") ||
    msg.includes("shard")
  );
}
// Exit 6: a usage/format error (unknown major version, mixed codec, secrets+gzip, non-canonical count, or
// any other spec-level structural rejection that is not a crypto failure).
function looksLikeUsageError(msg: string): boolean {
  return (
    msg.includes("formatversion") ||
    msg.includes("major") ||
    msg.includes("codec") ||
    msg.includes("canonical") ||
    msg.includes("must not be compressed") ||
    msg.includes("field") ||
    msg.includes("usage") ||
    msg.includes("not implemented") ||
    msg.includes("unknown source type")
  );
}

function assertExitCodeClass(label: string, msg: string, exitCode: number): void {
  switch (exitCode) {
    case 2:
      // Exit 2 covers any crypto/structural verification failure: signature, key commitment, shard hash,
      // recipient fingerprint, Merkle root, capsule, bundle. Plaintext and freshness failures are distinct
      // (exit 4 and 5); a message that looks like those would be mis-classified.
      ok(
        `${label}: exit 2 error is not a freshness or plaintext error (correct class for unverified)`,
        !looksLikeFreshnessErrorExit2(msg) && !looksLikePlaintextError(msg),
      );
      break;
    case 3:
      ok(`${label}: exit 3 error indicates an incomplete or missing-object failure`, looksLikeIncompleteError(msg));
      break;
    case 4:
      ok(`${label}: exit 4 error mentions plaintext hash`, looksLikePlaintextError(msg));
      break;
    case 5:
      ok(`${label}: exit 5 error mentions freshness or runlog`, looksLikeFreshnessError(msg));
      break;
    case 6:
      ok(`${label}: exit 6 error indicates a format/usage violation`, looksLikeUsageError(msg));
      break;
    default:
      break;
  }
}

// dispatch routes one expectation (top-level or an also[] entry) to the recover or reject
// oracle purely on its declared mode, so a positive also[] (dedup, allowStale recovery) and
// any future negative also[] are both driven without a name check.
async function dispatch(label: string, dir: string, expect: VectorExpect): Promise<void> {
  if (expect.mode === "positive") {
    await assertPositive(label, dir, expect);
  } else {
    await assertNegativeRejected(label, dir, expect);
  }
}

// loadVerifier reads only the operator-pinned PUBLIC verifier for a vector. The keyless
// attestation tier needs no decryption identity (it reads no record plaintext), so unlike
// loadKeys it never touches identity.key, mirroring the break-glass-only posture in which the
// engine holds no in-account read-back key but can still attest a sealed run.
async function loadVerifier(dir: string): Promise<HybridVerifier> {
  return parseVerifier(b64urlDecode((await text(join(dir, "signer.pub"))).trim()));
}

// FaultyStore wraps a real DirStore and lets a test inject one fault for a single object key:
// either a thrown error (to drive the destination-access reason buckets the production
// ObjectStore raises) or a one-byte mutation of the returned bytes (to break a signed shard
// hash WITHOUT touching the signed root, which the corpus cannot ship because re-signing needs
// the private key). Every other key passes through untouched, so the rest of the run still
// verifies. It is the keyless counterpart of the streaming tests' MapStore tampering.
class FaultyStore implements ObjectStore {
  private inner: DirStore;
  private targetKey: string;
  private mode: "throw" | "flip";
  private thrownMessage: string;
  constructor(base: string, targetKey: string, mode: "throw" | "flip", thrownMessage = "") {
    this.inner = new DirStore(base);
    this.targetKey = targetKey;
    this.mode = mode;
    this.thrownMessage = thrownMessage;
  }
  async get(key: string): Promise<Uint8Array> {
    if (key === this.targetKey) {
      if (this.mode === "throw") throw new Error(this.thrownMessage);
      const bytes = await this.inner.get(key);
      // Flip the low bit of the first byte so the object's SHA-384 no longer matches the value
      // pinned in the signed root. A non-empty object always has a first byte to flip.
      if (bytes.length > 0) bytes[0] = bytes[0]! ^ 0x01;
      return bytes;
    }
    return this.inner.get(key);
  }
}

// shardObjectOf reads a positive vector's signed root and returns the object key of its first
// shard, so a fault can be aimed at a real shard the keyless completeness check will fetch.
async function shardObjectOf(archiveDir: string, runId: string): Promise<string> {
  const rootBytes = await new DirStore(archiveDir).get(`run/${runId}/root.manifest.json`);
  const root = JSON.parse(new TextDecoder().decode(rootBytes)) as { shards: Array<{ object: string }> };
  return root.shards[0]!.object;
}

// KeylessExpect declares the three flags and a reason predicate for one attestKeyless case.
// reasonHas is a list of lowercase substrings the coarse, secret-free reason must contain (the
// reason is an enumerated phrase, so a substring match is exact enough and survives wording
// tweaks); reasonNull asserts a clean attestation. The two are mutually exclusive.
interface KeylessExpect {
  signatureValid: boolean;
  complete: boolean;
  notRolledBack: boolean;
  reasonHas?: string[];
  reasonNull?: boolean;
  downpipeIdNull?: boolean;
}

// assertKeyless runs attestKeyless over one store and asserts every flag, the coarse reason and
// the downpipeId redaction rule. It is the keyless oracle: it never throws (the function is
// total by contract), so a regression that lets an exception escape, fabricates a pass for a
// check that could not be reached, or leaks raw exception text into the reason is caught here.
async function assertKeyless(label: string, store: ObjectStore, runId: string, verifier: HybridVerifier, opts: { allowStale?: boolean; minRunlogIndex?: number }, want: KeylessExpect): Promise<void> {
  let att: KeylessAttestation;
  try {
    att = await attestKeyless(store, runId, verifier, opts);
  } catch (e) {
    ok(`${label}: attestKeyless does not throw (total by contract)`, false);
    console.log(`       threw: ${(e as Error).message}`);
    return;
  }
  ok(`${label}: signatureValid=${want.signatureValid}`, att.signatureValid === want.signatureValid);
  ok(`${label}: complete=${want.complete}`, att.complete === want.complete);
  ok(`${label}: notRolledBack=${want.notRolledBack}`, att.notRolledBack === want.notRolledBack);

  if (want.reasonNull) {
    ok(`${label}: reason is null (clean attestation)`, att.reason === null);
  } else if (want.reasonHas) {
    const r = (att.reason ?? "").toLowerCase();
    const hit = want.reasonHas.every((s) => r.includes(s));
    ok(`${label}: reason contains ${JSON.stringify(want.reasonHas)} (coarse, secret-free)`, hit);
    if (!hit) console.log(`       reason was: ${JSON.stringify(att.reason)}`);
  }

  // downpipeId redaction: it is read from the SIGNATURE-VERIFIED root, so it must be null when
  // the signature did not verify (no trustworthy manifest to read it from) and a non-empty id
  // once the signature held. This guards the "never report an unverified field" rule.
  if (want.downpipeIdNull) {
    ok(`${label}: downpipeId is null (no signature-verified manifest)`, att.downpipeId === null);
  } else if (att.signatureValid) {
    ok(`${label}: downpipeId is present (read from the signed root)`, typeof att.downpipeId === "string" && att.downpipeId.length > 0);
  }
}

// runKeylessAttestation drives the Tier 0 keyless integrity attestation (attestKeyless) across
// the vendored corpus and two injected-fault stores. attestKeyless is the keyless dual of
// openRun: it verifies the root signature under the PUBLIC verifier, re-runs the key-free
// structural gates (canonical-numeric, format-version major, runId match, recipient-set), the
// shard-presence completeness proof and the RUNLOG anti-rollback check, and returns three honest
// flags plus a coarse, secret-free reason, never an exception and never raw exception text. Each
// case below pins what a keyless verdict MUST be for a known archive, so the tier cannot quietly
// start fabricating passes (the strongest failure mode for an attestation) or leaking internals.
//
// The verdicts are deliberately not all "reject": the keyless tier is honestly WEAKER than the
// keyed tiers. wrong-merkle-root and incomplete-record-count both pass keyless because a Merkle
// recomputation and a per-record count need the manifest key; the keyless tier attests only the
// covering signature plus shard presence, so it correctly does not claim to have caught them.
// That honesty (a check it cannot reach is not faked as a pass) is itself asserted here.
async function runKeylessAttestation(): Promise<void> {
  console.log("\nkeyless attestation (Tier 0, no decryption key):");

  // 1) Clean attestation. A well-formed, latest run attests on all three flags with a null
  // reason. allowStale defaults to true; here the run is the latest so notRolledBack holds either
  // way. Exercises the whole success body and the downpipeId-from-signed-root read.
  {
    const dir = join(vectors, "master-capsule");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless master-capsule", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, {}, {
      signatureValid: true, complete: true, notRolledBack: true, reasonNull: true,
    });
  }

  // 2) Signature absent. The .sig object is missing, so the read throws inside the signature
  // try-block and the attestation reports signatureValid:false with the manifest-or-signature
  // missing reason; no later check is evaluated (all false), and downpipeId stays null.
  {
    const dir = join(vectors, "absent-signature");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless absent-signature", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: false, complete: false, notRolledBack: false, reasonHas: ["missing"], downpipeIdNull: true,
    });
  }

  // 3) Signature present but does not verify (wrong signer). hybridVerify returns false, so the
  // attestation takes the early signatureValid:false return (not the catch), with the
  // signature-did-not-verify reason. This is the verify-false arm, distinct from the missing-file
  // arm in case 2.
  {
    const dir = join(vectors, "unknown-signer");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless unknown-signer", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: false, complete: false, notRolledBack: false, reasonHas: ["signature", "verify"], downpipeIdNull: true,
    });
  }

  // 4) Validly signed but an unimplemented major version. The signature holds, so the body is
  // parsed, and checkFormatVersion throws in the structure try-block: signatureValid:true,
  // complete:false, and a coarse structure reason. Drives the structure catch, coarseKeylessReason
  // and keylessErrId, plus the format-version major gate reached on signature-valid bytes.
  {
    const dir = join(vectors, "unknown-major");
    const v = await loadVerifier(dir);
    // The vector's label is "downpipe/9.0.0": a WELL-FORMED semver version at a major this build does not
    // implement, which is the whole point of a vector called unknown-major. The reason names the version
    // specifically rather than the generic structure bucket.
    await assertKeyless("keyless unknown-major", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["archive format version not supported"], downpipeIdNull: true,
    });
  }

  // 5) Validly signed but a structurally broken recipient set (a master-capsule wrap addresses an
  // unlisted recipient). The signature holds, checkRecipientSet throws in the structure try-block:
  // signatureValid:true, complete:false. Drives the recipient-set structural gate on the keyless
  // path, which the corpus reaches here because this tamper leaves the signature intact.
  {
    const dir = join(vectors, "forged-capsule-wrap");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless forged-capsule-wrap", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // 6) Validly signed, structurally valid, but a shard object is absent. Structure passes;
  // completeness throws (the shard get fails) so complete:false with a completeness reason, while
  // signatureValid stays true and downpipeId is read from the signed root. Drives the completeness
  // try/catch and the shard-presence loop.
  {
    const dir = join(vectors, "deleted-shard");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless deleted-shard", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: true, complete: false, notRolledBack: true, reasonHas: ["attestation check failed"], downpipeIdNull: false,
    });
  }

  // 7) Validly signed, structurally valid, but a shard's bytes do not hash to the signed value.
  // The completeness check recomputes the shard SHA-384 and rejects it as an integrity failure, so
  // complete:false with the integrity reason. This binds the stored shard bytes to the signature
  // without any key, the heart of the keyless completeness proof.
  {
    const dir = join(vectors, "shard-hash-mismatch");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless shard-hash-mismatch", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: true, complete: false, notRolledBack: true, reasonHas: ["integrity check failed"], downpipeIdNull: false,
    });
  }

  // 8) Validly signed and complete, but the RUNLOG is absent so the anti-rollback check cannot
  // place the run in the freshness chain. signatureValid and complete hold; notRolledBack:false
  // with a freshness reason surfaced verbatim from checkRunlogFreshness. Drives the freshness
  // try-block and the not-rolled-back reason assignment.
  {
    const dir = join(vectors, "absent-runlog");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless absent-runlog", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: false }, {
      signatureValid: true, complete: true, notRolledBack: false, reasonHas: ["runlog"], downpipeIdNull: false,
    });
  }

  // 9) Honesty controls: the keyless tier is weaker than the keyed tiers and must NOT fake a pass
  // for a check it cannot reach without a key. wrong-merkle-root and incomplete-record-count both
  // attest clean under keyless because a Merkle recomputation and a per-record count need the
  // manifest key; the keyless tier covers only the signature and shard presence. A regression that
  // bolted a fake Merkle or count check onto the keyless tier would flip these to a failure and be
  // caught.
  {
    const dir = join(vectors, "wrong-merkle-root");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless wrong-merkle-root (weaker tier, honestly passes)", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: true }, {
      signatureValid: true, complete: true, notRolledBack: true, reasonNull: true,
    });
  }
  {
    const dir = join(vectors, "incomplete-record-count");
    const v = await loadVerifier(dir);
    await assertKeyless("keyless incomplete-record-count (weaker tier, honestly passes)", new DirStore(join(dir, "archive")), DEFAULT_RUN_ID, v, { allowStale: true }, {
      signatureValid: true, complete: true, notRolledBack: true, reasonNull: true,
    });
  }

  // 10) Injected destination faults on the completeness path, to drive the remaining coarse-reason
  // buckets the corpus cannot produce (a corrupt shard cannot be re-signed without the private
  // key, and a directory store cannot raise the production "is missing" / "status N" wording).
  // FaultyStore aims one fault at a real shard object of a known-good run, leaving the signed root
  // and signature untouched so the signature and structure still pass and only completeness fails.
  {
    const dir = join(vectors, "master-capsule");
    const archiveDir = join(dir, "archive");
    const v = await loadVerifier(dir);
    const shardObject = await shardObjectOf(archiveDir, DEFAULT_RUN_ID);

    // 10a) The production ObjectStore raises `object <key> is missing` on a 404; coarseKeylessReason
    // maps that to the "object missing" bucket. This is the keyless dual of a real dropped object.
    await assertKeyless(
      "keyless shard 404 (object missing bucket)",
      new FaultyStore(archiveDir, shardObject, "throw", `object ${shardObject} is missing`),
      DEFAULT_RUN_ID, v, { allowStale: true },
      { signatureValid: true, complete: false, notRolledBack: true, reasonHas: ["object missing"], downpipeIdNull: false },
    );

    // 10b) A non-404 destination error (an HTTP 5xx) carries a `status <n>` message;
    // coarseKeylessReason maps that to the "destination access error" bucket, distinct from a clean
    // 404. This proves the two access-failure reasons are not collapsed.
    await assertKeyless(
      "keyless shard 503 (destination access bucket)",
      new FaultyStore(archiveDir, shardObject, "throw", `destination GET failed with status 503`),
      DEFAULT_RUN_ID, v, { allowStale: true },
      { signatureValid: true, complete: false, notRolledBack: true, reasonHas: ["destination access"], downpipeIdNull: false },
    );

    // 10c) A flipped shard byte breaks the signed shard hash without re-signing the root, the
    // injected-fault equivalent of the shard-hash-mismatch vector, confirming FaultyStore's flip
    // mode drives the same integrity bucket on an otherwise valid run.
    await assertKeyless(
      "keyless flipped shard byte (integrity bucket via injected fault)",
      new FaultyStore(archiveDir, shardObject, "flip"),
      DEFAULT_RUN_ID, v, { allowStale: true },
      { signatureValid: true, complete: false, notRolledBack: true, reasonHas: ["integrity check failed"], downpipeIdNull: false },
    );
  }

  // 11) Default allowStale. attestKeyless defaults allowStale to true when the option is omitted,
  // so an older but otherwise sound run still attests, with notRolledBack reflecting latest-ness
  // honestly. The dedup vector's second (older) run id, opened with no options block, drives the
  // `allowStale ?? true` default arm and the older-run-still-attests behaviour.
  {
    const dir = join(vectors, "dedup-same-value-two-runs");
    const v = await loadVerifier(dir);
    const olderRunId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    await assertKeyless("keyless dedup older run (allowStale default true)", new DirStore(join(dir, "archive")), olderRunId, v, {}, {
      signatureValid: true, complete: true, notRolledBack: false, reasonHas: ["latest"], downpipeIdNull: false,
    });
  }
}

// A self-generated hybrid signer plus a real recipient public key, built once and reused by the
// structural-attestation cases below. Generating our own signer is the only way to produce a
// VALIDLY SIGNED root that nonetheless carries a malformed structural field: the vendored corpus
// cannot ship one because re-signing needs the private key, so a recipient-set or format-version
// gate that fires only after the signature passes is otherwise unreachable from the corpus.
interface SignerKit {
  verifier: HybridVerifier;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
  recipient: HybridRecipientPublic;
  recipientJSON: Recipient;       // a well-formed break-glass recipient entry for the signed root
  recipientSetHashHex: string;    // the matching recipient-set hash for that single recipient
}

async function makeSignerKit(): Promise<SignerKit> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const verifier: HybridVerifier = { ed: edPublic, mldsa: mldsa.publicKey };

  // A real recipient public key: a 32-byte X25519 public from a random scalar, and a 1568-byte
  // ML-KEM encap key from a random 64-byte seed, so the fingerprint and set hash are genuine.
  const x25519 = x25519PublicFromScalar(crypto.getRandomValues(new Uint8Array(32)));
  const { encapKey } = mlkemKeygen(crypto.getRandomValues(new Uint8Array(64)));
  const recipient: HybridRecipientPublic = { x25519, mlkemEk: encapKey };
  const fingerprint = await recipientFingerprint(x25519, encapKey);
  const recipientSetHashHex = hexEncode(await recipientSetHash([recipient]));
  const recipientJSON: Recipient = {
    fingerprint,
    role: "break-glass",
    x25519: b64urlEncode(x25519),
    mlkem: b64urlEncode(encapKey),
  };

  return {
    verifier,
    sign: (bytes) => hybridSign(ed.privateKey, mldsa.secretKey, bytes),
    recipient,
    recipientJSON,
    recipientSetHashHex,
  };
}

// baseSignedRoot returns a structurally complete, self-consistent root manifest for a given run
// id: a single well-formed break-glass recipient, its matching wrap and recipient-set hash, a
// supported format version and zero shards (so the keyless completeness check passes vacuously
// when the structure is left intact). A case clones this and mutates exactly one field, so the
// signature is over the mutated bytes (it verifies) and the attestation must fail at the gate the
// mutation targets, never at the signature. The capsule sealed/kemCiphertext are placeholders:
// the keyless tier never unwraps the capsule (that needs a key), it only checks the wrap
// fingerprint covers the recipient set.
function baseSignedRoot(kit: SignerKit, runId: string): DeepMutable<RootManifest> {
  return {
    formatVersion: "downpipe/0.1.0",
    runId,
    createdAt: "2026-01-01T00:00:00Z",
    downpipeId: "dp_synth",
    envelope: { aead: "AES-256-GCM", kem: "ML-KEM-1024+X25519", sig: "Ed25519+ML-DSA-87", kdf: "HKDF-SHA-384", chunkSize: 65536, codec: "none" },
    recipients: [kit.recipientJSON],
    masterCapsule: [{ fingerprint: kit.recipientJSON.fingerprint, kemCiphertext: b64urlEncode(new Uint8Array(8)), sealed: b64urlEncode(new Uint8Array(8)) }],
    recipientSetHash: kit.recipientSetHashHex,
    keyCommitment: hexEncode(new Uint8Array(48)),
    breakGlassPresent: true,
    shards: [],
    shardCount: 0,
    declaredRecordCount: 0,
    merkleRoot: hexEncode(new Uint8Array(48)),
    freshness: { prevRunId: null, runlogIndex: 1 },
    signingKeyFingerprint: "00",
  };
}

// signedStore signs a root manifest's canonical bytes with the kit and returns an ObjectStore that
// serves the root, its signature, and (optionally) a faulted RUNLOG. Any other key throws, which is
// fine: the structural cases reject before completeness, and the completeness-vacuous cases (zero
// shards) never read a shard.
function signedStore(kit: SignerKit, runId: string, root: RootManifest, extra?: (key: string) => Uint8Array | undefined): ObjectStore {
  let rootBytes: Uint8Array | null = null;
  let sigBytes: Uint8Array | null = null;
  return {
    async get(key: string): Promise<Uint8Array> {
      if (key === `run/${runId}/root.manifest.json`) {
        if (!rootBytes) rootBytes = canonicalJSON(root);
        return rootBytes;
      }
      if (key === `run/${runId}/root.manifest.json.sig`) {
        if (!sigBytes) {
          if (!rootBytes) rootBytes = canonicalJSON(root);
          sigBytes = utf8(b64urlEncode(await kit.sign(rootBytes)));
        }
        return sigBytes;
      }
      const e = extra?.(key);
      if (e !== undefined) return e;
      throw new Error(`object ${key} is missing`);
    },
  };
}

// oneShardSignedRoot clones baseSignedRoot and lists a single shard so the keyless completeness
// loop actually runs a shard fetch. The shard's pinned SHA-384 is a placeholder: the cases that use
// this root fault the shard get (a thrown destination error) so the completeness check fails inside
// its own try/catch before the recomputed hash is compared, which is the precise path that feeds a
// thrown error to coarseKeylessReason. shardCount matches the single listed shard so the count gate
// is not what fires.
function oneShardSignedRoot(kit: SignerKit, runId: string): DeepMutable<RootManifest> {
  const root = baseSignedRoot(kit, runId);
  root.shards = [{ id: "00000", object: `run/${runId}/manifest/00000.dpe`, sha384: hexEncode(new Uint8Array(48)) }];
  root.shardCount = 1;
  return root;
}

// faultShardGet serves a kit-signed root and signature (so the signature and structure pass) and
// raises a caller-supplied fault from the single shard object's get, so the thrown value reaches
// the keyless completeness catch and is coarsened by coarseKeylessReason. It is the validly-signed
// counterpart of FaultyStore: FaultyStore faults a real vector's shard, this faults a synthetic
// signed root's shard, which lets a test choose the exact thrown shape (a non-Error value, or an
// Error whose message targets a specific coarse-reason bucket).
function faultShardGet(kit: SignerKit, runId: string, root: RootManifest, thrower: () => never): ObjectStore {
  const shardKey = root.shards[0]!.object;
  const inner = signedStore(kit, runId, root);
  return {
    async get(key: string): Promise<Uint8Array> {
      if (key === shardKey) return thrower();
      return inner.get(key);
    },
  };
}

// runKeylessStructuralAttestation drives the keyless gates that fire only on a VALIDLY SIGNED but
// structurally malformed root, which the vendored corpus cannot reach (re-signing needs the
// private key). Each case signs a one-field mutation of a known-good root, so the signature
// verifies (signatureValid stays true) and the attestation must reject at the targeted gate with a
// coarse, secret-free reason. It also exercises the coarse-reason buckets a directory store cannot
// raise (a non-Error throw, the freshness/config buckets) by faulting the RUNLOG read.
async function runKeylessStructuralAttestation(): Promise<void> {
  console.log("\nkeyless attestation on validly-signed-but-malformed roots:");
  const kit = await makeSignerKit();
  const RID = DEFAULT_RUN_ID;

  // Positive control: the unmutated base root attests clean (signature, structure and the vacuous
  // zero-shard completeness all pass; the RUNLOG object is absent, so checkRunlogFreshness reports
  // RUNLOG-absent and notRolledBack is honestly false). This proves the base is well-formed, so a
  // later failure is the mutation, not a broken scaffold.
  await assertKeyless("signed base (well-formed control)", signedStore(kit, RID, baseSignedRoot(kit, RID)), RID, kit.verifier, { allowStale: true }, {
    signatureValid: true, complete: true, notRolledBack: false, reasonHas: ["runlog"], downpipeIdNull: false,
  });

  // formatVersion with no "downpipe/" prefix: checkFormatVersion rejects it as not a downpipe
  // label. Structure fails after a valid signature.
  {
    const root = baseSignedRoot(kit, RID); root.formatVersion = "acme/1.0";
    await assertKeyless("signed bad-format-prefix", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // formatVersion with a single component ("downpipe/1"): not a version at all, so checkFormatVersion
  // refuses it as a damaged or hand-edited manifest rather than as a format this build does not implement.
  // No reader anywhere implements a label that does not name a version, so the go-and-fetch-a-reader remedy
  // would be a lie and the strict answer is the true one.
  //
  // A refusal worded "...is missing the major.minor.patch components" would match coarseKeylessReason's
  // `is missing` net (a substring match), so a version refusal must NOT be attested as an ABSENT OBJECT: that
  // class is replica-fallback-eligible, so it would send the caller to a 3-2-1 copy holding the same signed
  // run and the same label, which could only refuse again.
  {
    const root = baseSignedRoot(kit, RID); root.formatVersion = "downpipe/1";
    // It coarsens to the same generic structure bucket as every other malformed-manifest refusal on this
    // surface (bad-format-prefix, runId-mismatch, forged-capsule-wrap), which is the consistent answer for
    // "the signature held and the body did not validate". What matters is that it is no longer "object
    // missing", a reason that is replica-fallback-eligible and would have sent the caller to a copy holding
    // the identical label.
    await assertKeyless("signed one-component-version", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // The same surface for a WELL-FORMED version this build does not implement: "downpipe/0.2.0", the shape
  // the next byte-level rule change produces. The signature verifies, the bytes are intact and nothing was
  // written, so the attestation must say the reader is the wrong build and must NOT reach either the
  // integrity bucket (which accuses the archive) or the object-missing bucket (which is fallback-eligible).
  // This is the ONLY route to the format-unsupported bucket now that all three components are part of the
  // version, so it is asserted directly: without it that bucket has no driver at all on this surface.
  {
    const root = baseSignedRoot(kit, RID); root.formatVersion = "downpipe/0.2.0";
    await assertKeyless("signed unimplemented-minor", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["archive format version not supported"], downpipeIdNull: true,
    });
  }

  // A TWO-component label is malformed, not a version this build could point somebody at another reader
  // for. It lands in the same structure bucket as the one-component case above. The pre-release lineage
  // that stamped MAJOR.MINOR labels was retired and no obtainable build emits one, so the
  // true reading of these bytes is an anomaly in our own signed manifest.
  {
    const root = baseSignedRoot(kit, RID); root.formatVersion = "downpipe/1.0";
    await assertKeyless("signed two-component-version", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // manifest runId does not match the requested run id: the structure check rejects a manifest
  // bound to a different run, even though it is validly signed.
  {
    const root = baseSignedRoot(kit, RID); root.runId = "01ARZ3NDEKTSV4RRFFQ69G5FZZ";
    await assertKeyless("signed runId-mismatch", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // breakGlassPresent false: checkRecipientSet rejects a manifest that does not declare a
  // break-glass recipient present.
  {
    const root = baseSignedRoot(kit, RID); root.breakGlassPresent = false;
    await assertKeyless("signed no-break-glass-declared", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // recipient x25519 of the wrong length: checkRecipientSet rejects a recipient whose X25519 key is
  // not 32 bytes.
  {
    const root = baseSignedRoot(kit, RID); root.recipients = [{ ...kit.recipientJSON, x25519: b64urlEncode(new Uint8Array(16)) }];
    await assertKeyless("signed bad-x25519-length", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // recipient ML-KEM of the wrong length: checkRecipientSet rejects a recipient whose ML-KEM key is
  // not 1568 bytes.
  {
    const root = baseSignedRoot(kit, RID); root.recipients = [{ ...kit.recipientJSON, mlkem: b64urlEncode(new Uint8Array(32)) }];
    await assertKeyless("signed bad-mlkem-length", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // recipient fingerprint that does not match its public key: checkRecipientSet recomputes the
  // fingerprint and rejects a forged one (the keys are the right length, only the fingerprint lies).
  {
    const root = baseSignedRoot(kit, RID); root.recipients = [{ ...kit.recipientJSON, fingerprint: "deadbeef" }];
    // The wrap must still address the listed (now-forged) fingerprint so the wrap-coverage check is
    // not what fires; the fingerprint recompute is.
    root.masterCapsule = [{ ...root.masterCapsule[0]!, fingerprint: "deadbeef" }];
    await assertKeyless("signed forged-fingerprint", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // two break-glass recipients: checkRecipientSet requires exactly one break-glass role.
  {
    const root = baseSignedRoot(kit, RID);
    const second: Recipient = { ...kit.recipientJSON };
    root.recipients = [kit.recipientJSON, second];
    root.masterCapsule = [root.masterCapsule[0]!, { ...root.masterCapsule[0]! }];
    await assertKeyless("signed two-break-glass", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // a master-capsule wrap that does not cover the recipient set (no wrap for the sole recipient):
  // checkRecipientSet rejects when the wraps do not address every listed recipient.
  {
    const root = baseSignedRoot(kit, RID); root.masterCapsule = [];
    await assertKeyless("signed wrap-does-not-cover-set", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: true,
    });
  }

  // a recipient-set hash that does not recompute to the listed recipients: checkRecipientSet's final
  // gate rejects a tampered set hash (everything else self-consistent). Its message ("...hash does
  // not match...") maps to the integrity bucket, driving that arm of coarseKeylessReason.
  {
    const root = baseSignedRoot(kit, RID); root.recipientSetHash = hexEncode(new Uint8Array(48));
    await assertKeyless("signed bad-set-hash", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["integrity check failed"], downpipeIdNull: true,
    });
  }

  // shard objects disagree with the declared shardCount: structure passes (zero shards listed) but
  // shardCount claims one, so the completeness check rejects the count mismatch (an integrity-class
  // reason). Signature and structure stay valid; completeness fails.
  {
    const root = baseSignedRoot(kit, RID); root.shardCount = 1;
    await assertKeyless("signed shardcount-mismatch", signedStore(kit, RID, root), RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["integrity check failed"], downpipeIdNull: false,
    });
  }

  // A non-Error value thrown from the store (a bare string). coarseKeylessReason and keylessErrId
  // must handle a non-Error throw without crashing, taking the String(e) arm of their `e instanceof
  // Error ? e.message : String(e)` ternary. The fault is aimed at the COMPLETENESS shard fetch, not
  // the RUNLOG read: checkRunlogFreshness wraps the RUNLOG get in its own try/catch and returns a
  // "RUNLOG absent" result rather than re-throwing, so a RUNLOG-read fault never reaches
  // attestKeyless's catch. The shard fetch in the completeness loop has no such inner guard, so a
  // throw there genuinely surfaces in the completeness catch and is coarsened. The root lists one
  // shard (so the loop runs) and the structure is otherwise intact, so the signature and structure
  // still pass and only completeness fails. A bare string matches none of the reason patterns, so
  // it lands in the catch-all "attestation check failed" bucket.
  {
    const root = oneShardSignedRoot(kit, RID);
    const store = faultShardGet(kit, RID, root, () => {
      // eslint-disable-next-line no-throw-literal
      throw "completeness blew up (bare string, non-Error)"; // exercises the String(e) ternary arm
    });
    await assertKeyless("signed completeness non-Error throw", store, RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: false,
    });
  }

  // The "engine not fully configured" reason bucket: a thrown error whose message matches
  // /missing required configuration/ maps to that coarse reason, the configuration-failure path the
  // keyed restore tiers share. The fault is on the completeness shard fetch (which actually
  // propagates to a catch) rather than the swallowed RUNLOG read, so the message reaches
  // coarseKeylessReason and exercises that regex arm. Signature and structure stay valid.
  {
    const root = oneShardSignedRoot(kit, RID);
    const store = faultShardGet(kit, RID, root, () => {
      throw new Error("missing required configuration: the dest credentials are not pinned");
    });
    await assertKeyless("signed completeness config-missing", store, RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["engine not fully configured"], downpipeIdNull: false,
    });
  }

  // The "freshness check failed" reason bucket (the /RUNLOG|freshness|latest run|stale/ arm of
  // coarseKeylessReason). This arm is only reached when an exception whose message carries that
  // vocabulary is thrown into one of attestKeyless's catches; the keyless freshness step itself does
  // not throw such text (checkRunlogFreshness returns a result), so we drive it through the
  // completeness catch with a destination error that mentions the RUNLOG. This is the same coarse
  // mapping the keyed tiers apply, asserted here so the reason vocabulary stays consistent.
  {
    const root = oneShardSignedRoot(kit, RID);
    const store = faultShardGet(kit, RID, root, () => {
      throw new Error("RUNLOG-adjacent destination failure while fetching the shard");
    });
    await assertKeyless("signed completeness freshness-vocabulary throw", store, RID, kit.verifier, { allowStale: true }, {
      signatureValid: true, complete: false, notRolledBack: false, reasonHas: ["freshness check failed"], downpipeIdNull: false,
    });
  }
}

// openVector opens a positive vendored vector under its bundled keys and returns the verified Run
// plus the store, so a test can take a real opened run and mutate a record copy to drive
// restoreRecord's post-decrypt guards. It is the read-only analogue of validate-reader-chunkrange's
// fixture: the stored bytes are real and verified, only the in-memory record copy is mutated.
async function openVector(name: string, runId: string = DEFAULT_RUN_ID): Promise<{ run: Awaited<ReturnType<typeof openRun>>; store: DirStore }> {
  const dir = join(vectors, name);
  const store = new DirStore(join(dir, "archive"));
  const { identity, verifier } = await loadKeys(dir);
  return { run: await openRun(store, runId, identity, verifier, {}), store };
}

// cloneRecord deep-copies a record's segments so a mutation of the copy never touches the run's own
// record (the same shape validate-reader-chunkrange's withChunkRange relies on).
function cloneRecord(rec: ShardRecord): DeepMutable<ShardRecord> {
  return { ...rec, segments: rec.segments.map((s) => ({ ...s, packed: s.packed ? { ...s.packed } : null })) };
}

// restoreThrows reports whether restoreRecord rejects a (mutated) record. The accept-vs-reject
// outcome is the assertion; the message text is checked separately where it is load-bearing.
async function restoreThrows(run: Awaited<ReturnType<typeof openRun>>, rec: ShardRecord): Promise<boolean> {
  try {
    await run.restoreRecord(rec);
    return false;
  } catch {
    return true;
  }
}

// A self-signed real archive, built once with a signer whose private halves we keep so a test can
// RE-SIGN a one-field mutation of the genuine root. This is the only way to drive the openRun gates
// that fire AFTER the root signature check (runId match, key commitment, the per-shard preamble
// match): a vendored vector cannot ship a validly-signed mutation, and mutating a vendored root in
// place fails at the signature gate before those branches are reached. The archive carries one
// non-secret and one secrets record so both segment-open paths are present.
interface ReSignKit {
  objects: Map<string, Uint8Array>;
  signer: import("../src/format/writer.ts").Signer;
  verifier: HybridVerifier;
  identity: HybridRecipientPrivate;
  runId: string;
  // master is the run master used to seal this archive. It is surfaced so the crafted-shard tests can
  // re-derive the same manifest-wrap key the writer used and seal a deliberately malformed shard body.
  master: Uint8Array;
}

async function buildReSignKit(): Promise<ReSignKit> {
  const { x25519 } = await import("@noble/curves/ed25519.js");
  const { buildArchive } = await import("../src/format/writer.ts");
  const { loadSigner, verifierFrom } = await import("../src/keys-env.ts");
  const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
  const runId = DEFAULT_RUN_ID;
  const signer = await loadSigner(b64urlEncode(concatBytes(rand(32), rand(32))));
  const verifier = verifierFrom(signer);
  const xk = x25519.keygen();
  const seed = rand(64);
  const bg = { role: "break-glass", pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } };
  const identity = parseIdentity(concatBytes(xk.secretKey, seed));
  const master = rand(32);
  const objects = await buildArchive({
    downpipeId: "dp_reader_test",
    downpipeName: "reader-test",
    cadence: "3600s",
    runId,
    master,
    recipients: [bg],
    signer,
    records: [
      { sourceType: "kv", name: "kv-rec", namespace: "ns", value: utf8("a non-secret value to seal") },
      { sourceType: "secrets", name: "sec-rec", value: utf8("a-secret-token") },
    ],
    windowStart: "2026-06-10T00:00:00.000Z",
    windowEnd: "2026-06-10T00:00:01.000Z",
    createdAt: "2026-06-10T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  return { objects, signer, verifier, identity, runId, master };
}

// concatBytes joins byte arrays (a tiny local helper so buildReSignKit does not need a separate
// import; the crypto concat is the canonical one but is not in this file's import set).
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// reSignedRootStore serves the kit's real archive but with a one-field MUTATION of the root,
// re-signed under the kit's signer so the signature still verifies. Every other object (shards,
// segments, RUNLOG, recovery bundle) is the genuine sealed byte, so openRun proceeds past the
// signature gate and rejects at the gate the mutation targets. The unmutated control proves the
// re-sign harness itself is sound, so a later rejection is the mutation, not a broken scaffold.
function reSignedRootStore(kit: ReSignKit, mutate: (r: DeepMutable<RootManifest>) => void): ObjectStore {
  const root = JSON.parse(new TextDecoder().decode(kit.objects.get(`run/${kit.runId}/root.manifest.json`)!)) as DeepMutable<RootManifest>;
  mutate(root);
  const rootBytes = canonicalJSON(root);
  let sigBytes: Uint8Array | null = null;
  return {
    async get(key: string): Promise<Uint8Array> {
      if (key === `run/${kit.runId}/root.manifest.json`) return rootBytes;
      if (key === `run/${kit.runId}/root.manifest.json.sig`) {
        if (!sigBytes) sigBytes = utf8(b64urlEncode(await hybridSign(kit.signer.edPrivate, kit.signer.mldsaSecret, rootBytes)));
        return sigBytes;
      }
      const v = kit.objects.get(key);
      if (!v) throw new Error(`object ${key} is missing`);
      return v;
    },
  };
}

// openThrows reports whether openRun rejects under the given store/options. Accept-vs-reject is the
// assertion; the message is checked where the gate identity matters.
async function openThrows(store: ObjectStore, kit: ReSignKit, opts: OpenOpts = {}): Promise<{ threw: boolean; message: string }> {
  try {
    await openRun(store, kit.runId, kit.identity, kit.verifier, opts);
    return { threw: false, message: "" };
  } catch (e) {
    return { threw: true, message: e instanceof Error ? e.message : String(e) };
  }
}

// runReaderErrorPaths drives the verification-failure branches of openRun and restoreRecord that the
// open/reject corpus scan above leaves uncovered: each is the THROW arm of a guard whose condition
// is false for every well-formed vector, so it is reached only by feeding the reader a mutated copy
// of a genuinely-sealed run. These are real rejections (the same structural-error path the reader
// uses in production), and each asserts the gate identity, not merely that something threw. The two
// strategies mirror the existing tests: a re-signed one-field root mutation for the gates after the
// signature check, and an in-memory record-copy mutation for restoreRecord's post-decrypt guards.
async function runReaderErrorPaths(): Promise<void> {
  console.log("\nreader verification-failure paths (mutated copies of real sealed runs):");

  // ---- openRun gates that fire after the root signature check (re-signed root mutations) ----
  const kit = await buildReSignKit();

  // Control: the genuine root, re-signed unmutated, still opens. This proves the re-sign harness is
  // sound, so a rejection below is the mutation rather than a broken signature.
  {
    const r = await openThrows(reSignedRootStore(kit, () => {}), kit);
    ok("re-sign control: an unmutated re-signed root still opens", !r.threw);
    if (r.threw) console.log(`       unexpected throw: ${r.message}`);
  }

  // manifest runId does not match the requested run id (openRun's `root.runId !== runID` gate). A
  // validly-signed manifest bound to a different run must be rejected, not opened against the wrong
  // id.
  {
    const r = await openThrows(reSignedRootStore(kit, (root) => { root.runId = "01ARZ3NDEKTSV4RRFFQ69G5FZZ"; }), kit);
    ok("openRun rejects a signed manifest whose runId does not match the requested run", r.threw && /runId does not match/i.test(r.message));
    if (r.threw && !/runId does not match/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // The shard preamble must agree with the signed root. Mutating the root's formatVersion to a
  // different (still major-1, so the version gate passes) minor leaves the sealed shard preamble at
  // the original version, so openRun's preamble cross-check rejects the disagreement. This reaches
  // the preamble-mismatch throw, which a well-formed run never trips.
  {
    const r = await openThrows(reSignedRootStore(kit, (root) => { root.formatVersion = "downpipe/0.1.5"; }), kit);
    ok("openRun rejects when a shard preamble disagrees with the signed root", r.threw && /preamble does not match/i.test(r.message));
    if (r.threw && !/preamble does not match/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // The freshness gate, when requested, throws on a non-clean result rather than returning. The
  // stale-run vector is the latest's predecessor, so opening it with verifyFreshness and WITHOUT
  // allowStale must throw "freshness: ...". This drives openRun's `if (!freshness.ok) throw` arm,
  // distinct from the corpus scan's freshness negatives which are asserted only at reject-time.
  {
    const dir = join(vectors, "stale-run");
    const store = new DirStore(join(dir, "archive"));
    const { identity, verifier } = await loadKeys(dir);
    let threw = false;
    let message = "";
    try {
      await openRun(store, DEFAULT_RUN_ID, identity, verifier, { verifyFreshness: true });
    } catch (e) {
      threw = true;
      message = e instanceof Error ? e.message : String(e);
    }
    ok("openRun throws on a failed freshness check when verifyFreshness is set and stale is not allowed", threw && /freshness/i.test(message));
    if (threw && !/freshness/i.test(message)) console.log(`       message: ${message}`);
  }

  // ---- restoreRecord post-decrypt guards (in-memory record-copy mutations of real runs) ----

  // A secrets record's recordId must be exactly 16 bytes. Open a real secrets archive, then shorten
  // the recordId on a copy: the segment still decrypts, but restoreRecord's secrets-id length guard
  // rejects it before deriving the per-record key.
  {
    const { run } = await openVector("secrets-no-dedup");
    const sec = run.records.find((r) => r.sourceType === "secrets")!;
    ok("secrets fixture record opens", !!sec && sec.recordId.length === 16);
    const badId = cloneRecord(sec);
    badId.recordId = "tooShort";
    ok("restoreRecord rejects a secrets record whose recordId is not 16 bytes", await restoreThrows(run, badId));
  }

  // A secrets record's recordSalt must be present and 16 bytes. Dropping it exercises the
  // `recordSalt ?? ""` nullish fallback (which yields an empty salt) and the subsequent salt-length
  // guard, so a secrets record stripped of its salt is rejected rather than decrypted with a guessed
  // salt.
  {
    const { run } = await openVector("secrets-no-dedup");
    const sec = run.records.find((r) => r.sourceType === "secrets")!;
    const noSalt = cloneRecord(sec);
    delete noSalt.recordSalt;
    ok("restoreRecord rejects a secrets record with no recordSalt (nullish fallback then length guard)", await restoreThrows(run, noSalt));
  }

  // A packed slice must lie within the assembled value. Open the real packed vector, then push the
  // packed offset far past the segment's decrypted length on a copy: the bounds guard rejects the
  // out-of-range slice rather than reading past the buffer.
  {
    const { run } = await openVector("seg-packed");
    const packedRec = run.records.find((r) => r.segments.length === 1 && r.segments[0]!.packed)!;
    ok("packed fixture record opens with a packed slice", !!packedRec);
    const badPacked = cloneRecord(packedRec);
    badPacked.segments[0]!.packed = { offset: 1_000_000, length: 1 };
    ok("restoreRecord rejects a packed slice whose offset is out of range", await restoreThrows(run, badPacked));
  }

  // A packed slice is only meaningful on a single-segment record. Open the real multi-segment
  // vector and attach a packed slice to one segment of the chain on a copy: restoreRecord takes the
  // multi-segment branch and rejects the stray packed field rather than silently ignoring it.
  {
    const { run } = await openVector("seg-multi-segment");
    const chain = run.records.find((r) => r.segments.length > 1)!;
    ok("multi-segment fixture record opens with more than one segment", !!chain && chain.segments.length > 1);
    const mixed = cloneRecord(chain);
    mixed.segments[0]!.packed = { offset: 0, length: 1 };
    ok("restoreRecord rejects a packed slice on a multi-segment chain", await restoreThrows(run, mixed) && (await restoreRejectMessage(run, mixed)).includes("multi-segment"));
  }

  // A gzip member that decompresses past the declared plaintextSize is rejected. Open the real gzip
  // vector, then lower the declared plaintextSize on a copy below the true decompressed length: the
  // buffered gunzip's size cap fires before the over-long output is accepted.
  {
    const { run } = await openVector("gzip-codec");
    const gz = run.records.find((r) => r.codec === "gzip")!;
    ok("gzip fixture record opens with the gzip codec", !!gz && gz.codec === "gzip" && gz.plaintextSize > 16);
    const undersized = cloneRecord(gz);
    undersized.plaintextSize = 8; // far below the real decompressed size
    ok("restoreRecord rejects a gzip record whose decompressed output exceeds the declared size", await restoreThrows(run, undersized));
  }

  // A segment object key must decode to a 48-byte segment id. Point a copy's segment at a key whose
  // basename is not 48 bytes of hex: segIDFromObject rejects the malformed object key before any
  // decryption is attempted.
  {
    const { run } = await openVector("master-capsule");
    const rec = run.records[0]!;
    const badObject = cloneRecord(rec);
    badObject.segments[0]!.object = "run/x/seg/00.seg"; // basename "00" decodes to 1 byte, not 48
    ok("restoreRecord rejects a segment object key that does not decode to a 48-byte id", await restoreThrows(run, badObject));
  }

  // ---- attestKeyless freshness catch (an exception escaping checkRunlogFreshness) ----

  // attestKeyless wraps the freshness check in a catch, but checkRunlogFreshness swallows a RUNLOG
  // READ failure into a result. A throw escapes only LATER: a present RUNLOG with a malformed (non
  // base64url) signature makes the signature decode throw after the read try/catch, which propagates
  // to attestKeyless's freshness catch. signature/structure/completeness still pass; the freshness
  // catch produces a coarse reason and notRolledBack is honestly false.
  {
    const dir = join(vectors, "master-capsule");
    const real = new DirStore(join(dir, "archive"));
    const verifier = await loadVerifier(dir);
    const store: ObjectStore = {
      async get(key: string): Promise<Uint8Array> {
        if (key === "_RECOVERY/RUNLOG.sig") return utf8("@@@not-base64url@@@"); // present but undecodable
        return real.get(key);
      },
    };
    await assertKeyless("keyless RUNLOG signature undecodable (freshness catch)", store, DEFAULT_RUN_ID, verifier, { allowStale: true }, {
      signatureValid: true, complete: true, notRolledBack: false, reasonHas: ["attestation check failed"], downpipeIdNull: false,
    });
  }

  // ---- shard-body gates inside openRun (a re-sealed shard with a deliberately malformed manifest) ----
  //
  // parseShard's structural guards and openRun's per-record codec and recordHash checks fire on the
  // DECRYPTED shard body, which a vendored vector cannot carry malformed (its shard is sealed and its
  // hash is in the signed root). We have the run master from buildReSignKit, so we can derive the same
  // manifest-wrap key the writer used, seal an arbitrary NDJSON shard body under it, point the
  // re-signed root's single shard at that object with its real hash, and let openRun decrypt and
  // reject at the targeted gate. Every byte the reader checks (the shard envelope, the shard hash, the
  // root signature) is genuine; only the plaintext manifest inside is malformed, which is exactly the
  // class of corruption these guards exist to catch.
  const craftKit = await buildReSignKit();

  // craftShardStore seals the given NDJSON shard body under the run's manifest-wrap key, frames it as a
  // .dpe object, and serves it under a re-signed root whose single shard lists that object's real
  // hash. mutateRoot adjusts the root's declared counts (and envelope codec where a case needs it) so
  // only the targeted gate fires, not an earlier count or codec mismatch.
  async function craftShardStore(shardBody: string, mutateRoot: (r: DeepMutable<RootManifest>) => void): Promise<ObjectStore> {
    const runIDBytes = decodeULID(craftKit.runId);
    const mk = await deriveMK(craftKit.master, runIDBytes);
    const shardWrap = await deriveManifestWrapKey(mk, runIDBytes, "00000");
    const sealed = frame(MAGIC_DPE, await sealStream(shardWrap, utf8(shardBody), crypto.getRandomValues(new Uint8Array(16))));
    const shardHash = hexEncode(await sha384(sealed));
    const root = JSON.parse(new TextDecoder().decode(craftKit.objects.get(`run/${craftKit.runId}/root.manifest.json`)!)) as DeepMutable<RootManifest>;
    root.shards = [{ id: "00000", object: `run/${craftKit.runId}/manifest/00000.dpe`, sha384: shardHash }];
    root.shardCount = 1;
    mutateRoot(root);
    const rootBytes = canonicalJSON(root);
    let sigBytes: Uint8Array | null = null;
    return {
      async get(key: string): Promise<Uint8Array> {
        if (key === `run/${craftKit.runId}/manifest/00000.dpe`) return sealed;
        if (key === `run/${craftKit.runId}/root.manifest.json`) return rootBytes;
        if (key === `run/${craftKit.runId}/root.manifest.json.sig`) {
          if (!sigBytes) sigBytes = utf8(b64urlEncode(await hybridSign(craftKit.signer.edPrivate, craftKit.signer.mldsaSecret, rootBytes)));
          return sigBytes;
        }
        const v = craftKit.objects.get(key);
        if (!v) throw new Error(`object ${key} is missing`);
        return v;
      },
    };
  }

  // matchingPreamble is a shard preamble whose runId, shardId and formatVersion agree with the
  // re-signed root, so openRun's preamble cross-check passes and a later record-level gate (codec,
  // recordHash) or the record-count gate is what fires, not the preamble mismatch.
  function matchingPreamble(realRoot: RootManifest, recordCount: number): string {
    return canonicalJSONLine({
      kind: "preamble",
      formatVersion: realRoot.formatVersion,
      runId: craftKit.runId,
      shardId: "00000",
      manifestCodec: "none",
      downpipe: { name: "reader-test", cadence: "3600s" },
      source: { type: "kv" },
      window: { start: "2026-06-10T00:00:00.000Z", end: "2026-06-10T00:00:01.000Z" },
      consistency: "crawl",
      recordCountInShard: recordCount,
    });
  }

  const realCraftRoot = JSON.parse(new TextDecoder().decode(craftKit.objects.get(`run/${craftKit.runId}/root.manifest.json`)!)) as RootManifest;
  const segHex = "0".repeat(96); // a 48-byte (96 hex) segment id basename, a structurally valid object key
  const segObject = `run/${craftKit.runId}/seg/${segHex}.seg`;

  // An empty shard manifest (no lines): parseShard rejects a shard with nothing to parse.
  {
    const store = await craftShardStore("", (r) => { r.declaredRecordCount = 0; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a shard whose manifest is empty", r.threw && /shard manifest is empty/i.test(r.message));
    if (r.threw && !/shard manifest is empty/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // First shard line is not a preamble: parseShard requires the first line's kind to be "preamble".
  {
    const notPreamble = canonicalJSONLine({ kind: "record", recordCountInShard: 0 });
    const store = await craftShardStore(notPreamble + "\n", (r) => { r.declaredRecordCount = 0; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a shard whose first line is not a preamble", r.threw && /first shard line is not a preamble/i.test(r.message));
    if (r.threw && !/first shard line is not a preamble/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // A non-record line after a valid preamble: parseShard requires every following line's kind to be
  // "record".
  {
    const body = matchingPreamble(realCraftRoot, 1) + "\n" + canonicalJSONLine({ kind: "footer", plaintextSize: 0 }) + "\n";
    const store = await craftShardStore(body, (r) => { r.declaredRecordCount = 1; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a shard whose body line is not a record", r.threw && /shard line is not a record/i.test(r.message));
    if (r.threw && !/shard line is not a record/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // Preamble record count disagrees with the number of record lines: parseShard cross-checks the
  // declared recordCountInShard against the lines actually present.
  {
    const rec = canonicalJSONLine({ kind: "record", plaintextSize: 0 });
    const body = matchingPreamble(realCraftRoot, 2) + "\n" + rec + "\n"; // says 2, carries 1
    const store = await craftShardStore(body, (r) => { r.declaredRecordCount = 1; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a shard whose preamble record count disagrees with its lines", r.threw && /shard record count mismatch/i.test(r.message));
    if (r.threw && !/shard record count mismatch/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // A record whose codec differs from the envelope codec: openRun rejects the per-record codec
  // disagreement (the run-wide-codec invariant). The envelope codec stays "none"; the record claims
  // "gzip".
  {
    const rec = craftRecordLine({ sourceType: "kv", codec: "gzip", segObject });
    const body = matchingPreamble(realCraftRoot, 1) + "\n" + rec + "\n";
    const store = await craftShardStore(body, (r) => { r.declaredRecordCount = 1; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a record whose codec differs from the envelope codec", r.threw && /differs from the envelope codec/i.test(r.message));
    if (r.threw && !/differs from the envelope codec/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // A secrets record carrying a codec: even when the record and envelope codecs agree (both "gzip"),
  // a secrets record must never be compressed, so openRun rejects it on the secrets-specific gate.
  {
    const rec = craftRecordLine({ sourceType: "secrets", codec: "gzip", segObject, recordId: "0123456789abcdef", recordSalt: b64urlEncode(new Uint8Array(16)) });
    const body = matchingPreamble(realCraftRoot, 1) + "\n" + rec + "\n";
    const store = await craftShardStore(body, (r) => { r.declaredRecordCount = 1; r.envelope.codec = "gzip"; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a secrets record that is compressed (section 5.2, 12.4)", r.threw && /must not be compressed/i.test(r.message));
    if (r.threw && !/must not be compressed/i.test(r.message)) console.log(`       message: ${r.message}`);
  }

  // A record whose recordHash does not recompute from its fields: openRun recomputes each record's
  // Merkle-leaf hash and rejects a forged recordHash before it ever reaches the Merkle root check.
  {
    const rec = craftRecordLine({ sourceType: "kv", codec: "none", segObject, recordHash: "ff".repeat(48) });
    const body = matchingPreamble(realCraftRoot, 1) + "\n" + rec + "\n";
    const store = await craftShardStore(body, (r) => { r.declaredRecordCount = 1; });
    const r = await openThrows(store, craftKit);
    ok("openRun rejects a record whose recordHash does not match its fields", r.threw && /hash does not match its fields/i.test(r.message));
    if (r.threw && !/hash does not match its fields/i.test(r.message)) console.log(`       message: ${r.message}`);
  }
}

// runRollbackPinAttestation proves the anti-rollback replay exploit end to end, over the SAME
// store fixture, on both tiers: downpipe D's RUNLOG legitimately advances from a real sealed run
// (kit.runId, index 1) to a later run (index 2, synthetic -- only its RUNLOG entry matters here). An
// attacker who can write to the destination overwrites _RECOVERY/RUNLOG(+.sig) with the EXACT bytes
// captured right after the first run sealed: a pure replay of genuinely-signed bytes, no forging and
// no signing key. The replayed document is itself internally consistent (detectChainAnomaly finds
// nothing), so the chain-anomaly signal alone cannot catch it -- only pinning
// minRunlogIndex to an out-of-band high-water mark (e.g. the scheduler DO's own
// runlogCounter) does.
async function runRollbackPinAttestation(): Promise<void> {
  console.log("\nrollback pin: a clean whole-document RUNLOG replay, keyless + keyed:");
  const kit = await buildReSignKit();
  const laterRunId = "01ARZ3NDEKTSV4RRFFQ69G5ZZ2";
  const downpipeId = "dp_reader_test"; // matches buildReSignKit's sealed root

  const r1Entry: RunlogEntry = { index: 1, runId: kit.runId, downpipeId, time: "2026-06-10T00:00:01.000Z", recordCount: 2, prevRunId: null, status: "active" };
  const r2Entry: RunlogEntry = { index: 2, runId: laterRunId, downpipeId, time: "2026-06-10T01:00:00.000Z", recordCount: 0, prevRunId: kit.runId, status: "active" };
  const runlogAtT0 = concatBytes(canonicalJSON(r1Entry), utf8("\n"));
  const runlogAtT1 = concatBytes(canonicalJSON(r1Entry), utf8("\n"), canonicalJSON(r2Entry), utf8("\n"));
  const sigAtT0 = utf8(b64urlEncode(await hybridSign(kit.signer.edPrivate, kit.signer.mldsaSecret, runlogAtT0)));
  const sigAtT1 = utf8(b64urlEncode(await hybridSign(kit.signer.edPrivate, kit.signer.mldsaSecret, runlogAtT1)));

  // storeWith serves the kit's REAL, unmutated archive (root/shards/segments all genuinely signed,
  // untouched) but with _RECOVERY/RUNLOG(+.sig) swapped for the given bytes, so a test can serve
  // either the stale t0 snapshot (the attacker's replay) or the genuine current t1 document (control).
  function storeWith(runlog: Uint8Array, sig: Uint8Array): ObjectStore {
    return {
      async get(key: string): Promise<Uint8Array> {
        if (key === "_RECOVERY/RUNLOG") return runlog;
        if (key === "_RECOVERY/RUNLOG.sig") return sig;
        const v = kit.objects.get(key);
        if (!v) throw new Error(`object ${key} is missing`);
        return v;
      },
    };
  }
  const replayStore = storeWith(runlogAtT0, sigAtT0);
  const currentStore = storeWith(runlogAtT1, sigAtT1);

  // Control: against the CURRENT (t1) document, both tiers honestly reject the first run as rolled
  // back (a real newer run for the same downpipe exists), proving the fixture itself is sound before
  // the replay case below. attestKeyless's notRolledBack ANDs isLatestForDownpipe, so it reflects
  // ordinary staleness even under allowStale:true; openRun's own throw does not (allowStale:true is
  // its documented "open an older run on purpose" contract, unaffected by this fix), so exercising it
  // here needs allowStale:false, matching the existing "stale-run" sibling test above.
  await assertKeyless("rollback-pin control: keyless against the CURRENT RUNLOG is honestly rolled back", currentStore, kit.runId, kit.verifier, { allowStale: true }, {
    signatureValid: true, complete: true, notRolledBack: false, reasonHas: ["latest"], downpipeIdNull: false,
  });
  {
    const r = await openThrows(currentStore, kit, { verifyFreshness: true, allowStale: false });
    ok("rollback-pin control: openRun against the CURRENT RUNLOG honestly rejects as not-latest (allowStale:false)", r.threw && /freshness/i.test(r.message));
  }

  // The exploit exactly as described, with NO minRunlogIndex pin (every real caller before this fix):
  // the replayed document carries no chain anomaly, so both tiers still read clean -- the residual gap
  // that case (A) alone cannot close.
  await assertKeyless("rollback-pin: replayed RUNLOG with NO pin still reads clean (the exploit)", replayStore, kit.runId, kit.verifier, { allowStale: true }, {
    signatureValid: true, complete: true, notRolledBack: true, reasonNull: true,
  });
  {
    const r = await openThrows(replayStore, kit, { verifyFreshness: true, allowStale: true });
    ok("rollback-pin: openRun on the replayed RUNLOG with NO pin still opens (the exploit)", !r.threw);
  }

  // (B) closes it: pin minRunlogIndex to 2 (simulating the scheduler DO's live runlogCounter, which
  // has already moved past the later run), exactly as router-restore.ts's runKeylessAttest now does
  // via GET /scheduler-signals. The replayed document's own global max (1) falls below the pin, so
  // both tiers now correctly reject it, even though the replay itself is clean.
  await assertKeyless("rollback-pin: replayed RUNLOG WITH the live-counter pin is rejected", replayStore, kit.runId, kit.verifier, { allowStale: true, minRunlogIndex: 2 }, {
    signatureValid: true, complete: true, notRolledBack: false, reasonHas: ["min-runlog-index pin"], downpipeIdNull: false,
  });
  {
    const r = await openThrows(replayStore, kit, { verifyFreshness: true, allowStale: true, minRunlogIndex: 2 });
    ok("rollback-pin: openRun on the replayed RUNLOG WITH the live-counter pin rejects", r.threw && /freshness/i.test(r.message));
  }
}

// runUncheckedFreshnessRefusal: a freshness check that COULD NOT BE RUN must never read as a clean chain.
//
// Every early return in checkRunlogFreshness shared one helper that hardcoded rollbackDetected:false and set
// ok from allowStale, so the five worst inputs (the RUNLOG absent, its signature not verifying, the run not in
// it, and either disagreement with the signed root) reported "no rollback" and, because every engine caller
// passes allowStale:true, opened the run. A benign chain merely below a min-index pin, the least severe of the
// six, was the one that refused: the signal was inverted by severity and deleting the document was the
// quietest way through. This drives the whole table through the PRODUCTION openRun over a genuinely sealed
// archive with a REAL hybrid signature over the RUNLOG bytes, in both stale postures.
//
// THE TWO CONTROLS ARE LOAD-BEARING and are asserted alongside the refusals: a clean latest run still opens
// with stale tolerance on, and the tampered signature already refused without it. A fix that simply refused
// everything would pass the five refusals and fail both controls. The below-pin case keeps its own verdict
// (rollbackDetected true with checked TRUE) so it stays distinguishable from a forgery (checked FALSE): a
// finding and an unknown are different facts and an operator acts differently on each.
async function runUncheckedFreshnessRefusal(): Promise<void> {
  console.log("\nunchecked freshness (a check that could not run must refuse, not report a clean chain):");
  const kit = await buildReSignKit();
  const downpipeId = "dp_reader_test"; // matches buildReSignKit's sealed root
  const otherRunId = "01ARZ3NDEKTSV4RRFFQ69G5ZZ3";
  const root = JSON.parse(new TextDecoder().decode(kit.objects.get(`run/${kit.runId}/root.manifest.json`)!)) as RootManifest;

  // A genuinely signed RUNLOG over the given entries: the signature gate PASSES for every case below except
  // the deliberately tampered one, so each refusal is the gate under test rather than a broken scaffold.
  async function signedRunlog(entries: RunlogEntry[]): Promise<{ log: Uint8Array; sig: Uint8Array }> {
    const log = concatBytes(...entries.map((e) => concatBytes(canonicalJSON(e), utf8("\n"))));
    return { log, sig: utf8(b64urlEncode(await hybridSign(kit.signer.edPrivate, kit.signer.mldsaSecret, log))) };
  }
  // The downpipe is overridable so a second, busier downpipe can share the document: the min-index pin is
  // deliberately compared against the ACCOUNT-GLOBAL max rather than this downpipe's, and that is only
  // observable when the two differ.
  function entry(index: number, runId: string, prevRunId: string | null, dp: string = downpipeId): RunlogEntry {
    return { index, runId, downpipeId: dp, time: "2026-06-10T00:00:01.000Z", recordCount: 2, prevRunId, status: "active" };
  }
  // storeWith serves the kit's real, unmutated archive with the RUNLOG pair swapped. A null body means the
  // object is ABSENT and the store throws, exactly as a destination does on a deleted object.
  function storeWith(log: Uint8Array | null, sig: Uint8Array | null): ObjectStore {
    return {
      async get(key: string): Promise<Uint8Array> {
        if (key === "_RECOVERY/RUNLOG") {
          if (log === null) throw new Error("object _RECOVERY/RUNLOG is missing");
          return log;
        }
        if (key === "_RECOVERY/RUNLOG.sig") {
          if (sig === null) throw new Error("object _RECOVERY/RUNLOG.sig is missing");
          return sig;
        }
        const v = kit.objects.get(key);
        if (!v) throw new Error(`object ${key} is missing`);
        return v;
      },
    };
  }

  const clean = await signedRunlog([entry(1, kit.runId, null)]);
  // One flipped character of the base64url signature over UNCHANGED bytes: the forgery case, not a bit-flip.
  const forged = new Uint8Array(clean.sig);
  forged[0] = forged[0] === 65 ? 66 : 65;

  const cases: { label: string; store: ObjectStore; anomaly: string | null }[] = [
    { label: "a tampered RUNLOG signature", store: storeWith(clean.log, forged), anomaly: "sig-invalid" },
    { label: "an absent RUNLOG", store: storeWith(null, clean.sig), anomaly: "runlog-absent" },
    { label: "a RUNLOG that does not carry the run", store: storeWith((await signedRunlog([entry(1, otherRunId, null)])).log, (await signedRunlog([entry(1, otherRunId, null)])).sig), anomaly: "run-missing" },
    { label: "an index that disagrees with the signed root", store: storeWith((await signedRunlog([entry(2, kit.runId, null)])).log, (await signedRunlog([entry(2, kit.runId, null)])).sig), anomaly: "root-disagreement" },
  ];

  for (const c of cases) {
    drainIntegrityFaultLedger();
    const f = await checkRunlogFreshness(c.store, kit.runId, root, kit.verifier, { allowStale: true });
    const rows = drainIntegrityFaultLedger().runlogAnomalies;
    ok(`${c.label} does not report the absence of a rollback (rollbackDetected true, checked false, ok false under allowStale)`, f.rollbackDetected === true && f.checked === false && f.ok === false);
    // THE REST OF THE UNCHECKED SHAPE, and it is not decoration. isLatestForDownpipe false is the invariant
    // that keeps attestKeyless OUT of this defect's blast radius: it ANDs that field, so its verdict never
    // depends on the broken one. maxIndexForDownpipe 0 says no maximum was
    // observed rather than inventing one, and runlogIndex carries the index the SIGNED ROOT claims for this
    // run, which is the one number a support row has when the RUNLOG itself could not be read.
    ok(`${c.label} reports the honest unchecked shape (not latest, no observed max, the root's own index)`, f.isLatestForDownpipe === false && f.maxIndexForDownpipe === 0 && f.runlogIndex === root.freshness.runlogIndex);
    const r = await openThrows(c.store, kit, { verifyFreshness: true, allowStale: true });
    ok(`openRun REFUSES ${c.label} with stale tolerance on`, r.threw && /freshness/i.test(r.message));
    // The forensic trail matters here: the highest-stakes question the product answers (was our history
    // rewritten, or did the destination lose an object?) must never start with nothing at all.
    ok(`${c.label} leaves a forensic row (${c.anomaly})`, rows.some((a) => a.kind === c.anomaly));
    // The keyless tier was ALREADY correct here (it ANDs isLatestForDownpipe, false in every one of these
    // states), and this fix must not have moved it. Asserted rather than assumed.
    const att = await attestKeyless(c.store, kit.runId, kit.verifier, { allowStale: true });
    ok(`attestKeyless still reports ${c.label} as rolled back (unchanged by this fix)`, att.notRolledBack === false && (att.reason ?? "").length > 0);
  }

  // The index disagreement carries the DISAGREEING PAIR, which is the whole finding: the index the RUNLOG
  // holds for this run against the index its signed root claims.
  {
    const bad = await signedRunlog([entry(2, kit.runId, null)]);
    drainIntegrityFaultLedger();
    await checkRunlogFreshness(storeWith(bad.log, bad.sig), kit.runId, root, kit.verifier, { allowStale: true });
    const row = drainIntegrityFaultLedger().runlogAnomalies.find((a) => a.kind === "root-disagreement");
    ok("the index disagreement records the pair the two signed documents disagree on", row?.indexA === 2 && row?.indexB === 1);
  }

  // THE ONE DISAGREEMENT THAT MUST NOT REFUSE, asserted so a later tightening cannot take it silently. A
  // prevRunId that disagrees with the signed root is a state the ENGINE ITSELF writes: appendRunlog's
  // relinkLocalPrev links each destination's entry to that destination's own tail, so a replica that skipped
  // a run the primary holds carries a copied root prev that legitimately differs from its relinked entry
  // (pipeline.ts destinationLocalPrev, residuals 1 and 2). It is a check that RAN (checked true), it keeps its
  // note, it now leaves a forensic row, and it still opens under stale tolerance, because refusing it would
  // block restore from exactly the diverged replica a 3-2-1 restore reaches for when the primary is gone.
  {
    const diverged = await signedRunlog([entry(1, kit.runId, otherRunId)]);
    drainIntegrityFaultLedger();
    const f = await checkRunlogFreshness(storeWith(diverged.log, diverged.sig), kit.runId, root, kit.verifier, { allowStale: true });
    const rows = drainIntegrityFaultLedger().runlogAnomalies;
    ok("a prevRunId disagreement is a check that RAN, keeping its benign note and its verdict", f.checked === true && f.rollbackDetected === false && f.ok === true && /disagrees with the signed root/.test(f.reason ?? ""));
    ok("a prevRunId disagreement still leaves a forensic row (root-disagreement)", rows.some((a) => a.kind === "root-disagreement"));
    const r = await openThrows(storeWith(diverged.log, diverged.sig), kit, { verifyFreshness: true, allowStale: true });
    ok("openRun still opens a relink-diverged replica under stale tolerance (3-2-1 restore is not blocked)", !r.threw);
    // AND IT IS STILL GATED ON THAT TOLERANCE. The branch reads `ok: !!opts.allowStale`, and the one caller
    // that does NOT acknowledge staleness is the hourly canary (canary/cycle.ts passes allowStale:false), so
    // a canary landing on a diverged replica must report it rather than pass. Nothing asserted the negative
    // half: a mutation hardcoding ok:true here survived all 51 suites, which would have made the canary
    // silently green on the one destination shape it exists to notice.
    const strict = await checkRunlogFreshness(storeWith(diverged.log, diverged.sig), kit.runId, root, kit.verifier, {});
    ok("a prevRunId disagreement is NOT ok without stale tolerance (the canary still sees it)", strict.ok === false && strict.checked === true && strict.rollbackDetected === false);
  }

  // THE CHAIN-ANOMALY BRANCH IS A FINDING, NOT AN UNKNOWN, and that is what `checked` is for. A duplicated
  // index is positive proof the log was rewritten or corrupted: the check RAN and reached a verdict, so it
  // reports checked TRUE beside rollbackDetected TRUE, which is exactly the pairing that distinguishes it
  // from a forged signature (rollbackDetected true, checked FALSE). validate-runlog-chain.ts already drives
  // every anomaly shape against the production detector, but it asserts on ok and the reason only: the file
  // contains zero occurrences of either `rollbackDetected` or `checked`, so a mutation flipping this branch's
  // checked to false survived every suite. This is the HI-05 unconditional signal, on the branch the ASVS
  // remediation guards.
  {
    const dup = await signedRunlog([entry(1, kit.runId, null), entry(1, otherRunId, kit.runId)]);
    const f = await checkRunlogFreshness(storeWith(dup.log, dup.sig), kit.runId, root, kit.verifier, { allowStale: true });
    ok("a duplicated RUNLOG index is a FINDING (rollbackDetected true, checked TRUE), not an unknown", f.rollbackDetected === true && f.checked === true);
    const r = await openThrows(storeWith(dup.log, dup.sig), kit, { verifyFreshness: true, allowStale: true });
    ok("openRun REFUSES a duplicated RUNLOG index with stale tolerance on", r.threw && /freshness/i.test(r.message));
  }

  // THE PIN IS A FLOOR, NOT A CEILING. `runlogMax < minRunlogIndex` rejects a document that has fallen BELOW
  // the out-of-band high-water mark; a document sitting exactly ON it is the healthy steady state, because
  // the pin is set FROM the observed maximum (the scheduler DO's live runlogCounter). Widening the comparison
  // to `<=` would refuse every archive at its own high-water mark, which is most of them, and the boundary
  // was untested in both directions.
  {
    const f = await checkRunlogFreshness(storeWith(clean.log, clean.sig), kit.runId, root, kit.verifier, { allowStale: true, minRunlogIndex: 1 });
    ok("a chain sitting exactly ON the min-index pin is not below it (the pin is a floor)", f.rollbackDetected === false && f.ok === true);
  }

  // AND THE PIN IS COMPARED AGAINST THE ACCOUNT-GLOBAL MAX, NOT THIS DOWNPIPE'S. Indices are allocated from
  // one account-wide counter, so a pin taken from the account high-water mark would be defeated by every
  // low-traffic downpipe if the comparison used the per-downpipe maximum: this run is index 1 of its own
  // downpipe while the document as a whole reaches 9, and a pin of 9 must clear. Every existing fixture holds
  // exactly one downpipe, so the two maxima are otherwise indistinguishable, and a pin that quietly used the
  // wrong one would be worse than no pin, because the operator believes a replay is covered.
  {
    const busy = await signedRunlog([entry(1, kit.runId, null), entry(9, otherRunId, null, "dp_reader_other")]);
    const f = await checkRunlogFreshness(storeWith(busy.log, busy.sig), kit.runId, root, kit.verifier, { allowStale: true, minRunlogIndex: 9 });
    ok("the min-index pin clears against the ACCOUNT-GLOBAL max, not this downpipe's (1 here, 9 in the document)", f.rollbackDetected === false && f.ok === true && f.maxIndexForDownpipe === 1);
  }

  // ORDINARY STALENESS IS THE ONE THING rollbackDetected MUST NOT COVER. A legitimately older run in a
  // verified, clean chain is precisely what allowStale exists to proceed past, so it reports a check that RAN
  // (checked true) and NO rollback, and refuses only because staleness was not acknowledged. Both halves were
  // unasserted: making ordinary staleness report a rollback would refuse every stale-tolerant restore in
  // the product.
  {
    const two = await signedRunlog([entry(1, kit.runId, null), entry(2, otherRunId, kit.runId)]);
    const f = await checkRunlogFreshness(storeWith(two.log, two.sig), kit.runId, root, kit.verifier, {});
    ok("an ordinary stale run is a check that RAN and found NO rollback (only allowStale was missing)", f.checked === true && f.rollbackDetected === false && f.ok === false && f.isLatestForDownpipe === false);
    const r = await openThrows(storeWith(two.log, two.sig), kit, { verifyFreshness: true, allowStale: true });
    ok("openRun OPENS that same stale run once staleness is acknowledged", !r.threw);
  }

  // CONTROL 1: a clean latest run still opens with stale tolerance on, and reports a check that RAN.
  {
    const f = await checkRunlogFreshness(storeWith(clean.log, clean.sig), kit.runId, root, kit.verifier, { allowStale: true });
    ok("control: a clean latest run reports checked true, no rollback, ok", f.checked === true && f.rollbackDetected === false && f.ok === true && f.isLatestForDownpipe === true);
    const r = await openThrows(storeWith(clean.log, clean.sig), kit, { verifyFreshness: true, allowStale: true });
    ok("control: openRun still OPENS a clean latest run with stale tolerance on", !r.threw);
  }
  // CONTROL 2: the tampered signature already refused WITHOUT stale tolerance, and still does. If this moved,
  // the change reached further than the defect.
  {
    const r = await openThrows(storeWith(clean.log, forged), kit, { verifyFreshness: true, allowStale: false });
    ok("control: openRun still refuses a tampered RUNLOG signature without stale tolerance", r.threw && /freshness/i.test(r.message));
  }
  // The BENIGN case keeps its own verdict and stays distinguishable from a forgery: the check RAN (checked
  // true) and found the document below an out-of-band pin. A fix that made everything unchecked would fail here.
  {
    const f = await checkRunlogFreshness(storeWith(clean.log, clean.sig), kit.runId, root, kit.verifier, { allowStale: true, minRunlogIndex: 57 });
    ok("a benign below-pin chain stays a FINDING (rollbackDetected true, checked TRUE), not an unknown", f.rollbackDetected === true && f.checked === true);
    const r = await openThrows(storeWith(clean.log, clean.sig), kit, { verifyFreshness: true, allowStale: true, minRunlogIndex: 57 });
    ok("openRun still refuses a benign below-pin chain", r.threw && /freshness/i.test(r.message));
  }
}

// runRunIdShapeGuard: a caller-supplied runId is interpolated raw into the
// `run/${runId}/...` object-key template both openRun and attestKeyless build. For an S3-style
// destination that key becomes a request PATH, and a dot-segment ("..") shape can walk the signed
// request outside the configured bucket once new URL() collapses it (dest/sigv4.ts). The router
// rejects this shape at the API boundary, but openRun/attestKeyless are the shared chokepoints
// every restore/verify/attest/drill/canary/prune caller funnels through, so both must refuse it
// too -- proven here with a store whose get() THROWS, so a pass can only mean the shape guard
// fired first; it can never mean some later step happened to also fail.
async function runRunIdShapeGuard(): Promise<void> {
  console.log("\nrunId shape guard (reject a non-ULID runId before any store read):");
  const dummyIdentity: HybridRecipientPrivate = { x25519Scalar: new Uint8Array(32), mlkemSeed: new Uint8Array(64) };
  const dummyVerifier: HybridVerifier = { ed: new Uint8Array(32), mldsa: new Uint8Array(2592) };

  class NeverReadStore implements ObjectStore {
    called = false;
    async get(key: string): Promise<Uint8Array> {
      this.called = true;
      throw new Error(`unexpected read: ${key}`);
    }
  }

  // The actual exploit string, a bare "." / "..", a traversal buried mid-key, and an
  // otherwise-canonical ULID that is one character short -- all non-ULID shapes decodeULID rejects.
  const evilRunIds = ["../../evil-bucket", ".", "..", "run/../../x", DEFAULT_RUN_ID.slice(0, -1)];
  for (const runId of evilRunIds) {
    const openStore = new NeverReadStore();
    let threw = false;
    try {
      await openRun(openStore, runId, dummyIdentity, dummyVerifier, { verifyFreshness: true, allowStale: true });
    } catch {
      threw = true;
    }
    ok(`openRun rejects runId ${JSON.stringify(runId)} without reading the store`, threw && !openStore.called);

    const attestStore = new NeverReadStore();
    const att = await attestKeyless(attestStore, runId, dummyVerifier, { allowStale: true });
    ok(
      `attestKeyless rejects runId ${JSON.stringify(runId)} without reading the store (no throw, per its total contract)`,
      !att.signatureValid && !att.complete && !att.notRolledBack && att.reason === "invalid runId" && !attestStore.called,
    );
  }

  // Positive control: a canonical (if fictional) ULID is NOT rejected by the shape guard -- it still
  // fails, but only once it reaches the store, proving the guard rejects the SHAPE, not every runId.
  {
    const openStore = new NeverReadStore();
    let threw = false;
    let message = "";
    try {
      await openRun(openStore, DEFAULT_RUN_ID, dummyIdentity, dummyVerifier, { verifyFreshness: true, allowStale: true });
    } catch (e) {
      threw = true;
      message = e instanceof Error ? e.message : String(e);
    }
    ok("openRun still reaches the store for a canonical ULID (the shape guard is not over-broad)", threw && openStore.called && /unexpected read/.test(message));
  }
}

// canonicalJSONLine renders a value as a single canonical-JSON line (no trailing newline), the shape
// each shard NDJSON line takes. Kept tiny so the crafted-shard bodies above read as data, not framing.
function canonicalJSONLine(value: unknown): string {
  return new TextDecoder().decode(canonicalJSON(value));
}

// craftRecordLine builds a structurally complete ShardRecord line for a crafted shard. Only the
// fields the targeted gate reads need to be meaningful (sourceType, codec, recordHash, the secrets
// salt); the rest are well-formed placeholders so the line parses and passes the per-line
// canonical-numeric check on plaintextSize. The record is never restored in these cases (the gates
// that fire are in openRun's verification loop, before any restore), so placeholder segment bytes are
// fine.
function craftRecordLine(opts: { sourceType: string; codec: string; segObject: string; recordId?: string; recordSalt?: string; recordHash?: string }): string {
  const rec: Record<string, unknown> = {
    kind: "record",
    sourceType: opts.sourceType,
    recordId: opts.recordId ?? "rec0",
    name: "crafted",
    plaintextSha384: hexEncode(new Uint8Array(48)),
    plaintextSize: 0,
    keyNameHash: hexEncode(new Uint8Array(48)),
    recordHash: opts.recordHash ?? hexEncode(new Uint8Array(48)),
    codec: opts.codec,
    segments: [{ object: opts.segObject, chunkRange: [0, 1], packed: null }],
  };
  if (opts.recordSalt !== undefined) rec.recordSalt = opts.recordSalt;
  return canonicalJSONLine(rec);
}

// restoreRejectMessage returns the message restoreRecord throws for a record, or empty if it did not
// throw. Used where the rejection MESSAGE is load-bearing (proving the multi-segment branch fired,
// not some earlier guard).
async function restoreRejectMessage(run: Awaited<ReturnType<typeof openRun>>, rec: ShardRecord): Promise<string> {
  try {
    await run.restoreRecord(rec);
    return "";
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

async function main(): Promise<void> {
  const commit = (await text(join(vectors, "VECTORS_COMMIT"))).trim();
  console.log(`corpus VECTORS_COMMIT ${commit}\n`);

  const dirents = await readdir(vectors, { withFileTypes: true });
  const names = dirents.filter((d) => d.isDirectory()).map((d) => d.name).sort();

  let scanned = 0;
  let positives = 0;
  let negatives = 0;

  for (const name of names) {
    const dir = join(vectors, name);
    let expect: VectorExpect;
    try {
      expect = JSON.parse(await text(join(dir, "expect.json"))) as VectorExpect;
    } catch {
      // The KAT directories (crypto-kat, kem-combiner-kat, mlkem-kat, mldsa-kat) carry a
      // kat.json, not an expect.json; they are covered by validate-crypto and validate-pq.
      continue;
    }

    scanned++;
    if (expect.mode === "positive") positives++;
    else negatives++;

    console.log(`${name}:`);
    await dispatch(name, dir, expect);

    // A vector may carry also[] expectations: a second run against the same archive, for
    // example the dedup shared value opened under both run ids, or a stale run that also
    // recovers under allowStale. Each is dispatched on its own mode.
    for (const a of expect.also ?? []) {
      await dispatch(`${name}#also`, dir, a);
    }
  }

  // The keyless attestation tier (attestKeyless) is the keyless dual of the openRun chain above.
  // It is driven from the same corpus plus a couple of injected destination faults, asserting the
  // three honest flags and the coarse, secret-free reasons.
  await runKeylessAttestation();

  // The structural gates that fire only on a validly-signed-but-malformed root, driven from
  // self-generated signed manifests the corpus cannot ship.
  await runKeylessStructuralAttestation();

  // The openRun and restoreRecord verification-failure branches the open/reject corpus scan leaves
  // uncovered (the throw arms of guards that no well-formed vector trips), driven from mutated copies
  // of genuinely-sealed runs.
  await runReaderErrorPaths();

  // The anti-rollback replay exploit (a clean whole-document RUNLOG replay) end to end on
  // both the keyless and keyed tiers, proving the minRunlogIndex pin -- not the chain-anomaly check
  // alone -- is what closes it.
  await runRollbackPinAttestation();

  // A freshness check that could not be RUN (an absent or forgery-signed RUNLOG, a run the document does
  // not carry, either disagreement with the signed root) must refuse rather than report a clean chain,
  // with both controls held.
  await runUncheckedFreshnessRefusal();

  // openRun/attestKeyless refuse a non-ULID runId before it ever reaches an object-key
  // template, proven with a store that fails the test if it is read at all.
  await runRunIdShapeGuard();

  console.log(`\nscanned ${scanned} vectors (${positives} positive, ${negatives} negative)`);
  console.log(
    failures === 0
      ? "ALL READER VECTORS PASS (the TS reader opens the Go archives and rejects the tampered ones)"
      : `${failures} FAILURE(S)`,
  );
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
