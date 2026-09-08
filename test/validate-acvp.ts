// FIPS 203 / FIPS 204 standard-conformance anchor for the post-quantum primitives
// (assessment finding CRYPTO-2).
//
// WHY THIS EXISTS
// ---------------
// The other PQ validators (test/validate-pq.ts, test/validate-mldsa-seed.ts) pin the
// pinned @noble/post-quantum implementation against the Go reference (filippo.io/mldsa,
// crypto/mlkem): the two implementations are shown to AGREE WITH EACH OTHER. That is a
// strong cross-implementation check, but two implementations can in principle agree on a
// shared deviation, so it is not by itself a claim against the published standard. A
// CNSA-2.0 product is expected to demonstrate conformance to the STANDARD's own expected
// outputs, i.e. NIST's Algorithm Cryptographic Validation Program (ACVP) known-answer
// vectors for ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204).
//
// WHAT THIS FILE PROVES, PRECISELY (read the run output; do not infer more):
//
//   [A1] ML-KEM-1024 (FIPS 203) BYTE-KAT, anchored to AUTHORITATIVE NIST OUTPUTS -- ALWAYS
//        runs. A VERBATIM subset of NIST's ACVP ML-KEM-1024 encapDecap vectors is vendored
//        at test/vectors/acvp/ML-KEM-1024-nist-subset.json (provenance + the exact NIST
//        ACVP-Server commit are recorded inside the file). The engine's @noble path is run
//        over NIST's own inputs and asserted BYTE-FOR-BYTE against NIST's published outputs:
//          - encapsulation : encapsulate(ek, m) must produce NIST's ciphertext c AND shared
//                            secret k (FIPS 203 Encaps_internal, Algorithm 17);
//          - decapsulation : decapsulate(c, dk) must produce NIST's k, including a
//                            modified-ciphertext case where k is the implicit-rejection
//                            value (FIPS 203 6.3) -- proving the engine matches the standard
//                            even on the reject path;
//          - key checks     : the engine's accept/reject of a malformed ek/dk must match
//                            NIST's testPassed verdict.
//        This is a real FIPS 203 standard-conformance anchor: byte-exact agreement with
//        NIST's reference outputs, not merely mutual agreement with the Go port.
//
//   [A2] ML-DSA-87 (FIPS 204) VERIFY, anchored to AUTHORITATIVE NIST OUTPUTS -- ALWAYS runs.
//        A VERBATIM subset of NIST's ACVP ML-DSA-87 sigVer vectors is vendored at
//        test/vectors/acvp/ML-DSA-87-sigver-nist-subset.json. For every case the engine's
//        @noble verify path (interface-correct: pure-internal, external, external-mu) must
//        produce the SAME accept/reject verdict (testPassed) NIST published -- including the
//        negative cases.
//
//        WHY VERIFY AND NOT BYTE-REPRODUCE THE SIGNATURE: ML-DSA signing is not required to
//        be byte-identical across conformant implementations, and empirically @noble's
//        deterministic signature bytes do not equal NIST's ACVP sigGen bytes (internal
//        hedging details differ) even though @noble VERIFIES every NIST signature. The
//        byte-stable, conformance-bearing direction for ML-DSA is therefore sigVer / verify,
//        which is what this anchors. (HashML-DSA / prehash cases are omitted: the engine
//        uses pure ML-DSA-87, and @noble enforces a >=256-bit pre-hash strength policy that
//        rejects the weaker ACVP prehash hashes by design.)
//
//   [A3] OPTIONAL FULL ACVP FILES -- run only if the complete NIST ACVP
//        internalProjection.json files are dropped in (see "HOW TO ENABLE"). They activate
//        the same anchors across the full NIST corpus:
//          - test/vectors/acvp/ML-KEM-1024.json  : full ML-KEM-1024 byte-KAT + key-check.
//          - test/vectors/acvp/ML-DSA-87.json     : full ML-DSA-87 sigVer verdicts, and (if
//            it is a sigGen file) every pure NIST signature must verify.
//
//   [B] HONEST DETERMINISM ANCHOR -- ALWAYS runs, no network, no vendored files. Not a
//       standard claim; it proves the properties the engine depends on, directly through
//       src/crypto/pq.ts, over many seeds: ML-KEM keygen stability, decap(encap)==ss
//       correctness, tampered-ciphertext implicit rejection (no throw, different secret),
//       deterministic encapsulate reproducibility; ML-DSA keygen stability, sign/verify
//       round-trip, and rejection of tampered message / tampered signature / wrong key,
//       at the FIPS 204 ML-DSA-87 sizes.
//
// HONEST PROVENANCE LINE for the assessment, after this file:
//   "The PQ primitives are pinned to the Go reference (validate-pq, validate-mldsa-seed)
//    AND anchored to NIST's published ACVP outputs: ML-KEM-1024 byte-for-byte against the
//    FIPS 203 encapDecap vectors (encapsulation c/k, decapsulation k incl. implicit
//    rejection, key-check verdicts), and ML-DSA-87 against the FIPS 204 sigVer accept/reject
//    verdicts (pure interfaces; HashML-DSA omitted). A vendored verbatim subset runs by
//    default; the full NIST files activate the complete corpus when dropped in." This is NOT
//    a statement that the product is NIST/CAVP-VALIDATED -- ACVP validation is a NIST/lab
//    process; this runs NIST's published vectors through the engine's code.
//
// HOW TO ENABLE THE FULL OPTIONAL ANCHOR (offline or online):
//   1. Obtain the NIST ACVP internalProjection.json files (they carry the expected outputs)
//      from NIST's ACVP-Server repository:
//        https://github.com/usnistgov/ACVP-Server  ->  gen-val/json-files/
//          ML-KEM-encapDecap-FIPS203/internalProjection.json
//          ML-DSA-sigVer-FIPS204/internalProjection.json   (or ML-DSA-sigGen-FIPS204)
//      `node scripts/fetch-acvp.mjs` downloads them if a network is available and prints the
//      same guidance + the exact target paths when offline.
//   2. Save them as  test/vectors/acvp/ML-KEM-1024.json  and  test/vectors/acvp/ML-DSA-87.json
//      (the reader accepts the native ACVP shape and filters to the right parameter set, so
//      the raw files drop in unedited).
//   3. Re-run `node test/validate-acvp.ts` (or `npm run validate`).
//
// Run with: node test/validate-acvp.ts

import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

import { hexDecode, hexEncode, constantTimeEqual } from "../src/crypto/bytes.ts";
import {
  mlkemKeygen,
  mlkemEncapsulate,
  mlkemDecapsulate,
  mldsaKeygen,
  mldsaSign,
  mldsaVerify,
} from "../src/crypto/pq.ts";

const here = dirname(fileURLToPath(import.meta.url));
const acvpDir = join(here, "vectors", "acvp");
// Committed verbatim NIST subsets (the always-on conformance anchors).
const MLKEM_SUBSET = join(acvpDir, "ML-KEM-1024-nist-subset.json");
const MLDSA_SUBSET = join(acvpDir, "ML-DSA-87-sigver-nist-subset.json");
// Optional full NIST ACVP internalProjection files (drop in to enable the complete anchor).
const MLKEM_FULL = join(acvpDir, "ML-KEM-1024.json");
const MLDSA_FULL = join(acvpDir, "ML-DSA-87.json");

let failures = 0;
let assertions = 0;
function ok(label: string, cond: boolean): void {
  assertions++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function eqBytes(label: string, got: Uint8Array, want: Uint8Array): void {
  ok(label, got.length === want.length && constantTimeEqual(got, want));
}

// ---------------------------------------------------------------------------
// ACVP JSON shape. NIST's internalProjection.json top level is
//   { testGroups: [ { tgId, testType, parameterSet, function, signatureInterface,
//                     preHash, externalMu, deterministic, tests: [ { tcId, ... } ] } ] }.
// Read defensively so a newer registration revision degrades to "skipped case", never a
// crash and never a false pass. Byte fields are hex; NIST emits UPPERCASE hex, so compare
// DECODED bytes (constantTimeEqual), never hex strings.
// ---------------------------------------------------------------------------
interface AcvpTest {
  tcId?: number;
  // ML-KEM
  ek?: string;
  dk?: string;
  m?: string;
  c?: string;
  k?: string;
  reason?: string;
  // ML-DSA
  pk?: string;
  message?: string;
  mu?: string;
  context?: string;
  signature?: string;
  // shared verdict
  testPassed?: boolean;
}
interface AcvpGroup {
  tgId?: number;
  testType?: string;
  function?: string; // "encapsulation" | "decapsulation" | "*KeyCheck"
  parameterSet?: string;
  signatureInterface?: string; // "internal" | "external"
  preHash?: string; // "pure" | "preHash" | "none"
  externalMu?: boolean;
  ek?: string;
  dk?: string;
  pk?: string;
  tests?: AcvpTest[];
}
interface AcvpFile {
  algorithm?: string;
  mode?: string;
  revision?: string;
  testGroups?: AcvpGroup[];
}

function loadAcvp(path: string): AcvpFile | null {
  if (!existsSync(path)) return null;
  const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (Array.isArray(parsed)) {
    for (const el of parsed) {
      if (el && typeof el === "object" && Array.isArray((el as AcvpFile).testGroups)) return el as AcvpFile;
    }
    return null;
  }
  return parsed as AcvpFile;
}

function hx(s: string | undefined): Uint8Array | null {
  if (typeof s !== "string" || s.length % 2 !== 0) return null;
  if (s.length === 0) return new Uint8Array(0);
  try {
    return hexDecode(s); // hexDecode is case-insensitive; NIST hex is uppercase.
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Section A1 -- ML-KEM-1024 byte-KAT against NIST ACVP encapDecap outputs.
// ---------------------------------------------------------------------------
// One test case's contribution to the anchor tally: either one assertion was made, or the case was
// skipped as not-applicable/incomplete. The three runMlKem* helpers each return this for one tc.
type AnchorTally = { asserted: number; skipped: number };
const SKIP: AnchorTally = { asserted: 0, skipped: 1 } as const;

// encapsulation: derive c and/or k from the NIST ek+m and compare against the published vectors.
function runMlKemEncap(g: AcvpGroup, t: AcvpTest, label: string): AnchorTally {
  const ek = hx(t.ek) ?? hx(g.ek);
  const m = hx(t.m);
  const wantC = hx(t.c);
  const wantK = hx(t.k);
  if (!ek || !m || ek.length !== 1568 || m.length !== 32 || (!wantC && !wantK)) return SKIP;
  const r = ml_kem1024.encapsulate(ek, m);
  let asserted = 0;
  if (wantC) {
    eqBytes(`${label} ML-KEM-1024 encap tc#${t.tcId}: ciphertext c matches NIST (FIPS 203)`, r.cipherText, wantC);
    asserted++;
  }
  if (wantK) {
    eqBytes(`${label} ML-KEM-1024 encap tc#${t.tcId}: shared secret k matches NIST (FIPS 203)`, r.sharedSecret, wantK);
    asserted++;
  }
  return { asserted, skipped: 0 };
}

// decapsulation: recover k from the NIST c+dk and compare against the published vector.
function runMlKemDecap(_g: AcvpGroup, t: AcvpTest, label: string): AnchorTally {
  const dk = hx(t.dk) ?? hx(_g.dk);
  const c = hx(t.c);
  const wantK = hx(t.k);
  if (!dk || !c || !wantK || dk.length !== 3168 || c.length !== 1568) return SKIP;
  let k: Uint8Array | null = null;
  try {
    k = mlkemDecapsulate(c, dk);
  } catch {
    k = null;
  }
  // FIPS 203 decapsulation never throws on a well-formed dk; a modified ciphertext
  // yields the implicit-rejection secret, which NIST also publishes as k.
  const note = t.reason && /modif/i.test(t.reason) ? " [implicit-rejection]" : "";
  ok(`${label} ML-KEM-1024 decap tc#${t.tcId}: shared secret k matches NIST (FIPS 203)${note}`, k !== null && k.length === wantK.length && constantTimeEqual(k, wantK));
  return { asserted: 1, skipped: 0 };
}

// key-check (dk or ek): assert the accept/reject verdict matches NIST's testPassed.
function runMlKemKeyCheck(fn: string, t: AcvpTest, label: string): AnchorTally {
  if (t.testPassed === undefined) return SKIP;
  // ACVP key-check: testPassed is whether the key is well-formed. @noble throws on a
  // malformed key (a hash/modulus check), so throw->invalid maps to testPassed false.
  let valid: boolean;
  try {
    if (fn === "decapsulationKeyCheck") {
      const dk = hx(t.dk);
      if (!dk) return SKIP;
      mlkemDecapsulate(new Uint8Array(1568), dk); // exercises the dk validity check
    } else {
      const ek = hx(t.ek);
      if (!ek) return SKIP;
      ml_kem1024.encapsulate(ek, new Uint8Array(32)); // exercises the ek modulus check
    }
    valid = true;
  } catch {
    valid = false;
  }
  ok(`${label} ML-KEM-1024 ${fn} tc#${t.tcId}: accept/reject matches NIST (expected ${t.testPassed})`, valid === t.testPassed);
  return { asserted: 1, skipped: 0 };
}

function runMlKemAnchor(file: AcvpFile, label: string): AnchorTally {
  let asserted = 0;
  let skipped = 0;
  for (const g of file.testGroups ?? []) {
    if (g.parameterSet && g.parameterSet !== "ML-KEM-1024") continue;
    const fn = g.function ?? "";
    for (const t of g.tests ?? []) {
      let r: AnchorTally;
      if (fn === "encapsulation") r = runMlKemEncap(g, t, label);
      else if (fn === "decapsulation") r = runMlKemDecap(g, t, label);
      else if (fn === "decapsulationKeyCheck" || fn === "encapsulationKeyCheck") r = runMlKemKeyCheck(fn, t, label);
      else r = SKIP;
      asserted += r.asserted;
      skipped += r.skipped;
    }
  }
  return { asserted, skipped };
}

// ---------------------------------------------------------------------------
// Section A2 -- ML-DSA-87 verify anchor against NIST ACVP sigVer (and sigGen-verifies).
//
// ACVP ML-DSA signature interfaces (FIPS 204):
//   internal, externalMu=false : verify_internal over the raw message M (Algorithm 8)
//   internal, externalMu=true  : verify_internal over a caller-supplied 64-byte mu
//   external,  preHash=pure    : top-level verify over M with the context string (5.3)
//   external,  preHash=preHash : HashML-DSA -- omitted (engine uses pure; @noble rejects
//                                sub-256-bit pre-hash for ML-DSA-87 by policy).
// ---------------------------------------------------------------------------
function mldsaVerifyAcvp(g: AcvpGroup, t: AcvpTest): boolean | "prehash-omitted" | "incomplete" {
  const sig = hx(t.signature);
  const pk = hx(t.pk) ?? hx(g.pk);
  if (!sig || !pk) return "incomplete";
  const si = g.signatureInterface ?? "internal";
  const ph = g.preHash ?? "none";
  const emu = g.externalMu === true;
  if (ph === "preHash") return "prehash-omitted";
  try {
    if (si === "internal" && emu) {
      const mu = hx(t.mu);
      if (!mu) return "incomplete";
      return ml_dsa87.internal.verify(sig, mu, pk, { externalMu: true });
    }
    if (si === "internal") {
      const msg = hx(t.message);
      if (msg === null) return "incomplete";
      return ml_dsa87.internal.verify(sig, msg, pk);
    }
    const msg = hx(t.message);
    if (msg === null) return "incomplete";
    const ctx = t.context !== undefined ? hx(t.context) : new Uint8Array(0);
    if (ctx === null) return "incomplete";
    return ml_dsa87.verify(sig, msg, pk, { context: ctx });
  } catch {
    return false; // a throw on a well-formed non-prehash interface is a real reject.
  }
}

function runMlDsaAnchor(file: AcvpFile, label: string): { asserted: number; prehash: number; incomplete: number } {
  let asserted = 0;
  let prehash = 0;
  let incomplete = 0;
  const isSigVer = (file.mode ?? "").toLowerCase() === "sigver" || (file.testGroups ?? []).some((g) => (g.tests ?? []).some((t) => t.testPassed !== undefined));
  for (const g of file.testGroups ?? []) {
    if (g.parameterSet && g.parameterSet !== "ML-DSA-87") continue;
    for (const t of g.tests ?? []) {
      const r = mldsaVerifyAcvp(g, t);
      if (r === "prehash-omitted") {
        prehash++;
        continue;
      }
      if (r === "incomplete") {
        incomplete++;
        continue;
      }
      if (t.testPassed !== undefined) {
        ok(`${label} ML-DSA-87 sigVer tc#${t.tcId} [${g.signatureInterface ?? "internal"}/mu=${g.externalMu === true}]: verdict matches NIST (expected ${t.testPassed})`, r === t.testPassed);
        asserted++;
      } else if (!isSigVer) {
        ok(`${label} ML-DSA-87 sigGen tc#${t.tcId} [${g.signatureInterface ?? "internal"}/mu=${g.externalMu === true}]: NIST signature verifies (FIPS 204)`, r === true);
        asserted++;
      }
    }
  }
  return { asserted, prehash, incomplete };
}

// ---------------------------------------------------------------------------
// Section B -- honest deterministic anchor, always, through src/crypto/pq.ts.
// ---------------------------------------------------------------------------
// Coprime multipliers and offset chosen to produce distinct, broadly-distributed seeds. Changing any
// of them changes every seed and breaks the cross-check with the Go reference.
const SEED_MUL_I = 131;
const SEED_MUL_J = 67;
const SEED_MUL_SALT = 251;
const SEED_OFFSET = 7;
function deterministicSeed(i: number, len: number, salt: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let j = 0; j < len; j++) {
    out[j] = (i * SEED_MUL_I + j * SEED_MUL_J + salt * SEED_MUL_SALT + SEED_OFFSET) & 0xff;
  }
  return out;
}

function runMlKemSelfCheck(): void {
  console.log("Section B -- ML-KEM-1024 determinism + correctness + implicit rejection (pq.ts, no ACVP needed):");
  const N = 24;
  let stable = 0;
  let roundTrip = 0;
  let implicitReject = 0;
  let detEncap = 0;
  let distinctKeys = 0;
  let prevEk = "";
  for (let i = 0; i < N; i++) {
    const seed = deterministicSeed(i, 64, 1);
    const a = mlkemKeygen(seed);
    const b = mlkemKeygen(seed);
    if (a.encapKey.length === 1568 && a.decapKey.length === 3168 &&
        constantTimeEqual(a.encapKey, b.encapKey) && constantTimeEqual(a.decapKey, b.decapKey)) {
      stable++;
    }
    const ekHex = hexEncode(a.encapKey);
    if (ekHex !== prevEk) distinctKeys++;
    prevEk = ekHex;

    const enc = mlkemEncapsulate(a.encapKey);
    const back = mlkemDecapsulate(enc.cipherText, a.decapKey);
    if (enc.sharedSecret.length === 32 && constantTimeEqual(back, enc.sharedSecret)) roundTrip++;

    const badCt = enc.cipherText.slice();
    badCt[i % badCt.length]! ^= 0x80;
    let rejectedImplicitly = false;
    try {
      const ssBad = mlkemDecapsulate(badCt, a.decapKey);
      rejectedImplicitly = ssBad.length === 32 && !constantTimeEqual(ssBad, enc.sharedSecret);
    } catch {
      rejectedImplicitly = false;
    }
    if (rejectedImplicitly) implicitReject++;

    const m = deterministicSeed(i, 32, 9);
    const d1 = ml_kem1024.encapsulate(a.encapKey, m);
    const d2 = ml_kem1024.encapsulate(a.encapKey, m);
    const d3 = mlkemDecapsulate(d1.cipherText, a.decapKey);
    if (constantTimeEqual(d1.cipherText, d2.cipherText) && constantTimeEqual(d1.sharedSecret, d2.sharedSecret) &&
        constantTimeEqual(d3, d1.sharedSecret)) {
      detEncap++;
    }
  }
  ok(`ML-KEM keygen(seed) is a stable function over ${N} seeds`, stable === N);
  ok(`ML-KEM keygen yields distinct keys across distinct seeds (${distinctKeys}/${N})`, distinctKeys === N);
  ok(`ML-KEM decapsulate(encapsulate(ek)) == shared secret over ${N} seeds`, roundTrip === N);
  ok(`ML-KEM tampered ciphertext -> different 32-byte secret, no throw (FIPS 203 6.3) over ${N} seeds`, implicitReject === N);
  ok(`ML-KEM deterministic encapsulate(ek, m) is reproducible + decapsulates back over ${N} seeds`, detEncap === N);
}

function runMlDsaSelfCheck(): void {
  console.log("Section B -- ML-DSA-87 determinism + sign/verify + negative acceptance (pq.ts, no ACVP needed):");
  const N = 24;
  let stable = 0;
  let roundTrip = 0;
  let rejectMsg = 0;
  let rejectSig = 0;
  let rejectKey = 0;
  let sizeOk = 0;
  let distinctKeys = 0;
  let prevPk = "";
  for (let i = 0; i < N; i++) {
    const seed = deterministicSeed(i, 32, 3);
    const a = mldsaKeygen(seed);
    const b = mldsaKeygen(seed);
    if (a.publicKey.length === 2592 && a.secretKey.length === 4896 &&
        constantTimeEqual(a.publicKey, b.publicKey) && constantTimeEqual(a.secretKey, b.secretKey)) {
      stable++;
    }
    const pkHex = hexEncode(a.publicKey);
    if (pkHex !== prevPk) distinctKeys++;
    prevPk = pkHex;

    const msg = new TextEncoder().encode(`acvp self-check message #${i}`);
    const sig = mldsaSign(a.secretKey, msg);
    if (sig.length === 4627) sizeOk++;
    if (mldsaVerify(a.publicKey, msg, sig)) roundTrip++;

    const badMsg = msg.slice();
    badMsg[i % badMsg.length]! ^= 0x01;
    if (!mldsaVerify(a.publicKey, badMsg, sig)) rejectMsg++;

    const badSig = sig.slice();
    badSig[(i * 7) % badSig.length]! ^= 0x01;
    if (!mldsaVerify(a.publicKey, msg, badSig)) rejectSig++;

    const other = mldsaKeygen(deterministicSeed(i + 1000, 32, 3));
    if (!mldsaVerify(other.publicKey, msg, sig)) rejectKey++;
  }
  ok(`ML-DSA keygen(seed) is a stable function over ${N} seeds`, stable === N);
  ok(`ML-DSA keygen yields distinct keys across distinct seeds (${distinctKeys}/${N})`, distinctKeys === N);
  ok(`ML-DSA sign/verify round-trips over ${N} seeds`, roundTrip === N);
  ok(`ML-DSA signature is 4627 bytes (FIPS 204 ML-DSA-87) over ${N} seeds`, sizeOk === N);
  ok(`ML-DSA rejects a tampered message over ${N} seeds`, rejectMsg === N);
  ok(`ML-DSA rejects a tampered signature over ${N} seeds`, rejectSig === N);
  ok(`ML-DSA rejects a signature under the wrong key over ${N} seeds`, rejectKey === N);
}

// ---------------------------------------------------------------------------
// [A1] Committed ML-KEM-1024 NIST byte-KAT.
function sectionA1(): void {
  console.log("Section A1 -- FIPS 203 ML-KEM-1024 BYTE-KAT anchored to NIST ACVP outputs (vendored subset):");
  const kemSub = loadAcvp(MLKEM_SUBSET);
  if (kemSub) {
    const r = runMlKemAnchor(kemSub, "NIST-subset");
    if (r.asserted === 0) ok("NIST ML-KEM-1024 subset present but yielded 0 usable cases (check shape)", false);
    else console.log(`  -> ${r.asserted} NIST ML-KEM-1024 byte/verdict cases asserted from ${MLKEM_SUBSET}` + (r.skipped ? ` (${r.skipped} skipped)` : ""));
  } else {
    ok("VENDORED NIST ML-KEM-1024 subset is MISSING (expected at test/vectors/acvp/ML-KEM-1024-nist-subset.json)", false);
    console.log("  -> the committed FIPS 203 NIST byte-KAT did not run; falling back to the Go-reference + [B] anchors.");
  }
  console.log("");
}

// [A2] Committed ML-DSA-87 NIST verify anchor.
function sectionA2(): void {
  console.log("Section A2 -- FIPS 204 ML-DSA-87 VERIFY anchored to NIST ACVP sigVer outputs (vendored subset):");
  const dsaSub = loadAcvp(MLDSA_SUBSET);
  if (dsaSub) {
    const r = runMlDsaAnchor(dsaSub, "NIST-subset");
    if (r.asserted === 0) ok("NIST ML-DSA-87 sigVer subset present but yielded 0 usable cases (check shape)", false);
    else console.log(`  -> ${r.asserted} NIST ML-DSA-87 sigVer verdicts asserted from ${MLDSA_SUBSET}` + (r.prehash ? ` (${r.prehash} prehash omitted)` : ""));
  } else {
    ok("VENDORED NIST ML-DSA-87 sigVer subset is MISSING (expected at test/vectors/acvp/ML-DSA-87-sigver-nist-subset.json)", false);
    console.log("  -> the committed FIPS 204 NIST verify anchor did not run; falling back to the Go-reference + [B] anchors.");
  }
  console.log("");
}

// [A3] Optional full NIST ACVP files.
function sectionA3(): void {
  const kemFull = loadAcvp(MLKEM_FULL);
  const dsaFull = loadAcvp(MLDSA_FULL);
  if (kemFull || dsaFull) {
    console.log("Section A3 -- OPTIONAL FULL NIST ACVP FILES:");
    if (kemFull) {
      const r = runMlKemAnchor(kemFull, "NIST-full");
      console.log(`  -> ML-KEM-1024: ${r.asserted} cases asserted, ${r.skipped} skipped, from ${MLKEM_FULL}`);
    } else {
      console.log(`  (no full ML-KEM-1024 ACVP file at ${MLKEM_FULL})`);
    }
    if (dsaFull) {
      const r = runMlDsaAnchor(dsaFull, "NIST-full");
      console.log(`  -> ML-DSA-87: ${r.asserted} cases asserted, ${r.prehash} prehash omitted, ${r.incomplete} incomplete, from ${MLDSA_FULL}`);
    } else {
      console.log(`  (no full ML-DSA-87 ACVP file at ${MLDSA_FULL})`);
    }
    console.log("");
  } else {
    console.log("Section A3 -- OPTIONAL FULL NIST ACVP FILES: not vendored (this is fine).");
    console.log("  Drop the full NIST ACVP internalProjection.json files to run the complete corpus:");
    console.log(`    - run  node scripts/fetch-acvp.mjs  (fetches if online; prints guidance offline), OR place`);
    console.log(`      ML-KEM-encapDecap-FIPS203 + ML-DSA-sigVer/sigGen-FIPS204 internalProjection.json at:`);
    console.log(`        ${MLKEM_FULL}`);
    console.log(`        ${MLDSA_FULL}`);
    console.log("");
  }
}

function main(): void {
  console.log("=== FIPS 203 / FIPS 204 conformance anchor (CRYPTO-2) ===\n");
  sectionA1();
  sectionA2();
  sectionA3();
  // [B] Always.
  runMlKemSelfCheck();
  runMlDsaSelfCheck();
  console.log("");
  console.log(failures === 0 ? `ACVP ANCHOR PASS (${assertions} assertions)` : `\n${failures} FAILURE(S) of ${assertions} assertions`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
