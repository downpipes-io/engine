import { b64urlDecode, b64urlEncode, constantTimeEqual, hexDecode, hexEncode, utf8 } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type HybridVerifier, hybridSign, hybridVerify } from "../crypto/sign.ts";
import { integrityError } from "./integrity-error.ts";
import { noteFailStage, noteFetchFault } from "./integrity-fault-ledger.ts";
import { VERSION } from "./version.ts";

// The recovery bundle (SPEC 9), ported from the Go reference: a versioned FORMAT.md pointer
// and recovery instructions under _RECOVERY/downpipe/0.1.0/, a SHA384SUMS over them, and a
// detached hybrid signature over SHA384SUMS so a recoverer relying on the bundle can confirm
// the instructions were not altered. Written every run (idempotent: identical content writes
// identically). By design (F16) the full specification and the reader source are NOT in the
// Worker bundle (module-size budget); they are the open-source MIT downpipe project, which a
// recoverer keeps or re-implements a clean-room reader from using the spec and the vectors.

/** The object-key prefix under which the recovery bundle files live (SPEC 9). */
export const BUNDLE_PREFIX = `_RECOVERY/${VERSION}/`;

// The engine writes a fixed, small set of bundle files (FORMAT.md, RECOVER.md). This caps how many
// SHA384SUMS lines verifyBundle will enumerate as defence-in-depth, so a tampered or hostile store
// cannot make it fan out into many store.get() calls. The signature guards integrity; this guards
// fan-out even before that is reasoned about.
const MAX_BUNDLE_SUM_LINES = 10;

// Allowed characters in a bundle file name parsed from SHA384SUMS. Object storage has no path
// traversal concern, but this rejects empty or unexpected names (e.g. "../x") before they are
// used as a storage key, even though the signed blob already guards the content.
const BUNDLE_NAME_RE = /^[A-Za-z0-9._-]+$/;

// WHY THIS NAMES A FORMAT VERSION AND DELIBERATELY NAMES NO MINIMUM READER VERSION.
//
// The question is live because an archive written today may be opened in ten years by somebody holding
// nothing but the bucket, and whatever this file says then is the only guidance they have. A version an
// archive names is a PROMISE, and it is signed into the run, so a wrong one cannot be corrected later.
//
// A minimum reader RELEASE would be the wrong promise, for a reason that is structural rather than a matter
// of taste: the reader's release number and the archive format are independent number spaces (SPEC 13.1),
// and they are not merely independent, they are not even ordered the same way. Measured against the two
// released reader tags: v0.2.0 implements downpipe/0.1.x and refuses downpipe/1.x, and the OLDER v0.1.1
// implements downpipe/1.x and refuses downpipe/0.1.x. The coverage is disjoint and it runs backwards, so
// "v0.2.0 or newer" is not a true statement of anything; a 0.x minor is allowed to break compatibility, so
// a future v0.3.0 may drop 0.1.x entirely and the sentence would then point a recoverer mid-disaster at a
// binary that refuses their archive. That is the "worse than none" case exactly: a confident, signed,
// immutable instruction that leads away from the one reader that works.
//
// The format version is the right promise and it is already made, in this file and in the signed root
// manifest's formatVersion field. It is a fact about THESE BYTES, fixed at write time and true forever,
// and it is the key into a mapping that is maintained in the direction that stays correct: each reader
// release states which format versions IT reads. Resolving that at READ time, by a reader that knows its
// own capability, is the only resolution that can account for readers not yet written.
//
// So what was genuinely missing was not a version but a POINTER. The old text told a recoverer to find "a
// conformant reader of the downpipe/0.1.0 format" and did not tell them how to tell which release that is,
// which is the whole question when you are holding a bucket and a decade has passed. A pointer cannot go
// stale the way a value can.
const FORMAT_MD = `# ${VERSION} archive format\n\nThis is a versioned pointer, not the full specification. Recover with the destination bucket bytes, your offline break-glass key, and a conformant reader of the ${VERSION} format. The authoritative specification (docs/format/SPEC.md) and the normative conformance vectors (internal/format/testdata/vectors) are the open-source MIT downpipe project; use its reader or build a clean-room one from the spec and vectors. Neither Cloudflare nor the vendor is involved.\n\nThis archive names the format version it is, above, and deliberately names no minimum reader version. A reader's release number is a separate number space from the format and says nothing about it: of the two released reader tags, the newer implements ${VERSION.slice(0, VERSION.lastIndexOf("."))}.x while the older implements a different format version and refuses this one. To find a reader that opens this archive, read each release's CHANGELOG.md entry, which names the format versions that release reads (https://github.com/downpipes-io/downpipe), then prove it by running a verify against these bytes before you rely on the binary. Any minimum reader version written here would be a promise made about releases that did not exist when this archive was sealed.\n`;
// RECOVER_MD is customer-facing copy read under stress, and every `downpipe ...` line in it is DRIVEN
// against a real engine-written archive by test/bundle-recover-commands.ts (wired into
// scripts/e2e-writer-reader.sh, the one place a real archive and a real built Go reader both exist).
// Change this text only alongside a run of that gate.
//
// The offline Go tool carries its own copy for its selftest (separate repo; the bundle content is not
// normative, because each archive verifies its bundle against the SHA384SUMS written in the same run).
// The two are held in step by matching CLAIM assertions, not by byte equality: test/validate-format-prims.ts
// here and TestTheSelftestRecoveryTextTeachesTheSameRecoveryAsARealArchive there. Both search
// case-sensitively, so "neither Cloudflare nor the vendor" has to stay lowercase where it appears.
const RECOVER_MD = `# Recovering this archive\n\nYou need the destination bucket, and from your recovery kit two files: your offline break-glass identity, and signer.pub, the operator signer public key this archive's signatures are verified against. Both restore and verify require --signer, so a kit holding only the identity cannot recover. The recovery involves neither Cloudflare nor the vendor.\n\n    downpipe restore --archive <dir> --run <runId> --identity identity.key \\\n      --signer signer.pub --out <dir> --apply\n\nWithout --apply that command plans the restore and writes nothing, which is the safe way to look at an archive before you commit to it. With --apply the recovered records are written under --out.\n\nIf your break-glass key is held as an M-of-N custody quorum rather than as a single file, give the shares to the same command instead of --identity. Pass one --share for each custodian your quorum requires, from any M of the N; they are combined in memory for that one command and wiped, so no complete key is written to disk:\n\n    downpipe restore --archive <dir> --run <runId> --signer signer.pub --out <dir> --apply \\\n      --share share-1.txt --share share-2.txt --share share-3.txt --envelope wrapped-identity.txt\n\nThe break-glass private key is the only universal way to recover, and signer.pub has to be supplied with it. The format is specified in FORMAT.md and pinned by the conformance vectors it references.\n`;

/**
 * The read side verifyBundle needs: a single get(key) that returns the object's bytes. It mirrors
 * the ObjectStore interface in reader.ts but is declared separately so bundle.ts is usable without
 * pulling in the full reader.
 */
export interface ObjectStoreReader {
  get(key: string): Promise<Uint8Array>;
}

// sha384Hex returns the lowercase hex SHA-384 of the given bytes, matching the Go
// reference SHA384Hex helper used in bundle.go.
async function sha384HexLocal(b: Uint8Array): Promise<string> {
  return hexEncode(await sha384(b));
}

/**
 * Verifies the recovery bundle against the operator-pinned signer (SPEC 9, 8.7), mirroring the Go
 * reference VerifyBundle. It reads SHA384SUMS and its detached signature, verifies the hybrid
 * signature, then checks every listed file's SHA-384 against the stored bytes.
 *
 * @param store - the read side of the destination holding the bundle objects.
 * @param verifier - the operator-pinned hybrid signer the SHA384SUMS signature must verify under.
 * @returns a promise that resolves when the bundle verifies.
 * @throws Error when the SHA384SUMS signature does not verify, a SHA384SUMS line is malformed, or
 *   any listed file's bytes do not match its signed SHA-384.
 */
export async function verifyBundle(store: ObjectStoreReader, verifier: HybridVerifier): Promise<void> {
  // Read failures and signature-decode failures are typed as RunIntegrityError so they are non-fallback by
  // construction, rather than being coarsened to an availability class that would trigger the 3-2-1 replica
  // fallback for a genuinely corrupt or tampered bundle.
  let sumsBytes: Uint8Array;
  let sigRaw: Uint8Array;
  try {
    sumsBytes = await store.get(`${BUNDLE_PREFIX}SHA384SUMS`);
    sigRaw = await store.get(`${BUNDLE_PREFIX}SHA384SUMS.sig`);
  } catch (e) {
    noteFetchFault("recovery-bundle", e);
    noteFailStage("recovery-bundle");
    throw e;
  }
  const sigText = new TextDecoder().decode(sigRaw);
  let sig: Uint8Array;
  try {
    sig = b64urlDecode(sigText.trim());
  } catch {
    // A signature OBJECT that will not decode is a CORRUPT signature file, not a signature that fails to
    // verify, and not an availability fault. The decode error's own text is discarded (it quotes the offending
    // character); the typed integrity error carries only the coarse, engine-owned sentence.
    noteFailStage("recovery-bundle");
    throw integrityError("recovery bundle SHA384SUMS signature object is malformed");
  }
  if (!(await hybridVerify(verifier, sumsBytes, sig))) {
    noteFailStage("recovery-bundle");
    throw integrityError("recovery bundle SHA384SUMS signature did not verify under the operator-pinned signer");
  }
  // Ordering is security-critical: the signature is verified above BEFORE any line is enumerated
  // here, so a hostile store cannot drive the get() loop below with unsigned content.
  const sumsText = new TextDecoder().decode(sumsBytes);
  const lines = sumsText.split("\n").filter((l) => l.replace(/\r$/, "") !== "");
  if (lines.length > MAX_BUNDLE_SUM_LINES) {
    throw new Error(`recovery bundle SHA384SUMS lists more than ${MAX_BUNDLE_SUM_LINES} files`);
  }
  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");
    const sep = line.indexOf("  ");
    if (sep < 0) throw new Error(`malformed SHA384SUMS line: ${JSON.stringify(line)}`);
    const expectedHex = line.slice(0, sep);
    const name = line.slice(sep + 2);
    if (!BUNDLE_NAME_RE.test(name)) {
      throw new Error(`recovery bundle SHA384SUMS has an invalid file name: ${JSON.stringify(name)}`);
    }
    const data = await store.get(`${BUNDLE_PREFIX}${name}`);
    const actualHex = await sha384HexLocal(data);
    if (!constantTimeEqual(hexDecode(actualHex), hexDecode(expectedHex))) {
      throw new Error(`recovery bundle file ${name} does not match its signed SHA-384`);
    }
  }
}

/**
 * Adds the recovery-bundle objects (FORMAT.md, RECOVER.md, SHA384SUMS and its detached signature)
 * to the archive map, signed by the run signer.
 *
 * @param out - the archive object map to add the bundle objects into (mutated in place).
 * @param edPrivate - the run signer's Ed25519 private key.
 * @param mldsaSecret - the run signer's ML-DSA-87 secret key.
 * @returns a promise that resolves once the bundle objects have been added.
 */
export async function addBundle(out: Map<string, Uint8Array>, edPrivate: CryptoKey, mldsaSecret: Uint8Array): Promise<void> {
  const files: Record<string, Uint8Array> = { "FORMAT.md": utf8(FORMAT_MD), "RECOVER.md": utf8(RECOVER_MD) };
  const names = Object.keys(files).sort();
  let sums = "";
  for (const n of names) {
    out.set(BUNDLE_PREFIX + n, files[n]!);
    sums += `${hexEncode(await sha384(files[n]!))}  ${n}\n`;
  }
  const sumsBytes = utf8(sums);
  out.set(`${BUNDLE_PREFIX}SHA384SUMS`, sumsBytes);
  const sig = await hybridSign(edPrivate, mldsaSecret, sumsBytes);
  out.set(`${BUNDLE_PREFIX}SHA384SUMS.sig`, utf8(b64urlEncode(sig)));
}
