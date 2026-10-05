// Vendor-side opener for a downpipe engine SUPPORT BUNDLE.
//
// A customer engine can SEAL its support bundle to the vendor support team's public
// key (VENDOR_SUPPORT_PUBLIC) so the diagnostics stay confidential through whatever
// ticket system carries them. This tool is the matching open path: it runs on the
// VENDOR's own machine, holds the vendor support PRIVATE identity (the half that never
// leaves that machine and is never deployed), and recovers the inner signed bundle.
//
// It also handles the signed-plain default (no vendor key set on the customer engine):
// it detects that shape and passes it straight through, so one command opens either
// form. It NEVER reimplements a primitive: the capsule decapsulation, the HKDF-SHA384
// key derivation and the AES-256-GCM open all come from the engine's own crypto, the
// exact code the engine sealed with and the validator opens with.
//
// What it prints to stdout is the inner bundle JSON. What it prints to stderr is a
// short status line saying whether the inner hybrid signature verified, could not be
// verified (no signer public supplied), or failed. A wrong key or corrupt input is a
// one-line error, never a stack trace.
//
// Usage:
//   node tools/open-support-bundle.ts --identity <file>   [--signer-pub <file>] [bundle.json]
//   node tools/open-support-bundle.ts --identity-b64 <b64> [--signer-pub-b64 <b64>] [bundle.json]
//   VENDOR_SUPPORT_IDENTITY=<b64> node tools/open-support-bundle.ts [bundle.json]
//
//   - The vendor support identity is taken from --identity (a file written by the
//     keypair generator), --identity-b64 (the raw base64url), or the
//     VENDOR_SUPPORT_IDENTITY environment variable, in that order.
//   - The sealed (or signed-plain) bundle JSON is read from the positional file path,
//     or from stdin when no path is given (so a ticket attachment can be piped in).
//   - The engine SIGNER PUBLIC key is optional. When supplied (the customer's
//     signer.pub, or the value the console shows under the signer fingerprint), the
//     inner hybrid signature is VERIFIED against it. Without it the bundle still opens,
//     and the tool says plainly that it could not verify provenance.

import { readFileSync } from "node:fs";
import { parseIdentity, parseVerifier } from "../src/crypto/keys.ts";
import { parseKeyFile, LABEL_IDENTITY, LABEL_SIGNER_PUBLIC } from "../src/crypto/keys.ts";
import { parseWraps, openCapsule } from "../src/crypto/capsule.ts";
import { hkdfSha384, aesGcmOpen } from "../src/crypto/primitives.ts";
import { hybridVerify } from "../src/crypto/sign.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { signerFingerprint } from "../src/format/writer.ts";
import { isTier } from "../src/admin/licence.ts";
import { b64urlDecode, sha256Hex, utf8 } from "../src/crypto/bytes.ts";
import type { HybridRecipientPrivate } from "../src/crypto/kem.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import { isEntryPoint } from "../test/lib/verdict-guard.ts";

// These two constants MUST match src/admin/support.ts exactly: the AAD bound into both
// the capsule wrap and the AES-256-GCM ciphertext, and the HKDF info that derives the
// data encryption key from the recovered 32-byte capsule key. A drift in either is a
// hard open failure (the GCM tag will not authenticate), which is the intended outcome:
// the opener never silently accepts a bundle sealed under different parameters.
const AAD = "downpipe/engine support-bundle v1";
const INFO_SUPPORT_BUNDLE_KEY = "downpipe/engine support-bundle-key v1";

/** The kind tag the engine stamps on a sealed bundle (src/admin/support.ts). */
const KIND_SEALED = "downpipe-support-bundle-sealed";
/** The kind tag the engine stamps on the inner (and the unsealed) signed bundle. */
const KIND_SIGNED = "downpipe-support-bundle-signed";
/** The domain label inside the clear-signed band manifest (src/admin/support-band-manifest.ts buildBandManifest). */
const KIND_BAND_MANIFEST = "downpipe-support-band-manifest";

/** A clear, message-only failure the CLI renders as one line (never a stack trace). */
export class SupportOpenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SupportOpenError";
  }
}

/** The shape of a sealed bundle's envelope (the fields the opener reads). */
interface SealedEnvelope {
  kind: string;
  capsule?: Array<{ fingerprint: string; kemCiphertext: string; sealed: string }>;
  iv?: string;
  ciphertext?: string;
}

/** The verdict on the envelope's clear-signed band manifest (buildBandManifest). */
export type BandManifestVerdict = "consistent" | "divergent" | "invalid" | "absent";

/** The outcome of an open: the recovered inner bundle and how provenance checked out. */
export interface OpenResult {
  // "sealed" when a vendor-key-sealed envelope was decrypted; "signed-plain" when the
  // input was already the signed bundle (no vendor key was set on the customer engine).
  form: "sealed" | "signed-plain";
  // The recovered inner bundle as a parsed object (kind downpipe-support-bundle-signed,
  // carrying bundle, signature and signerFingerprint).
  inner: Record<string, unknown>;
  // The canonical JSON bytes that were signed (the inner object), so the caller can
  // re-verify or hash if it wants to.
  signedBytes: Uint8Array;
  // "verified" when a signer public was supplied and both signature halves checked;
  // "unverified" when no signer public was available to check against; "failed" when a
  // signer public was supplied and the signature did NOT verify; "unsigned" when the
  // inner bundle carries no signature (a pre-ceremony engine emits one).
  signature: "verified" | "unverified" | "failed" | "unsigned";
  // The band-manifest verdict: "consistent" when the envelope's clear-signed manifest
  // verifies (own hybrid signature under its CARRIED keys, recomputed fingerprint, and
  // on the sealed form the bodySha256 binding) AND agrees with the unsealed inner bundle
  // (volumes, licence, signer fingerprint); "divergent" when it verifies but disagrees
  // with the inner bundle (a tamper signal: a validly signed manifest from a DIFFERENT
  // pack or engine was grafted on); "invalid" when the manifest is present but its
  // signature, shape, fingerprint or body binding fails; "absent" when the envelope
  // carries no manifest (a pre-manifest or pre-ceremony engine, or stripped in transit).
  manifest: BandManifestVerdict;
}

/**
 * Opens a support bundle. When the input is a sealed envelope, the vendor identity
 * decapsulates the capsule, HKDF-SHA384 derives the data key under INFO_SUPPORT_BUNDLE_KEY,
 * and AES-256-GCM opens the ciphertext under the bound AAD to recover the inner signed
 * bundle. When the input is already the signed bundle, it is returned as-is. The inner
 * hybrid signature is verified against the supplied engine signer public when one is
 * given; otherwise the result reports that provenance could not be checked.
 *
 * @param input - the parsed bundle JSON (a sealed envelope or a signed bundle).
 * @param identity - the held vendor support private identity (only needed for a sealed input).
 * @param signerPub - the engine signer public to verify the inner signature against, or null to skip.
 * @returns the recovered inner bundle and the provenance outcome.
 * @throws SupportOpenError on an unrecognised shape, a wrong key, or a tampered/corrupt bundle.
 */
export async function openSupportBundle(
  input: unknown,
  identity: HybridRecipientPrivate | null,
  signerPub: HybridVerifier | null,
  // parseJson parses the DECRYPTED INNER plaintext — attacker-influenced once a bundle is treated as
  // hostile. Defaults to JSON.parse (the CLI / round-trip tests), but the off-platform diagnosis poller
  // injects its HARDENED single-pass tokenizer here (depth / node-count / string / duplicate-key caps), so
  // the engine's own opener never hands the inner bytes to a permissive parser. Backward-compatible:
  // existing callers pass nothing and get JSON.parse, byte-for-byte as before.
  parseJson: (text: string) => unknown = (t) => JSON.parse(t) as unknown,
): Promise<OpenResult> {
  if (typeof input !== "object" || input === null) {
    throw new SupportOpenError("input is not a JSON object (expected a support bundle).");
  }
  const obj = input as SealedEnvelope & Record<string, unknown>;

  // The signed-plain path: the input is already the inner bundle, nothing to decrypt. The band
  // manifest (when present) rides on this same object; no bodySha256 applies (there is no sealed body).
  if (obj.kind === KIND_SIGNED) {
    const opened = await finishSigned(obj as Record<string, unknown>, "signed-plain", signerPub);
    const manifest = await verifyBandManifest(obj as Record<string, unknown>, null, opened.inner, signerPub);
    return { ...opened, manifest };
  }

  if (obj.kind !== KIND_SEALED) {
    throw new SupportOpenError(
      `unrecognised bundle kind ${JSON.stringify(obj.kind)}; expected ${KIND_SEALED} (sealed) or ${KIND_SIGNED} (signed-plain).`,
    );
  }

  // A sealed envelope needs the vendor identity to decapsulate.
  if (!identity) {
    throw new SupportOpenError("this bundle is sealed; supply the vendor support identity to open it.");
  }
  if (!Array.isArray(obj.capsule) || obj.capsule.length === 0 || typeof obj.iv !== "string" || typeof obj.ciphertext !== "string") {
    throw new SupportOpenError("the sealed bundle is missing its capsule, iv or ciphertext fields (corrupt or truncated).");
  }

  // Decapsulate the capsule with the held identity, derive the data key, AES-256-GCM
  // open the ciphertext. Every failure here (no matching wrap = wrong identity, an
  // authentication failure = wrong key or tampering) is surfaced as one clean line.
  let capsuleKey: Uint8Array;
  try {
    capsuleKey = await openCapsule(parseWraps(obj.capsule), identity, utf8(AAD));
  } catch (e) {
    throw new SupportOpenError(
      `could not open the capsule with this identity: ${msg(e)}. The bundle may be sealed to a different vendor key, or this is the wrong identity.`,
    );
  }

  let plaintext: Uint8Array;
  try {
    const dek = await hkdfSha384(capsuleKey, new Uint8Array(0), utf8(INFO_SUPPORT_BUNDLE_KEY), 32);
    plaintext = await aesGcmOpen(dek, b64urlDecode(obj.iv), b64urlDecode(obj.ciphertext), utf8(AAD));
  } catch (e) {
    throw new SupportOpenError(`the ciphertext failed to authenticate (${msg(e)}); the bundle is corrupt or was altered in transit.`);
  } finally {
    capsuleKey.fill(0);
  }

  let inner: unknown;
  try {
    inner = parseJson(new TextDecoder().decode(plaintext));
  } catch (e) {
    throw new SupportOpenError(`the decrypted payload is not valid JSON (${msg(e)}).`);
  }
  if (typeof inner !== "object" || inner === null || (inner as Record<string, unknown>).kind !== KIND_SIGNED) {
    throw new SupportOpenError(`the decrypted payload is not a ${KIND_SIGNED} bundle.`);
  }

  const opened = await finishSigned(inner as Record<string, unknown>, "sealed", signerPub);
  // The band manifest rides on the ENVELOPE (outside the ciphertext); on the sealed form its
  // bodySha256 must bind to the exact raw ciphertext bytes that were just authenticated and opened.
  const manifest = await verifyBandManifest(obj as Record<string, unknown>, b64urlDecode(obj.ciphertext), opened.inner, signerPub);
  return { ...opened, manifest };
}

// finishSigned verifies the inner signature (when a signer public is available) and packs
// the result, less the band-manifest verdict (the caller appends it: the manifest lives on
// the envelope, and on the sealed form it binds to ciphertext bytes this function never sees).
// The signed-over bytes are the canonical JSON of the INNER bundle's `bundle`
// field, exactly what signedSupportBundle signed.
async function finishSigned(inner: Record<string, unknown>, form: "sealed" | "signed-plain", signerPub: HybridVerifier | null): Promise<Omit<OpenResult, "manifest">> {
  const bundle = inner["bundle"];
  const signature = inner["signature"];
  if (typeof bundle !== "object" || bundle === null) {
    throw new SupportOpenError("the inner bundle is missing its `bundle` body.");
  }
  const signedBytes = canonicalJSON(bundle);

  if (typeof signature !== "string" || signature === "") {
    // A pre-ceremony engine emits an unsigned bundle; that is honest, not an error.
    return { form, inner, signedBytes, signature: "unsigned" };
  }
  if (!signerPub) {
    return { form, inner, signedBytes, signature: "unverified" };
  }
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlDecode(signature);
  } catch (e) {
    throw new SupportOpenError(`the inner signature is not valid base64url (${msg(e)}).`);
  }
  const verified = await hybridVerify(signerPub, signedBytes, sigBytes);
  return { form, inner, signedBytes, signature: verified ? "verified" : "failed" };
}

// verifyBandManifest checks the envelope's clear-signed band manifest against itself and against the
// unsealed inner bundle. Order matters: shape and kind first, then the CARRIED public keys (exact
// lengths, and the fingerprint RECOMPUTED from them must equal the carried fingerprint field, because
// a fingerprint alone cannot verify anything), then the hybrid signature over canonicalJSON(manifest)
// under those carried keys, then the optional pin against a supplied --signer-pub, then the sealed
// form's bodySha256 binding to the raw ciphertext bytes. Only a manifest that survives all of that is
// compared with the inner bundle (volumes, licence, signer fingerprint): agreement is "consistent",
// disagreement is "divergent" (a validly signed manifest grafted from a different pack or engine).
// Any verification failure is "invalid"; no manifest at all is "absent". The whole check is fenced in
// try/catch so a hostile manifest can only ever produce a verdict, never a crash.
async function verifyBandManifest(
  envelope: Record<string, unknown>,
  ciphertextBytes: Uint8Array | null,
  inner: Record<string, unknown>,
  signerPub: HybridVerifier | null,
): Promise<BandManifestVerdict> {
  const manifest = envelope["manifest"];
  const manifestSignature = envelope["manifestSignature"];
  if (manifest === undefined && manifestSignature === undefined) return "absent";
  try {
    if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) return "invalid";
    const m = manifest as Record<string, unknown>;
    if (m["kind"] !== KIND_BAND_MANIFEST) return "invalid";
    if (typeof manifestSignature !== "string" || manifestSignature === "") return "invalid";

    // The carried public keys: exact lengths, and the recomputed fingerprint must match the field.
    const sp = m["signerPublic"];
    if (typeof sp !== "object" || sp === null) return "invalid";
    const edB64 = (sp as Record<string, unknown>)["ed"];
    const mldsaB64 = (sp as Record<string, unknown>)["mldsa"];
    if (typeof edB64 !== "string" || typeof mldsaB64 !== "string") return "invalid";
    const ed = b64urlDecode(edB64);
    const mldsa = b64urlDecode(mldsaB64);
    if (ed.length !== 32 || mldsa.length !== 2592) return "invalid";
    if (m["signerFingerprint"] !== (await signerFingerprint({ ed, mldsa }))) return "invalid";

    // The manifest's own hybrid signature, verified under the CARRIED keys.
    if (!(await hybridVerify({ ed, mldsa }, canonicalJSON(m), b64urlDecode(manifestSignature)))) return "invalid";

    // When the caller pinned a signer public, the carried keys must be exactly that key pair.
    if (signerPub && !(bytesEqual(ed, signerPub.ed) && bytesEqual(mldsa, signerPub.mldsa))) return "invalid";

    // The body binding: the sealed form must carry bodySha256 and it must hash THESE ciphertext
    // bytes; the signed-plain form must not carry it (the inner signature already covers the body).
    const bodySha256 = m["bodySha256"];
    if (ciphertextBytes !== null) {
      if (typeof bodySha256 !== "string" || bodySha256 !== (await sha256Hex(ciphertextBytes))) return "invalid";
    } else if (bodySha256 !== undefined) {
      return "invalid";
    }

    // Verified. Now: does it agree with the unsealed inner bundle? The expected values are derived
    // from the inner bundle by the SAME rules buildBandManifest applies, so the comparison cannot
    // drift from the emitter. A null volumes must match a not-measurable inner rollup exactly.
    const innerBundle = inner["bundle"];
    if (typeof innerBundle !== "object" || innerBundle === null) return "invalid";
    const ib = innerBundle as Record<string, unknown>;

    let expectedVolumes: { totalProtectedBytes: number; accounts: number } | null = null;
    const rawVolumes = ib["volumes"];
    if (typeof rawVolumes === "object" && rawVolumes !== null) {
      const t = (rawVolumes as Record<string, unknown>)["totalProtectedBytes"];
      const a = (rawVolumes as Record<string, unknown>)["accounts"];
      if (typeof t === "number" && Number.isSafeInteger(t) && typeof a === "number" && Number.isSafeInteger(a)) {
        expectedVolumes = { totalProtectedBytes: t, accounts: a };
      }
    }
    const mv = m["volumes"];
    if (mv === null) {
      if (expectedVolumes !== null) return "divergent";
    } else {
      if (typeof mv !== "object" || Array.isArray(mv)) return "invalid";
      const keys = Object.keys(mv as Record<string, unknown>).sort().join(",");
      const t = (mv as Record<string, unknown>)["totalProtectedBytes"];
      const a = (mv as Record<string, unknown>)["accounts"];
      if (keys !== "accounts,totalProtectedBytes" || typeof t !== "number" || !Number.isSafeInteger(t) || typeof a !== "number" || !Number.isSafeInteger(a)) return "invalid";
      if (expectedVolumes === null || t !== expectedVolumes.totalProtectedBytes || a !== expectedVolumes.accounts) return "divergent";
    }

    const rawLicence = ib["licence"];
    const rawTier = typeof rawLicence === "object" && rawLicence !== null ? (rawLicence as Record<string, unknown>)["tier"] : undefined;
    const expectedTier = isTier(rawTier) ? rawTier : undefined;
    const ml = m["licence"];
    if (typeof ml !== "object" || ml === null || Array.isArray(ml)) return "invalid";
    const mlKeys = Object.keys(ml as Record<string, unknown>).sort().join(",");
    if (mlKeys !== "present" && mlKeys !== "present,tier") return "invalid";
    const mPresent = (ml as Record<string, unknown>)["present"];
    const mTier = (ml as Record<string, unknown>)["tier"];
    if (typeof mPresent !== "boolean" || (mTier !== undefined && !isTier(mTier))) return "invalid";
    if (mPresent !== (rawLicence != null) || mTier !== expectedTier) return "divergent";

    // The manifest's fingerprint must be the INNER bundle's signer too, or the manifest was signed
    // by some other engine than the one that signed the body.
    if (m["signerFingerprint"] !== inner["signerFingerprint"]) return "divergent";

    return "consistent";
  } catch {
    return "invalid";
  }
}

// bytesEqual compares two byte arrays for exact equality (public key material; not secret-dependent,
// so constant-time comparison is not required here).
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---- CLI ------------------------------------------------------------------------------

interface Args {
  identityFile?: string;
  identityB64?: string;
  signerPubFile?: string;
  signerPubB64?: string;
  bundleFile?: string;
}

function parseArgs(argv: string[]): Args {
  const a: Args = {};
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === undefined) continue; // unreachable under the loop bound; satisfies the type narrowing.
    const next = (): string => {
      const v = argv[i + 1];
      if (v === undefined) throw new SupportOpenError(`${t} needs a value.`);
      i++;
      return v;
    };
    switch (t) {
      case "--identity":
        a.identityFile = next();
        break;
      case "--identity-b64":
        a.identityB64 = next();
        break;
      case "--signer-pub":
        a.signerPubFile = next();
        break;
      case "--signer-pub-b64":
        a.signerPubB64 = next();
        break;
      case "-h":
      case "--help":
        printUsage();
        process.exit(0);
        break;
      default:
        if (t.startsWith("--")) throw new SupportOpenError(`unknown option ${t}.`);
        if (a.bundleFile !== undefined) throw new SupportOpenError("more than one bundle path was given.");
        a.bundleFile = t;
    }
  }
  return a;
}

function printUsage(): void {
  console.error("Open a downpipe engine support bundle (sealed or signed-plain).");
  console.error("");
  console.error("  node tools/open-support-bundle.ts --identity <file>   [--signer-pub <file>] [bundle.json]");
  console.error("  node tools/open-support-bundle.ts --identity-b64 <b64> [--signer-pub-b64 <b64>] [bundle.json]");
  console.error("  VENDOR_SUPPORT_IDENTITY=<b64> node tools/open-support-bundle.ts [bundle.json]");
  console.error("");
  console.error("The bundle JSON is read from the file path, or from stdin when none is given.");
  console.error("Supply the engine signer public (--signer-pub) to verify the inner signature.");
}

// loadIdentityFromArgs resolves the vendor identity from a file, a raw base64url, or the
// VENDOR_SUPPORT_IDENTITY env var, tolerating either the labelled key-file line or a bare
// base64url value. Returns null when no identity was supplied (a signed-plain bundle needs
// none); a malformed value is a clean error.
function loadIdentityFromArgs(a: Args): HybridRecipientPrivate | null {
  let raw: Uint8Array | null = null;
  if (a.identityFile !== undefined) {
    const text = readFileSync(a.identityFile, "utf8");
    raw = looksLabelled(text, LABEL_IDENTITY) ? parseKeyFile(text, LABEL_IDENTITY) : decodeB64url(text.trim(), "identity file");
  } else if (a.identityB64 !== undefined) {
    raw = decodeB64url(a.identityB64.trim(), "--identity-b64");
  } else if (typeof process.env["VENDOR_SUPPORT_IDENTITY"] === "string" && process.env["VENDOR_SUPPORT_IDENTITY"] !== "") {
    raw = decodeB64url(process.env["VENDOR_SUPPORT_IDENTITY"].trim(), "VENDOR_SUPPORT_IDENTITY");
  }
  if (raw === null) return null;
  try {
    return parseIdentity(raw);
  } catch (e) {
    throw new SupportOpenError(`the vendor identity is not a valid 96-byte hybrid identity: ${msg(e)}.`);
  }
}

// loadSignerPubFromArgs resolves the optional engine signer public, again tolerating the
// labelled key-file line or a bare base64url. Returns null when none was supplied.
function loadSignerPubFromArgs(a: Args): HybridVerifier | null {
  let raw: Uint8Array | null = null;
  if (a.signerPubFile !== undefined) {
    const text = readFileSync(a.signerPubFile, "utf8");
    raw = looksLabelled(text, LABEL_SIGNER_PUBLIC) ? parseKeyFile(text, LABEL_SIGNER_PUBLIC) : decodeB64url(text.trim(), "signer public file");
  } else if (a.signerPubB64 !== undefined) {
    raw = decodeB64url(a.signerPubB64.trim(), "--signer-pub-b64");
  }
  if (raw === null) return null;
  try {
    return parseVerifier(raw);
  } catch (e) {
    throw new SupportOpenError(`the signer public key is malformed: ${msg(e)}.`);
  }
}

function looksLabelled(text: string, label: string): boolean {
  return text.trim().startsWith(label);
}

function decodeB64url(s: string, what: string): Uint8Array {
  try {
    return b64urlDecode(s);
  } catch (e) {
    throw new SupportOpenError(`${what} is not valid base64url: ${msg(e)}.`);
  }
}

async function readStdin(): Promise<string> {
  // Each stdin chunk is a Buffer (a Uint8Array subclass); decode them with TextDecoder so
  // this does not depend on Buffer's typings being present at type-check time.
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Uint8Array);
  let total = 0;
  for (const c of chunks) total += c.length;
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }
  return new TextDecoder().decode(all);
}

async function main(): Promise<void> {
  let a: Args;
  try {
    a = parseArgs(process.argv.slice(2).filter((x) => x !== ""));
  } catch (e) {
    if (e instanceof SupportOpenError) {
      console.error(`error: ${e.message}`);
      printUsage();
      process.exit(2);
    }
    throw e;
  }

  try {
    const identity = loadIdentityFromArgs(a);
    const signerPub = loadSignerPubFromArgs(a);

    const text = a.bundleFile !== undefined ? readFileSync(a.bundleFile, "utf8") : await readStdin();
    if (text.trim() === "") throw new SupportOpenError("no bundle on input (the file or stdin was empty).");
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new SupportOpenError(`the input is not valid JSON (${msg(e)}).`);
    }

    const result = await openSupportBundle(parsed, identity, signerPub);

    // The status line goes to stderr so stdout is exactly the inner bundle JSON (pipeable).
    const where = result.form === "sealed" ? "opened the sealed bundle" : "read the signed-plain bundle";
    const sig =
      result.signature === "verified"
        ? "inner signature VERIFIED against the supplied signer public."
        : result.signature === "failed"
          ? "inner signature DID NOT VERIFY against the supplied signer public (treat the bundle as untrusted)."
          : result.signature === "unsigned"
            ? "the inner bundle is unsigned (a pre-ceremony engine); provenance cannot be checked."
            : "no signer public supplied, so provenance was NOT verified (pass --signer-pub to verify).";
    console.error(`${where}; ${sig}`);
    // The band-manifest verdict on its own stderr line, so intake tooling and a human eye both get
    // the tamper signal without parsing stdout.
    const band =
      result.manifest === "consistent"
        ? "band manifest VERIFIED and CONSISTENT with the bundle."
        : result.manifest === "divergent"
          ? "band manifest DIVERGES from the bundle (tamper signal)."
          : result.manifest === "invalid"
            ? "band manifest present but INVALID (signature, shape or binding failed)."
            : "no band manifest on the envelope.";
    console.error(band);

    process.stdout.write(JSON.stringify(result.inner, null, 2) + "\n");
    // A failed verification is a non-zero exit so a script can gate on it, while still
    // having printed the bundle for inspection.
    if (result.signature === "failed") process.exit(3);
    // A divergent or invalid band manifest is its own non-zero exit (the inner bundle was still
    // printed above for inspection); absence is exit 0, an honest state, never a clean pass claim.
    if (result.manifest === "divergent" || result.manifest === "invalid") process.exit(4);
  } catch (e) {
    if (e instanceof SupportOpenError) {
      console.error(`error: ${e.message}`);
      process.exit(1);
    }
    console.error(`error: ${msg(e)}`);
    process.exit(1);
  }
}

// Run main only when invoked directly, not when imported by the round-trip test.
if (isEntryPoint(import.meta.url)) {
  void main();
}
