import { b64urlDecode, constantTimeEqual, hexDecode } from "../crypto/bytes.ts";
import { recipientFingerprint, recipientSetHash } from "../crypto/capsule.ts";
import type { HybridRecipientPublic } from "../crypto/kem.ts";
import { formatUnsupportedError, integrityError } from "./integrity-error.ts";
import type { RootManifest } from "./manifest.ts";

// The key-free structural gates the in-account verifying reader enforces before any capsule unwrap,
// shared by openRun (the keyed path) and attestKeyless (the Tier 0 keyless path). Both are
// byte-for-byte ports of the Go reference reader.

/**
 * checkRecipientSet enforces the SPEC 8.6 structural gate the Go reference reader enforces
 * (reader.go checkRecipientSet). A break-glass
 * recipient must be declared present, each listed fingerprint must actually belong to its
 * public key, exactly one recipient must be the break-glass role, every master-capsule wrap
 * must address a listed recipient and the wraps must cover the recipient set, and the
 * recipient-set hash must recompute to the signed value. Without it a retargeted or dropped
 * capsule wrap, or a missing break-glass recipient, would pass the second reader.
 *
 * It runs on the SIGNATURE-VERIFIED root and BEFORE any capsule unwrap, so a recipient-set
 * violation is reported as itself rather than as a failed decap. It returns nothing and
 * signals every refusal by throwing integrityError, i.e. a NON-fallback fault: a 3-2-1 replica
 * holds the same signed run, so re-reading it there would only mask the violation.
 */
export async function checkRecipientSet(root: RootManifest): Promise<void> {
  if (!root.breakGlassPresent) throw integrityError("manifest does not declare a break-glass recipient present");
  const pubs: HybridRecipientPublic[] = [];
  const recipientFP = new Map<string, number>();
  let breakGlass = 0;
  for (const rc of root.recipients) {
    const x25519 = b64urlDecode(rc.x25519);
    const mlkemEk = b64urlDecode(rc.mlkem);
    if (x25519.length !== 32) throw integrityError("recipient x25519 must be 32 bytes");
    if (mlkemEk.length !== 1568) throw integrityError("recipient mlkem must be 1568 bytes");
    if ((await recipientFingerprint(x25519, mlkemEk)) !== rc.fingerprint) {
      throw integrityError("recipient fingerprint does not match its public key");
    }
    pubs.push({ x25519, mlkemEk });
    recipientFP.set(rc.fingerprint, (recipientFP.get(rc.fingerprint) ?? 0) + 1);
    if (rc.role === "break-glass") breakGlass++;
  }
  if (breakGlass !== 1) throw integrityError(`expected exactly one break-glass recipient, found ${breakGlass}`);

  // Every wrap must address a listed recipient, and the wraps must cover the set, so a wrap
  // cannot be added, dropped or retargeted relative to the signed recipients.
  const wrapFP = new Map<string, number>();
  for (const w of root.masterCapsule) {
    if (!recipientFP.has(w.fingerprint)) throw integrityError("master-capsule wrap addresses an unlisted recipient");
    wrapFP.set(w.fingerprint, (wrapFP.get(w.fingerprint) ?? 0) + 1);
  }
  if (wrapFP.size !== recipientFP.size) throw integrityError("master-capsule wraps do not cover the recipient set");

  if (!constantTimeEqual(await recipientSetHash(pubs), hexDecode(root.recipientSetHash))) {
    throw integrityError("recipient-set hash does not match the listed recipients");
  }
}

/**
 * checkRootStructure is a lightweight shape gate run straight after JSON.parse of the signed
 * root manifest, before any field is dereferenced. The JSON.parse cast to RootManifest is
 * unchecked, so without this gate a missing or mistyped required field would surface as a generic
 * TypeError deep in a downstream accessor rather than a clear format violation. The signature is
 * checked first and the signed JSON is operator-controlled, so this is defence in depth, not a
 * bypass guard: it confirms the required array fields (shards, recipients, masterCapsule) are
 * arrays and the required string fields are strings.
 *
 * It checks PRESENCE and TYPE only, never the contents: an empty shards array or an unparsable
 * fingerprint passes here and is caught by the gate that owns it. Refusals throw integrityError.
 */
export function checkRootStructure(root: RootManifest): void {
  const arrayFields = ["shards", "recipients", "masterCapsule"] as const;
  for (const f of arrayFields) {
    if (!Array.isArray((root as unknown as Record<string, unknown>)[f])) {
      throw integrityError(`manifest field ${JSON.stringify(f)} must be an array`);
    }
  }
  const stringFields = ["runId", "formatVersion", "merkleRoot", "keyCommitment", "recipientSetHash"] as const;
  for (const f of stringFields) {
    if (typeof (root as unknown as Record<string, unknown>)[f] !== "string") {
      throw integrityError(`manifest field ${JSON.stringify(f)} must be a string`);
    }
  }
}

/**
 * IMPLEMENTED_FORMAT_VERSIONS is the set of major.minor format identities this build reads, at any patch.
 * It mirrors the Go reference `ImplementedFormatVersions` (verify.go). The format is semver'd below 1.0
 * (downpipe/0.MINOR.PATCH): while the major is 0 a byte-level rule change bumps the MINOR and is a
 * different, incompatible format identity, so this build accepts exactly its own major.minor at any patch.
 *
 * Pinned here as literals rather than read from version.ts VERSION, so widening what this reader opens is
 * a deliberate edit to this gate rather than a side effect of bumping the writer.
 */
const IMPLEMENTED_FORMAT_VERSIONS = ["0.1"] as const;

/** readerSupportSummary renders the implemented set the way the refusal message quotes it, e.g. "downpipe/0.1.x". */
function readerSupportSummary(): string {
  return IMPLEMENTED_FORMAT_VERSIONS.map((unit) => `downpipe/${unit}.x`).join(", ");
}

/**
 * isCanonicalVersionNumber reports whether s is a canonical decimal semver component: one or more ASCII
 * digits with no leading zero before another digit (SPEC 13). Mirrors the Go reference's function of the
 * same name. It is what stops "0.1.x", "0.1.0 " and "01.1.0" being read as versions at all.
 */
function isCanonicalVersionNumber(s: string): boolean {
  if (!/^[0-9]+$/.test(s)) return false;
  return s.length === 1 || s[0] !== "0";
}

/**
 * checkFormatVersion refuses any formatVersion this build does not implement (SPEC 13, 13.1, 14.3
 * unknown-major and unimplemented-minor), mirroring the Go reference verify.go checkFormatVersion. The
 * expected form is "downpipe/MAJOR.MINOR.PATCH" with every component a canonical decimal integer.
 *
 * IT SEPARATES THREE REFUSALS THAT MEAN DIFFERENT THINGS TO WHOEVER IS HOLDING THE ARCHIVE, and the split
 * is the whole point of this function rather than a nicety.
 *
 *   1. Not a downpipe label at all ("age/1.0.0").
 *   2. A MALFORMED label ("downpipe/0.1", "downpipe/0.1.x", a trailing space, a fourth component): the
 *      version field is not a version, so no reader anywhere implements it.
 *   3. A WELL-FORMED version outside the implemented set ("downpipe/0.2.0"): the bytes are fine and the
 *      reader is the wrong build.
 *
 * ONLY CASE 3 IS A FORMAT MISMATCH, and only case 3 gets formatUnsupportedError. Every other refusal throws
 * integrityError, which restore-reasons.ts renders as the integrity reason and the console renders as a
 * failed integrity check. Case 3 stays non-fallback, because a 3-2-1 replica holds the SAME signed run
 * carrying the SAME label and a replica walk could only refuse again.
 *
 * WHY CASES 1 AND 2 ARE INTEGRITY, WHERE THE GO READER PUTS ALL THREE ON ExitUsage. The Go reader opens an
 * arbitrary file it has not yet authenticated, so "these are not our bytes" is a usage error there. This
 * gate runs at three call sites (reader.ts openRun and readRunCapsule, keyless.ts attestKeyless) and at
 * every one of them the root signature has ALREADY verified under the operator-pinned signer. So the label
 * is inside bytes we provably wrote and signed, and a label that is not a version cannot be a foreign
 * archive or a stale writer: it is an anomaly in our own signed manifest. Reporting it as a format mismatch
 * would also make the remedy a lie, because no reader implements a malformed label and there is nothing for
 * the customer to go and fetch. The strictest answer is the true one in both cases.
 *
 * THE PRECEDENCE RULE IS PRESERVED. Case 3 is reachable only for a label that is syntactically a valid
 * version identity naming a major.minor this build does not implement. That is a fact about which build is
 * reading, established without running any check over any byte, so no check that genuinely failed can land
 * there and a real tamper cannot be softened into it.
 *
 * ALL THREE COMPONENTS ARE PART OF THE VERSION, which is why a two-component label is case 2 and not
 * case 3, and the arity requirement is load-bearing rather than tidy. "downpipe/0.1" carries the same two
 * numbers this build implements, so matching on the numbers alone would accept it, and it is a DIFFERENT
 * format: its derivation labels would read "downpipe/0.1 <purpose>" and derive every key to different
 * bytes. It would decrypt nothing and report an authentication failure over intact bytes, which is the
 * exact failure this gate exists to prevent.
 *
 * WHY THERE IS NO BRANCH HERE FOR A MAJOR.MINOR LABEL. That was the identity scheme of a pre-release
 * lineage of this format, retired. No reader implementing it was ever published, none is
 * obtainable, and the update channel no longer offers an engine artefact that stamps one, so nothing a
 * person can install emits a two-component label. A branch softening case 2 for it would close by naming a
 * different reader build to go and fetch, and that build does not exist and will not be published: mid
 * recovery, a remedy nobody can act on is worse than a blunt one.
 *
 * THE ORDERING THIS DEPENDS ON. This function is only correct while no obtainable engine build stamps a
 * two-component label. If one is ever offered again, case 2 is telling the holder of intact bytes that
 * their signed manifest is anomalous, which is the most expensive wrong thing it could say. The check that
 * falls in that case is the harness census scripts/reader-pairing-census.mjs, which fails when the update
 * channel offers a writer whose format label no reader ref implements.
 *
 * v is the manifest's formatVersion label, checked as text. Every refusal quotes the offending label
 * JSON-encoded, which is safe because the label is a format constant, not a customer value.
 */
export function checkFormatVersion(v: string): void {
  const prefix = "downpipe/";
  if (!v.startsWith(prefix)) {
    throw integrityError(`formatVersion ${JSON.stringify(v)} is not a downpipe version label`);
  }
  const rest = v.slice(prefix.length);
  // Bounded at three the way the Go reference's SplitN is, so a fourth component lands in the third part
  // and is caught as non-canonical. An unbounded split let "downpipe/0.1.0.0" through the arity check and
  // then past the major.minor comparison, so this build ACCEPTED a label it does not implement.
  const parts = splitN(rest, ".", 3);
  // The message names both ways this refusal fires, arity and canonicality, because it fires for both.
  // Saying only "every component must be a decimal number" is a false description of "downpipe/0.1",
  // whose components are all decimal numbers, and a false description is what sends somebody hunting the
  // wrong thing in an already bad hour.
  if (parts.length !== 3 || !parts.every(isCanonicalVersionNumber)) {
    throw integrityError(
      `formatVersion ${JSON.stringify(v)} is not a downpipe version label at all: after ${JSON.stringify(prefix)} it must read MAJOR.MINOR.PATCH, with all three components present and each one a canonical decimal number, and this one does not. No downpipe reader implements it, because it does not name a version. Treat this root manifest as damaged or hand-edited, and check the archive's other copies before anything else`,
    );
  }
  const unit = `${parts[0]}.${parts[1]}`;
  if ((IMPLEMENTED_FORMAT_VERSIONS as readonly string[]).includes(unit)) return;
  throw formatUnsupportedError(
    `formatVersion ${JSON.stringify(v)}: this build implements ${readerSupportSummary()} and does not implement ${unit}, so it will not read this archive. Nothing is wrong with the bytes, nothing has been lost and nothing was written. Get a downpipe reader that implements ${unit}: each release's CHANGELOG.md entry names the format versions that release reads (https://github.com/downpipes-io/downpipe). No override reads a format this build does not implement`,
  );
}

/**
 * splitN splits s on sep into at most n parts, leaving any remaining separators inside the final part.
 * JavaScript's String.prototype.split takes a limit that DISCARDS the tail instead of keeping it, which is
 * the opposite of Go's SplitN and would silently accept "downpipe/0.1.0.0" by throwing the extra component
 * away. Written out rather than worked around at the call site so the difference is stated where it bites.
 */
function splitN(s: string, sep: string, n: number): string[] {
  const out: string[] = [];
  let from = 0;
  while (out.length < n - 1) {
    const i = s.indexOf(sep, from);
    if (i === -1) break;
    out.push(s.slice(from, i));
    from = i + sep.length;
  }
  out.push(s.slice(from));
  return out;
}
