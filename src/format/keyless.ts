import { b64urlDecode } from "../crypto/bytes.ts";
import { type HybridVerifier, hybridVerify } from "../crypto/sign.ts";
import { log } from "../log.ts";
import { destAccessReason, REASON_FORMAT_UNSUPPORTED, REASON_OBJECT_MISSING } from "../restore-reasons.ts";
import { validateCanonicalCounts } from "./canonnum.ts";
import { checkRunlogFreshness } from "./freshness.ts";
import { integrityCategoryOf } from "./integrity-error.ts";
import { type KeylessCoverageMode, noteAttestCoverage } from "./integrity-fault-ledger.ts";
import type { RootManifest } from "./manifest.ts";
import { sha384Hex } from "./record-codec.ts";
import { checkFormatVersion, checkRecipientSet } from "./structural-gates.ts";
import type { ObjectStore } from "./types.ts";
import { isValidRunId } from "./ulid.ts";

/**
 * The Tier 0 restorability proof: what can be established about a sealed run WITHOUT any decryption
 * key (no recipient identity, no capsule unwrap) and WITHOUT touching a single record's plaintext.
 * It is the cheapest, most broadly available recoverability signal, runnable even in the
 * break-glass-only posture where the engine holds no in-account read-back key.
 *
 * signatureValid means the stored root manifest verifies under the operator-pinned PUBLIC verifier
 * (a verification key, never a decryption key), so the committed structure is authentic: that one
 * signature covers the merkleRoot, every per-record recordHash, the declared counts and the shard
 * digests. complete means every shard the signed root lists is present and its bytes hash (SHA-384)
 * to the value the signed root pins, and the declared counts are well-formed, so no shard was
 * dropped, truncated or otherwise swapped out (a per-record Merkle recomputation needs the manifest
 * key and belongs to the keyed tiers; keyless attests those fields through the covering signature
 * plus this shard-presence check). notRolledBack means the signed append-only RUNLOG verifies, places this
 * run in the freshness chain with no index gap or fork, and (unless staleness was acknowledged) the
 * run is the latest for its downpipe.
 *
 * Every field is honest: a check that could not be reached (for example the signature failed, so
 * completeness was not evaluated) reports false, never a fabricated pass. reason is a short,
 * coarse, secret-free note on the first failing check, null on a clean attestation.
 */
export interface KeylessAttestation {
  // shardCount is the run's shard count as read from the signed root. Exposed because a caller deciding
  // whether to ALSO run a keyed pass needs it: the keyed path's openShards re-walks the whole shard list
  // with no sampling of its own, so the two passes together cost roughly twice this many subrequests, and
  // that arithmetic is what keeps a large run under the platform cap. Absent when the root never parsed.
  shardCount?: number;
  runId: string;
  // downpipeId is the run's own downpipe id from the SIGNATURE-VERIFIED root manifest (so it is
  // trustworthy even though no key was used), null when the signature did not verify or the manifest was
  // missing (no trustworthy manifest to read the id from). Redaction-safe; never a key or value.
  downpipeId: string | null;
  signatureValid: boolean;
  complete: boolean;
  notRolledBack: boolean;
  reason: string | null;
  // G320: WHAT complete:true actually claims. An unqualified `complete` is three different strengths of claim:
  // every shard read back and hashed (full); a strided sample plus the RL-VAS-05 per-shard PRESENCE pass, so a
  // durably missing shard outside the sample is still caught (sampled); or a strided sample with NO presence
  // pass at all, because the store cannot list() (sampled-no-presence) -- in which case a MISSING shard outside
  // the sample reads as complete. Absent when the completeness pass did not run (the signature failed, or the
  // manifest is structurally invalid), which is honest rather than a fabricated "full".
  coverage?: KeylessCoverageMode;
}

// keylessErrId hashes an exception's constructor name + message to a stable, opaque 8-hex code (FNV-1a),
// mirroring restore.ts's errId: it lets an operator correlate a coarse reason in the response with the
// console.error line WITHOUT the raw exception text ever entering the log or the response. Kept local so
// reader.ts has no cross-module dependency on the restore wrapper.
function keylessErrId(e: unknown): string {
  const name = e instanceof Error ? e.constructor.name : "unknown";
  const msg = e instanceof Error ? e.message : String(e);
  let h = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(`${name}:${msg}`)) {
    h = (Math.imul(h ^ byte, 0x01000193)) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

// coarseKeylessReason maps a caught exception to an ENUMERATED, secret-free reason matching the keyed
// restore tiers (runRestore / runBlindRestoreTest in restore.ts use the same vocabulary), so the keyless
// attestation never returns raw exception text to the client. The raw message could carry shard ids,
// object keys or other internals; the client only ever sees one of these closed reasons. The raw text is
// NEVER returned and NEVER logged in plaintext: this logs only the coarse reason plus an opaque error id
// (keylessErrId, a hash of the raw message) to console.error, exactly as the keyed tiers do, so an
// operator can still correlate the failure. The mapping mirrors the keyed tiers' regex buckets so the two
// surfaces stay consistent. `ctx` is a short call-site tag (which check failed) for the log line.
function coarseKeylessReason(e: unknown, runID: string, ctx: string): string {
  const m = e instanceof Error ? e.message : String(e);
  let reason: string;
  // The TYPED category is read before any prose net: a version-refusal message can otherwise collide with the
  // `is missing` substring match below, which would misclassify it as REASON_OBJECT_MISSING (in the
  // replica-fallback set) and point the caller at a 3-2-1 replica that holds the same signed run and could
  // only refuse again. Reading the category the gate already set removes the coincidence entirely.
  if (integrityCategoryOf(e) === "format-unsupported") reason = REASON_FORMAT_UNSUPPORTED;
  else
  // A COLD-storage-class object (a bucket lifecycle rule silently moved the archive to GLACIER/DEEP_ARCHIVE)
  // reads back as a distinct `thaw-needed` fault (s3-read-ops get() classifies the S3 InvalidObjectState code).
  // Preserve that classification through the reader (checked first of the prose nets) so verify/restore render the actionable
  // cause (bucket-lifecycle-to-glacier) -- the object IS present + recoverable, just unreadable until restored --
  // rather than mislabelling it a generic access error or a missing object.
  if (/thaw-needed|InvalidObjectState|cold storage class/.test(m)) reason = "cold storage class";
  else if (/signature did not verify|key commitment|hash does not match|Merkle root|failed its plaintext hash|disagree/.test(m)) reason = "integrity check failed";
  else if (/is missing|status 404/.test(m)) reason = REASON_OBJECT_MISSING;
  else if (/status \d/.test(m)) reason = destAccessReason(m);
  else if (/RUNLOG|freshness|latest run|stale/.test(m)) reason = "freshness check failed";
  else if (/missing required configuration/.test(m)) reason = "engine not fully configured";
  else reason = "attestation check failed";
  log("error", `attest-keyless ${runID} ${ctx} [err:${keylessErrId(e)} ${reason.replace(/ /g, "-")}]`);
  return reason;
}

/**
 * Performs the Tier 0 keyless integrity attestation. It needs no decryption key and reads no record
 * plaintext: it verifies the root signature under the public verifier, re-checks the recipient-set
 * structural gate, confirms every listed shard is present and hashes to the signed root, and runs
 * the RUNLOG freshness / anti-rollback check (the same checkRunlogFreshness the drill uses). It is
 * deliberately total: every check is wrapped so a missing object or a malformed manifest yields a
 * false verdict with a coarse enumerated reason rather than an exception, and the raw exception
 * text (which could carry an object key or shard id) never leaves the function.
 *
 * @param store - the read side of the destination holding the run objects.
 * @param runID - the run id to attest.
 * @param verifier - the operator-pinned public hybrid verifier.
 * @param opts - options: allowStale defaults to true so an older run still attests (notRolledBack
 *   reflects latest-ness honestly); pass allowStale:false to require the run be the latest for its
 *   downpipe. minRunlogIndex (HI-05) is an out-of-band account-global RUNLOG high-water mark (e.g. the
 *   scheduler DO's own runlogCounter): supplying it lets checkRunlogFreshness catch a whole-document
 *   replay of an older, internally-consistent, validly-signed RUNLOG that a chain-anomaly check alone
 *   cannot see, since that check is unconditional (see freshness.ts's rollbackDetected) regardless of
 *   allowStale; omitted, no pin is applied. shardCheck defaults to
 *   "full" (read back EVERY listed shard) and is what the offline CLI
 *   and the periodic drill always use; the at-seal caller may pass a bounded form {sampleAbove, sample}
 *   so a VERY large run does not trip the platform subrequest cap re-reading thousands of shards (Fix-A):
 *   the run stays FULL while shardCount <= sampleAbove, and above it reads a strided SAMPLE of `sample`
 *   shards. The root SIGNATURE already authenticates every shard's pinned sha384 in-memory at sign time,
 *   so the read-back is a durability smoke test, not the cryptographic completeness proof -- sampling it
 *   weakens nothing the signature plus the always-full offline/drill path guarantee.
 * @returns the three-flag KeylessAttestation with a coarse, secret-free reason; it does not throw.
 */
export async function attestKeyless(store: ObjectStore, runID: string, verifier: HybridVerifier, opts: { allowStale?: boolean; shardCheck?: "full" | { sampleAbove: number; sample: number }; minRunlogIndex?: number } = {}): Promise<KeylessAttestation> {
  const allowStale = opts.allowStale ?? true;
  const shardCheck = opts.shardCheck ?? "full";
  // HI-09: same shared-chokepoint shape gate as openRun (reader.ts) -- runID feeds the identical
  // `run/${runID}/...` key template, so a non-ULID shape must be refused here too, before the
  // first store.get, rather than trust the router (or a future caller) to have checked upstream.
  if (!isValidRunId(runID)) {
    return { runId: runID, downpipeId: null, signatureValid: false, complete: false, notRolledBack: false, reason: "invalid runId" };
  }
  // 1) Root signature. Read the stored root bytes and the detached signature, verify under the
  // operator-pinned PUBLIC verifier. A missing object or a non-verifying signature is signatureValid:
  // false, and the later checks are NOT evaluated (a manifest we cannot trust must not have its body
  // parsed as authoritative), so they report false too.
  let rootBytes: Uint8Array;
  let root: RootManifest;
  try {
    rootBytes = await store.get(`run/${runID}/root.manifest.json`);
    const sigText = new TextDecoder().decode(await store.get(`run/${runID}/root.manifest.json.sig`));
    const sig = b64urlDecode(sigText.trim());
    if (!(await hybridVerify(verifier, rootBytes, sig))) {
      return { runId: runID, downpipeId: null, signatureValid: false, complete: false, notRolledBack: false, reason: "root signature did not verify" };
    }
  } catch (e) {
    // A cold-storage-class root (bucket-lifecycle-to-glacier) reads back as a thrown thaw-needed fault, DISTINCT
    // from a genuinely absent root: preserve the classification (the object is present + recoverable, just
    // unreadable until restored) so verify/restore render the actionable cause instead of "object missing".
    const cold = /thaw-needed|InvalidObjectState|cold storage class/.test(String((e as Error)?.message ?? ""));
    return { runId: runID, downpipeId: null, signatureValid: false, complete: false, notRolledBack: false, reason: cold ? "cold storage class" : "root manifest or signature missing" };
  }
  // The signature verified, so the root body is authentic. Parse and structurally validate it the same
  // way openRun does (canonical-numeric gate, format-version major, runId match, recipient-set gate),
  // all of which are key-free. A failure here is a structurally invalid (but signed) run: report it as
  // not-complete with the reason, signature still valid.
  try {
    const rootText = new TextDecoder().decode(rootBytes);
    validateCanonicalCounts(rootText, "declaredRecordCount", "shardCount", "freshness.runlogIndex");
    root = JSON.parse(rootText) as RootManifest;
    checkFormatVersion(root.formatVersion);
    if (root.runId !== runID) throw new Error("manifest runId does not match the requested run");
    await checkRecipientSet(root);
  } catch (e) {
    // A structurally invalid (but signed) run: the signature held, the body did not validate. Report a
    // coarse, enumerated reason; the raw message (which could name an internal field) never leaves here.
    return { runId: runID, downpipeId: null, signatureValid: true, complete: false, notRolledBack: false, reason: coarseKeylessReason(e, runID, "structure") };
  }

  // 2) Completeness: every shard the signed root lists must be present and hash to the signed value, so
  // no shard was dropped, truncated or swapped. The shard SHA-384 is in the signed root, so this binds
  // the stored bytes to the signature without any key. The declared counts being canonical was checked
  // above. This is the keyless completeness proof; a per-record Merkle recomputation needs the key.
  let complete = false;
  let completeReason: string | null = null;
  // shardCountSeen is captured for the caller: a keyed pass re-walks the whole shard list, so a caller
  // deciding whether to run one needs the count to keep the combined subrequest cost under the cap.
  let shardCountSeen: number | undefined;
  // G320: the coverage mode this completeness pass ACTUALLY achieved, decided below and returned beside the
  // verdict so complete:true is never read as a stronger claim than the one that was made.
  let coverage: KeylessCoverageMode | undefined;
  try {
    const total = root.shards.length;
    shardCountSeen = total;
    // FULL (the default; offline CLI + drill) reads back EVERY listed shard; the run also stays full when
    // it is small (shardCount <= sampleAbove), so the common at-seal verdict is byte-identical to today.
    const full = shardCheck === "full" || total <= shardCheck.sampleAbove;
    coverage = "full";
    if (full) {
      for (const shard of root.shards) {
        const shardBytes = await store.get(shard.object);
        if ((await sha384Hex(shardBytes)) !== shard.sha384) {
          throw new Error(`shard ${shard.id} hash does not match the signed root`);
        }
      }
      if (root.shards.length !== root.shardCount) {
        throw new Error(`shard objects (${root.shards.length}) disagree with the declared shardCount (${root.shardCount})`);
      }
    } else {
      // Fix-A bounded form for a very large run: the count cross-check first (NO read; the root signature
      // already pins every shard's sha384), then a strided SAMPLE of shards read back as a durability
      // smoke test, so the at-seal verify never trips the platform subrequest cap. Striding (not the head)
      // so a corruption in a late shard is as likely to be sampled as an early one.
      if (root.shards.length !== root.shardCount) {
        throw new Error(`shard objects (${root.shards.length}) disagree with the declared shardCount (${root.shardCount})`);
      }
      // RL-VAS-05 PRESENCE pass: the strided GET sample below only spot-checks min(sample,N) shards, so a
      // durably-MISSING shard OUTSIDE that sample would otherwise pass as "complete" at seal (a false green).
      // Close it with ONE list of the run's manifest/ prefix, cross-referenced BY NAME against the signed
      // shard list: a signed shard whose object is absent is a completeness shortfall (a dropped shard), so
      // throw -> suspect. This is one LIST per ~1000 shards, not N per-shard GETs, so it stays within the
      // subrequest budget. When the store cannot LIST (a minimal offline double), the presence pass is skipped
      // and only the strided GET spot-checks run (the always-FULL offline/drill path reads every shard anyway,
      // so it needs no presence pass). The strided hash spot-checks below still run either way.
      // G320: WHICH of the two sampled modes this is. With list() the presence pass runs and a missing shard
      // outside the strided sample is still caught (sampled). WITHOUT it the pass is silently skipped and
      // complete:true becomes a WEAKER claim -- only min(sample,N) shards were looked at, so a durably missing
      // shard elsewhere in the run reads as complete. This mode is recorded as a closed enum on the
      // attestation AND a row in the run's integrity evidence.
      if (typeof store.list === "function") {
        coverage = "sampled";
        const present = new Set(await store.list(`run/${runID}/manifest/`));
        for (const shard of root.shards) {
          if (!present.has(shard.object)) {
            throw new Error(`shard ${shard.id} object is missing from the run manifest listing`);
          }
        }
      } else {
        coverage = "sampled-no-presence";
      }
      const want = Math.min(shardCheck.sample, total);
      const stride = want > 0 ? Math.max(1, Math.floor(total / want)) : 1;
      let sampled = 0;
      for (let i = 0; i < total && sampled < want; i += stride) {
        const shard = root.shards[i]!;
        const shardBytes = await store.get(shard.object);
        if ((await sha384Hex(shardBytes)) !== shard.sha384) {
          throw new Error(`shard ${shard.id} hash does not match the signed root`);
        }
        sampled++;
      }
    }
    complete = true;
  } catch (e) {
    // Coarse, enumerated reason only: a shard-mismatch message could carry a shard id / object key.
    completeReason = coarseKeylessReason(e, runID, "completeness");
  }
  // G320: record the DEGRADED coverage modes into the run's integrity evidence (noteAttestCoverage is a no-op
  // for "full", so a healthy fleet stays silent). This is the one piece of evidence in the ledger that rides a
  // run reporting a CLEAN verdict, which is exactly the point: the overclaim is invisible by construction.
  if (coverage !== undefined) noteAttestCoverage(coverage);

  // 3) Anti-rollback: the signed RUNLOG places this run in the freshness chain with no anomaly and (unless
  // staleness is acknowledged) as the latest for its downpipe. checkRunlogFreshness is key-free (it only
  // needs the public verifier), so it runs in the keyless tier exactly as in the drill.
  let notRolledBack = false;
  let freshnessReason: string | null = null;
  try {
    const freshness = await checkRunlogFreshness(store, runID, root, verifier, { allowStale, ...(opts.minRunlogIndex !== undefined ? { minRunlogIndex: opts.minRunlogIndex } : {}) });
    // HI-05: rollbackDetected is unconditional (never masked by allowStale), so a chain anomaly or a
    // breach of an out-of-band minRunlogIndex pin always fails notRolledBack, even for a whole-document
    // replay that is itself internally consistent (freshness.ok/isLatestForDownpipe alone cannot see it,
    // since both are computed from the same possibly-replayed document).
    notRolledBack = freshness.ok && freshness.isLatestForDownpipe && !freshness.rollbackDetected;
    // freshness.reason is a fixed, secret-free enumeration from checkRunlogFreshness (e.g. "not the latest
    // run for this downpipe"), so it is safe to surface verbatim; only a THROWN exception below could carry
    // raw internals, and that is coarsened.
    if (!notRolledBack) freshnessReason = freshness.reason ?? "run is not the latest for its downpipe";
  } catch (e) {
    // Coarse, enumerated reason only: a thrown freshness error could carry an object key in its message.
    freshnessReason = coarseKeylessReason(e, runID, "freshness");
  }

  return {
    runId: runID,
    downpipeId: root.downpipeId,
    signatureValid: true,
    complete,
    notRolledBack,
    ...(shardCountSeen !== undefined ? { shardCount: shardCountSeen } : {}),
    reason: completeReason ?? freshnessReason,
    ...(coverage !== undefined ? { coverage } : {}),
  };
}
