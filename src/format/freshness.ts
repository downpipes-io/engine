import { b64urlDecode, hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type HybridVerifier, hybridVerify } from "../crypto/sign.ts";
import { classifyFetchFault, type FetchFaultClass, type FetchStatusClass, noteFailStage, noteFetchFault, noteRunlogAnomaly, type RunlogAnomalyKind } from "./integrity-fault-ledger.ts";
import type { RootManifest } from "./manifest.ts";
import type { ObjectStore } from "./types.ts";
import { parseRunlog, type RunlogEntry } from "./writer.ts";

// The RUNLOG freshness / anti-rollback check, ported from the Go reader (SPEC 10, 8.7).
// It verifies the signed append-only RUNLOG against the operator-pinned signer, confirms
// the run is present and agrees with the signed root, and requires the run to be the
// latest for its downpipe unless staleness is acknowledged. Used by the in-account drill.

/**
 * The outcome of the RUNLOG freshness / anti-rollback check: whether the run passed (honouring
 * allowStale), whether it is the latest for its downpipe, the downpipe's max RUNLOG index, this
 * run's index, and a short secret-free reason on a non-clean result. rollbackDetected is a SEPARATE,
 * unconditional signal (mirrors the Go reader's RollbackWarning): true whenever the anti-rollback
 * check did not clear this run by a route allowStale was never meant to cover -- an internal chain
 * anomaly, the account-global max falling below an out-of-band minRunlogIndex pin, or a check that
 * could not be run at all (see checked) -- regardless of allowStale/ok. ORDINARY STALENESS IS THE ONE
 * THING IT DOES NOT COVER: a legitimately older run in a verified, clean chain leaves it false, which
 * is exactly what allowStale exists to proceed past. A caller making a real trust decision
 * (attestKeyless, openRun) must treat rollbackDetected as an unconditional failure.
 *
 * The Go reader (internal/format/freshness.go) applies the identical rule with the same two fields, and
 * this port matches it.
 */
export interface FreshnessResult {
  ok: boolean;
  isLatestForDownpipe: boolean;
  maxIndexForDownpipe: number;
  runlogIndex: number;
  reason?: string;
  rollbackDetected: boolean;
  // Whether the check RAN to a verdict. False when nothing was established: the RUNLOG or its signature could
  // not be read, the signature did not verify, or the document does not carry this run in a form that binds to
  // the signed root. It is the strictly stronger half of rollbackDetected, which is also true in every one of
  // those cases: a check that ran and found a problem is a FINDING, a check that could not run is an UNKNOWN,
  // and an operator deciding whether to restore needs to be told which one they hold. It also disambiguates
  // isLatestForDownpipe, which reads false for "this is deliberately an older run" and for "nothing was
  // established" alike. Named to match the reader's receipt field (SPEC 8.5, ReceiptFreshness.checked) so the
  // two implementations report the same fact under the same name.
  checked: boolean;
  // G011: WHY the RUNLOG read failed, when it did. The reason string says "RUNLOG absent" for a 403 after a
  // credential rotation, a 429 throttle and a lifecycle move to cold storage alike -- so support tells the
  // customer their object is gone while it is plainly sitting in the bucket. This closed class (and its HTTP
  // status class) is the difference. Absent when the RUNLOG was read successfully.
  fetchFault?: FetchFaultClass;
  fetchStatusClass?: FetchStatusClass;
}

/**
 * Options for the freshness check: minRunlogIndex pins the account-global RUNLOG high-water mark
 * (reject below it), and allowStale proceeds despite a stale or rolled-back run while still
 * recording it.
 */
export interface FreshnessOptions {
  minRunlogIndex?: number; // reject if the downpipe's max index is below this pin
  allowStale?: boolean; // proceed despite a stale/rolled-back run, recording it
}

/**
 * Runs the RUNLOG freshness / anti-rollback check (SPEC 10, 8.7): verifies the signed append-only
 * RUNLOG against the operator-pinned signer, confirms the run is present and agrees with the
 * signed root, rejects any chain anomaly, applies the min-index pin, and requires the run to be
 * the latest for its downpipe unless staleness is acknowledged.
 *
 * @param store - the read side of the destination holding the RUNLOG.
 * @param runId - the run id being checked.
 * @param root - the run's signed root manifest (its freshness fields are cross-checked).
 * @param verifier - the operator-pinned hybrid signer the RUNLOG signature must verify under.
 * @param opts - freshness options (min-index pin and allow-stale).
 * @returns a FreshnessResult rather than throwing. ok reflects allowStale on a check that RAN and found the
 *   run stale or rolled back; a check that could not run at all returns ok:false, rollbackDetected:true and
 *   checked:false whatever allowStale says, because stale tolerance is about the age of a run and not about
 *   whether the document proving that age is intact.
 */
export async function checkRunlogFreshness(store: ObjectStore, runId: string, root: RootManifest, verifier: HybridVerifier, opts: FreshnessOptions = {}): Promise<FreshnessResult> {
  // The UNCHECKED result every early return below carries: the check did not run, so it did not pass, and
  // nothing here is evidence that no rollback occurred. All three fields say so.
  //
  //  - checked:false           -- nothing was established.
  //  - rollbackDetected:true   -- the unconditional signal every real trust decision gates on. It is set here
  //                               because a caller that reads only this field must still refuse; reading it as
  //                               "proof of a clean chain" is what let a deleted RUNLOG through.
  //  - ok:false, ignoring allowStale -- stale tolerance is about the AGE of a run, not about whether the
  //                               document that would prove its age is intact. Conflating the two is the whole
  //                               defect: it made a forged signature quieter than a benign pin miss.
  //
  // Written once rather than at each return because the defect this replaces was exactly one shared helper
  // getting it wrong for five call sites, and five hand-written literals is how it comes back for one of them.
  const fail = (reason: string): FreshnessResult => ({ ok: false, isLatestForDownpipe: false, maxIndexForDownpipe: 0, runlogIndex: root.freshness.runlogIndex, reason, rollbackDetected: true, checked: false });

  let runlogBytes: Uint8Array;
  let sigText: Uint8Array;
  try {
    runlogBytes = await store.get("_RECOVERY/RUNLOG");
    sigText = await store.get("_RECOVERY/RUNLOG.sig");
  } catch (e) {
    // G011: the store's error names the real cause (403 after a credential rotation, 429, a lifecycle move to
    // a restore-required tier, a network fault), so the pack must not say "RUNLOG absent" for all of them
    // alike. classifyFetchFault reads the message ONLY to select the two closed enums and returns them; the
    // message -- which embeds the object key and the endpoint host -- is never stored, never logged and never
    // returned.
    const { cls, statusClass } = classifyFetchFault(e);
    noteFetchFault("runlog", e);
    noteFailStage("freshness-signature");
    // The anomaly ring is where a tamper-vs-corruption investigation starts, and an ABSENT RUNLOG left it
    // empty: the one state with no document to hash and no chain to inspect produced no row at all, so the
    // quietest attack on the chain (delete it) was also the least evidenced. There is no digest to carry (the
    // bytes were never read); the fetch-fault class above says whether it was denied, throttled or gone.
    noteRunlogAnomaly({ kind: "runlog-absent" });
    return { ...fail("RUNLOG absent"), fetchFault: cls, fetchStatusClass: statusClass };
  }
  // G102: the one-way digest of the RUNLOG BYTES, so every anomaly row below can be JOINED to the document
  // that produced it. The customer can hash their own _RECOVERY/RUNLOG object and compare this prefix: if it
  // matches, support and the customer are reasoning about the same bytes (a corruption is durable, in the
  // bucket); if it does not, the object has CHANGED since the engine read it, which is itself the finding.
  // The digest is one-way and carries nothing back to us; no line content ever leaves this function.
  const digest = await runlogDigestField(runlogBytes);

  const sig = b64urlDecode(new TextDecoder().decode(sigText).trim());
  if (!(await hybridVerify(verifier, runlogBytes, sig))) {
    noteFailStage("freshness-signature");
    // G102: a RUNLOG whose own signature will not verify is either a TAMPER or a destination-side bit-flip,
    // and today it persisted as one coarse reason string with no evidence at all. The digest is what lets the
    // customer prove which: a bit-flip changes the bytes, a re-signed forgery does not.
    noteRunlogAnomaly({ kind: "sig-invalid", ...digest });
    return fail("RUNLOG signature did not verify");
  }

  // G102: a RUNLOG line that will not parse (a corrupt index, a missing runId, a destination-side bit-flip)
  // throws out of here and is coarsened to "attestation check failed" three frames up. writer-runlog.ts notes
  // WHICH line and WHICH field failed the shape gate; this adds the document digest to the same evidence and
  // rethrows, so the caller's control flow is byte-for-byte unchanged.
  let entries: RunlogEntry[];
  try {
    entries = parseRunlog(runlogBytes);
  } catch (e) {
    noteFailStage("freshness-chain");
    noteRunlogAnomaly({ kind: "parse-field", ...digest });
    throw e;
  }
  const here = entries.find((e) => e.runId === runId);
  // G056: the three RUNLOG-INDEX disagreements are one stage (the document does not agree with the signed
  // root) and are a different ticket from a signature that will not verify or a chain that is anomalous.
  if (!here) {
    noteFailStage("freshness-index");
    // A signed, well-formed document that does not carry this run at all: the entry was removed, and the row
    // records the index the signed root claims for it plus the chain length it was looked for in.
    noteRunlogAnomaly({ kind: "run-missing", indexA: root.freshness.runlogIndex, entryCount: entries.length, ...digest });
    return fail("run not present in the RUNLOG");
  }
  if (here.index !== root.freshness.runlogIndex) {
    noteFailStage("freshness-index");
    // The DISAGREEING PAIR is the whole finding: indexA is the index the RUNLOG carries for this run, indexB
    // the index its signed root claims. Two independently signed documents disagree about the same run.
    noteRunlogAnomaly({ kind: "root-disagreement", indexA: here.index, indexB: root.freshness.runlogIndex, entryCount: entries.length, ...digest });
    return fail("RUNLOG index disagrees with the signed root");
  }
  const maxForDownpipe = entries.filter((e) => e.downpipeId === root.downpipeId).reduce((m, e) => Math.max(m, e.index), 0);
  const isLatest = here.index === maxForDownpipe;
  if ((here.prevRunId ?? null) !== (root.freshness.prevRunId ?? null)) {
    noteFailStage("freshness-index");
    // The same disagreement on the chain POINTER rather than the index. The two prevRunIds are the customer's
    // own run ids and can never ride, so the row carries the entry's index, the chain length and the digest.
    noteRunlogAnomaly({ kind: "root-disagreement", indexA: here.index, entryCount: entries.length, ...digest });
    // THE ONE EARLY RETURN THAT IS NOT UNCHECKED, and deliberately so. The other four say nothing was
    // established; here the signature verified, the run was found, and its index bound to the signed root, so
    // a verdict WAS reached (checked:true) and only the chain pointer disagreed. The engine WRITES this state
    // itself: appendRunlog's relinkLocalPrev recomputes each destination's entry against that destination's
    // own tail, so a replica that skipped a run the primary holds carries a root prev (copied immutably from
    // the primary) that legitimately differs from its own relinked entry, and an out-of-order reclaim can do
    // the same on a primary (pipeline.ts destinationLocalPrev, residuals 1 and 2). Both are documented benign
    // notes cleared with stale tolerance, and refusing them would block restore from every diverged replica,
    // which is the destination a 3-2-1 restore reaches for precisely when the primary is gone. A rewritten
    // chain does not hide here: a dangling, forked or broken link is caught by detectChainAnomaly, and a
    // replayed document by the min-index pin, both unconditional. So this return keeps the verdict it always
    // had and gains only the forensic row above and an honest checked:true.
    return { ok: !!opts.allowStale, isLatestForDownpipe: isLatest, maxIndexForDownpipe: maxForDownpipe, runlogIndex: here.index, reason: "RUNLOG prevRunId disagrees with the signed root", rollbackDetected: false, checked: true };
  }

  // A signed RUNLOG can still be internally chain-anomalous: a duplicated index,
  // a break in a downpipe's prevRunId linearity, or a dangling or forked prevRunId. The
  // signature gate and the min-runlog-index pin cover the active bucket-write adversary,
  // but SPEC 8.7 item 3 and SPEC 10 make the in-bucket chain a verified-mode MUST the
  // reader is the authoritative verifier for, so reject any anomaly as a rollback
  // regardless of whether the restored run is itself the latest. A per-downpipe index gap
  // is NOT an anomaly: indices are allocated account-globally and a failed run consumes
  // one without appending an entry (SPEC 10). This mirrors the Go reader's
  // detectChainAnomaly call, placed after the run-vs-root agreement checks and before the
  // min-pin and latest checks.
  const anomaly = detectChainAnomaly(entries);
  if (anomaly) {
    // Unconditional (HI-05): a chain anomaly is proof the log was corrupted or rewritten, never a
    // legitimate state, so rollbackDetected is true regardless of allowStale.
    // G056: the anomaly REASON interpolates the customer's run and downpipe ids, so it can never be recorded.
    // The closed stage can, and it is the actionable half: a rewritten chain is a security event, not a
    // scheduling one.
    noteFailStage("freshness-chain");
    // G102: THE forensic row. The engine has just detected a possible ROLLBACK ATTACK, and support needs to be
    // able to tell a hostile rewrite from a corrupt object, which are opposite tickets (one is an incident,
    // one is a bucket). The CLOSED kind says which anomaly the detector matched,
    // the two indices are the disagreeing pair it compared, entryCount is how long the chain was, and the
    // digest pins the exact document. The reason string (which names the customer's runs) stays out.
    noteRunlogAnomaly({ kind: anomaly.kind, entryCount: entries.length, ...digest, ...(anomaly.indexA !== undefined ? { indexA: anomaly.indexA } : {}), ...(anomaly.indexB !== undefined ? { indexB: anomaly.indexB } : {}) });
    return { ok: !!opts.allowStale, isLatestForDownpipe: isLatest, maxIndexForDownpipe: maxForDownpipe, runlogIndex: here.index, reason: anomaly.reason, rollbackDetected: true, checked: true };
  }
  // The anti-rollback pin compares against the RUNLOG-GLOBAL max (matching the Go reader
  // and the monotonic index allocator), not the per-downpipe max, so a pin set from the
  // account-wide high-water mark is not defeated by a low-traffic downpipe.
  const runlogMax = entries.reduce((m, e) => Math.max(m, e.index), 0);
  // Explicit undefined check, not a truthy test: RUNLOG indices are 1-based (the first allocation is 1), so 0
  // is not a valid pin, but an explicit !== undefined keeps the intent ("skip only when no pin is set") honest.
  if (opts.minRunlogIndex !== undefined && runlogMax < opts.minRunlogIndex) {
    // Unconditional (HI-05), exactly like the chain-anomaly branch above: this is the ONE check
    // anchored OUTSIDE the document being read, so a whole-object replay of an older, internally-
    // consistent, validly-signed RUNLOG trips no anomaly but still fails the pin -- honour that
    // regardless of allowStale, or the pin can never actually catch a clean replay.
    noteFailStage("freshness-chain");
    // G102: the REPLAY case, and the two indices are the whole finding: indexA is the max this document
    // carries, indexB is the out-of-band pin it fell below. A support engineer reading "observed 41, pinned
    // 57" knows immediately that 16 runs of history were rolled back, which no reason string ever said.
    noteRunlogAnomaly({ kind: "index-regression", indexA: runlogMax, indexB: opts.minRunlogIndex, entryCount: entries.length, ...digest });
    return { ok: !!opts.allowStale, isLatestForDownpipe: isLatest, maxIndexForDownpipe: maxForDownpipe, runlogIndex: here.index, reason: "below the min-runlog-index pin", rollbackDetected: true, checked: true };
  }
  if (!isLatest && !opts.allowStale) {
    return { ok: false, isLatestForDownpipe: false, maxIndexForDownpipe: maxForDownpipe, runlogIndex: here.index, reason: "not the latest run for this downpipe", rollbackDetected: false, checked: true };
  }
  return { ok: true, isLatestForDownpipe: isLatest, maxIndexForDownpipe: maxForDownpipe, runlogIndex: here.index, rollbackDetected: false, checked: true };
}

// detectChainAnomaly inspects the signed RUNLOG for the chain anomalies of SPEC 10 (as
// amended: per-downpipe prevRunId linearity replaced index contiguity),
// returning a descriptive reason for the first it finds or null for a well-formed
// document. A faithful port of the Go reader's detectChainAnomaly (freshness.go). The
// writer allocates index values from one account-global counter and appends an entry
// only when a run finalises successfully, so index values MAY be non-contiguous within a
// downpipe and across the document; an index gap is NOT an anomaly. The checks, in order:
//
//  1. Index uniqueness: no two entries may carry the same index (the account-global
//     counter never reissues one). LINE ORDER is NOT significant: concurrent runs
//     finalise (and therefore append) out of allocation order, a writer may
//     canonicalise order on a later rewrite, and the whole-document signature is the
// integrity anchor, so the checks sort by index first (SPEC 10, amended).
//
//  2. Per-downpipe prevRunId linearity: taking each downpipe's entries in ascending
//     index order, the first entry's prevRunId is null (a downpipe's first run) or is
//     covered by the dangling check below, and every subsequent entry's prevRunId must
//     equal the immediately prior retained entry's runId for that downpipe. Pruned
//     predecessors are retained marked superseded (SPEC 10.1), so the after-prune state
//     does not trip this; a break in linearity means an entry was removed from the
//     middle of the chain or the chain was rewritten.
//
//  3. Dangling or forked prevRunId: each entry's non-null prevRunId must resolve to an
//     existing RUNLOG entry of any status, and no two entries may share a prevRunId. A
//     prevRunId that no entry carries is a dangling pointer and a shared prevRunId is a
//     fork; either means the chain was rewritten.
//
// G102: it now returns the CLOSED KIND and the two DISAGREEING INDICES beside the reason. The reason is
// unchanged and still returned to the caller (it names the customer's own runs, which is exactly why it can
// never be recorded); the kind and the index pair are the redaction-safe half that CAN be, and they are the
// half a tamper-vs-corruption investigation actually needs.
function detectChainAnomaly(entries: RunlogEntry[]): ChainAnomaly | null {
  // LINE ORDER IS NOT LOAD-BEARING (SPEC 10): indices are allocated at trigger time but entries land at
  // FINALISE time, so concurrent runs legitimately append out of allocation order. The whole-document
  // signature is the integrity anchor; reordering without re-signing is impossible. The checks below run
  // over a copy sorted by index; the one index fact that IS a corruption signal is a DUPLICATE (the
  // account-global counter never reissues one).
  const sorted = [...entries].sort((a, b) => a.index - b.index);
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i]!.index === sorted[i - 1]!.index) {
      return {
        kind: "duplicate-index",
        reason: `runlog index ${sorted[i]!.index} appears twice (log corrupted or rewritten)`,
        indexA: sorted[i - 1]!.index,
        indexB: sorted[i]!.index,
      };
    }
  }

  // Ascending index order is allocation order, so one pass with a per-downpipe tail
  // implements the prevRunId linearity rule.
  const tail = new Map<string, { runId: string; index: number }>();
  for (const e of sorted) {
    const last = tail.get(e.downpipeId);
    if (last !== undefined && (e.prevRunId == null || e.prevRunId !== last.runId)) {
      return {
        kind: "chain-break",
        reason: `runlog entry ${e.runId} for downpipe ${e.downpipeId} does not chain to the prior retained entry ${last.runId} (chain rewritten)`,
        indexA: last.index,
        indexB: e.index,
      };
    }
    tail.set(e.downpipeId, { runId: e.runId, index: e.index });
  }

  const ids = new Set<string>();
  for (const e of sorted) ids.add(e.runId);
  const prevSeen = new Map<string, { runId: string; index: number }>();
  for (const e of sorted) {
    if (e.prevRunId == null) continue;
    const prev = e.prevRunId;
    if (!ids.has(prev)) {
      return { kind: "dangling-prev", reason: `runlog entry ${e.runId} has a dangling prevRunId ${prev} that no entry carries (chain rewritten)`, indexA: e.index };
    }
    const first = prevSeen.get(prev);
    if (first !== undefined) {
      return {
        kind: "forked-prev",
        reason: `runlog entries ${first.runId} and ${e.runId} share prevRunId ${prev} (forked chain)`,
        indexA: first.index,
        indexB: e.index,
      };
    }
    prevSeen.set(prev, { runId: e.runId, index: e.index });
  }
  return null;
}

// ChainAnomaly is the detector's structured verdict (G102): the CLOSED kind and the two disagreeing indices
// are recordable; the reason -- which interpolates the customer's run and downpipe ids -- is returned to the
// caller for the API response and is never carried into any record.
interface ChainAnomaly {
  readonly kind: RunlogAnomalyKind;
  readonly reason: string;
  readonly indexA?: number;
  readonly indexB?: number;
}

// runlogDigest is the 12-hex one-way join key over the RUNLOG BYTES (G102): the same causeDigest discipline the
// rest of the pack uses. The customer can hash their own _RECOVERY/RUNLOG object and compare; nobody can go the
// other way. Never throws: an anomaly must be recorded even if the digest cannot be computed.
async function runlogDigestField(bytes: Uint8Array): Promise<{ digest?: string }> {
  try {
    return { digest: hexEncode(await sha384(bytes)).slice(0, 12) };
  } catch {
    return {};
  }
}

/**
 * RUNLOG-FORKS-ON-THE-RECOVERY-PATH. The account-global runlogCounter (allocated by
 * the scheduler DO) and the RUNLOG it numbers (written to the destination bucket) live in different
 * places with different lifetimes, and nothing seeds the counter from the document on the control-plane
 * recovery path. A rebuilt DO's counter starts at zero against a bucket the amnesia detector has just
 * proved still holds a RUNLOG, so the next trigger allocates index 1 into it and forks the log on its
 * first post-recovery run -- and the SAME zeroed counter also feeds the anti-rollback pin every attest
 * call reads (fetchMinRunlogIndex), so a whole-document replay of an older signed RUNLOG attests clean
 * with no reason recorded, before the fork even happens.
 *
 * This reads the destination's own RUNLOG, verifies it under the operator's pinned verifier exactly as
 * checkRunlogFreshness does, and returns the highest index it carries so the recovery path can anchor the
 * counter to the document before any trigger allocates. Signature-gated: to inflate the returned index an
 * attacker would need a validly signed document, which means holding the signing key, at which point
 * forging runs directly does not need this path at all.
 *
 * Deliberately narrower than a full anti-rollback repair: it reads ONE destination (whichever the caller
 * resolves), not the account-global maximum across every destination a multi-dest account might hold, so
 * an account whose highest index lives on a replica the caller did not resolve can still under-seed. It
 * is a pure floor-raise on the recovery path, never a refusal: an absent, unreadable, unsigned or
 * unparsable document returns null, which a caller must treat as "no anchor was established", not as
 * zero -- zero is what today's unseeded counter already produces, so a caller that leaves the counter
 * untouched on null makes recovery no worse than it is today, never better and never worse.
 *
 * @param getObject - reads one object's bytes by key, or null when absent/unreadable. Never throws (a
 *   throwing implementation is treated the same as a missing object: no anchor).
 * @param verifier - the operator-pinned hybrid signer the RUNLOG signature must verify under.
 * @returns the highest index the verified document carries, or null when no anchor could be established.
 */
export async function readVerifiedRunlogMaxIndex(getObject: (key: string) => Promise<Uint8Array | null>, verifier: HybridVerifier): Promise<number | null> {
  let runlogBytes: Uint8Array | null;
  let sigBytes: Uint8Array | null;
  try {
    runlogBytes = await getObject("_RECOVERY/RUNLOG");
    sigBytes = await getObject("_RECOVERY/RUNLOG.sig");
  } catch {
    return null;
  }
  if (runlogBytes === null || sigBytes === null) return null;
  let sig: Uint8Array;
  try {
    sig = b64urlDecode(new TextDecoder().decode(sigBytes).trim());
  } catch {
    return null;
  }
  try {
    if (!(await hybridVerify(verifier, runlogBytes, sig))) return null;
  } catch {
    return null;
  }
  let entries: RunlogEntry[];
  try {
    entries = parseRunlog(runlogBytes);
  } catch {
    return null;
  }
  let max = 0;
  for (const e of entries) if (typeof e.index === "number" && Number.isFinite(e.index) && e.index > max) max = e.index;
  return max > 0 ? max : null;
}
