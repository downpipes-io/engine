// The RUNLOG hand-over from one signer to the next (a signer re-key).
//
// A re-key replaces SIGNER_PRIVATE, and each destination's _RECOVERY/RUNLOG is signed under the OLD key. The
// engine refuses to modify a RUNLOG it cannot verify under its own key, so after a re-key each RUNLOG must be
// handed over: the stored bytes are verified under the OLD public key, and the SAME bytes are signed under
// the new key. Nothing in the body changes, and nothing is signed that the old key did not verify, so a
// re-key can never launder a RUNLOG that was changed in the bucket.
//
// precheckRunlog runs before the new secret is installed: a destination whose RUNLOG does not verify under the
// old key stops the re-key. handOverRunlog runs after it: it re-signs, under the new key, only a RUNLOG that
// still verifies under the old public key, and leaves anything else pending.

import { noteSiteFault } from "../admin/site-faults.ts";
import { b64urlEncode, hexEncode, utf8 } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { type HybridVerifier, hybridSign } from "../crypto/sign.ts";
import type { Destination } from "../dest/types.ts";
import { detectChainAnomaly, runlogDigestField } from "../format/freshness.ts";
import type { RunlogAnomaly } from "../format/integrity-fault-ledger.ts";
import { parseRunlog, type RunlogEntry, type Signer, signRunlog } from "../format/writer.ts";
import { bytesEqual } from "../util/bytes-equal.ts";
import { RUNLOG_SIG_PENDING_KEY, resolveRunlogSignature, sigVerifies } from "./pipeline.ts";
import { throttleRetry, withRetry } from "./retry.ts";

const RUNLOG_KEY = "_RECOVERY/RUNLOG";
const RUNLOG_SIG_KEY = "_RECOVERY/RUNLOG.sig";
const HANDOVER_ATTEMPTS = 4;

/** Why a RUNLOG did not pass the pre-check, as a closed class. */
export const PRECHECK_REFUSALS = ["sig-invalid", "sig-absent", "unparsable", "chain-anomaly", "unreadable"] as const;
export type PrecheckRefusal = (typeof PRECHECK_REFUSALS)[number];

/** Why an attended relink was refused, as a closed class. The audit row and the support pack carry this. */
export const RELINK_REFUSALS = ["changed-since-read", "absent", "not-verified", "unparsable", "below-floor", "no-anomaly", "not-cleared"] as const;
export type RelinkRefusal = (typeof RELINK_REFUSALS)[number];

/**
 * The forensic row behind a chain-anomaly refusal, for the support pack: the downpipe whose chain is anomalous
 * and the anomaly in the integrity ledger's closed vocabulary. The anomaly's reason text names customer run ids
 * and is never carried.
 */
export interface PrecheckAnomaly {
  downpipeId: string;
  row: RunlogAnomaly;
}

export type PrecheckResult = { ok: true; state: "absent" | "verified" | "promoted"; maxIndex: number } | { ok: false; reason: PrecheckRefusal; anomaly?: PrecheckAnomaly };

/**
 * precheckRunlog verifies one destination's RUNLOG under the outgoing signer's public key: the signature
 * (resuming an interrupted write from the pending signature when that verifies), the parse and the chain. An
 * absent RUNLOG passes: there is nothing to hand over.
 */
export async function precheckRunlog(dest: Destination, oldVerifier: HybridVerifier): Promise<PrecheckResult> {
  let body: Uint8Array;
  try {
    const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    if (!existing) return { ok: true, state: "absent", maxIndex: 0 };
    body = existing.body;
    const state = await resolveRunlogSignature(dest, body, oldVerifier);
    if (state === "sig-invalid" || state === "sig-absent") return { ok: false, reason: state === "sig-absent" ? "sig-absent" : "sig-invalid" };
    let entries: ReturnType<typeof parseRunlog>;
    try {
      entries = parseRunlog(body);
    } catch (e) {
      // The signature verified, so the engine signed bytes it cannot parse.
      noteSiteFault("rekey.runlog-precheck-parse", e);
      return { ok: false, reason: "unparsable" };
    }
    const anomaly = detectChainAnomaly(entries);
    if (anomaly !== null) {
      const at = anomaly.indexA ?? anomaly.indexB;
      const downpipeId = entries.find((e) => e.index === at)?.downpipeId ?? "";
      const row: RunlogAnomaly = { kind: anomaly.kind, entryCount: entries.length, ...(await runlogDigestField(body)), ...(anomaly.indexA !== undefined ? { indexA: anomaly.indexA } : {}), ...(anomaly.indexB !== undefined ? { indexB: anomaly.indexB } : {}) };
      return { ok: false, reason: "chain-anomaly", ...(downpipeId !== "" ? { anomaly: { downpipeId, row } } : {}) };
    }
    return { ok: true, state, maxIndex: entries.reduce((m, e) => Math.max(m, e.index), 0) };
  } catch (e) {
    noteSiteFault("rekey.runlog-precheck-read", e);
    return { ok: false, reason: "unreadable" };
  }
}

/** The outcome of handing over one destination's RUNLOG. */
export type HandoverOutcome = "re-signed" | "already-current" | "absent" | "pending";

/**
 * handOverRunlog signs one destination's RUNLOG under the new signer, but only when the stored bytes verify
 * under the outgoing signer's public key. A RUNLOG that already verifies under the new key is left alone. A
 * RUNLOG that verifies under neither key is left PENDING and never signed: the held old key or the attended
 * re-sign decides it later. The write uses the RUNLOG writers' protocol: the pending signature first, then a
 * conditional write of the SAME body bytes (so a concurrent writer is detected and the pass re-reads), then
 * the .sig only while the body is still ours.
 */
export async function handOverRunlog(dest: Destination, oldVerifier: HybridVerifier, newSigner: Signer): Promise<HandoverOutcome> {
  const newVerifier: HybridVerifier = { ed: newSigner.edPublic, mldsa: newSigner.mldsaPublic };
  for (let attempt = 0; attempt < HANDOVER_ATTEMPTS; attempt++) {
    let existing: Awaited<ReturnType<Destination["get"]>>;
    try {
      existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    } catch (e) {
      noteSiteFault("rekey.runlog-handover-read", e);
      return "pending";
    }
    if (!existing) return "absent";
    const body = existing.body;
    const underNew = await resolveRunlogSignature(dest, body, newVerifier);
    if (underNew === "verified" || underNew === "promoted") return "already-current";
    const underOld = await resolveRunlogSignature(dest, body, oldVerifier);
    if (underOld !== "verified" && underOld !== "promoted") return "pending";
    const sigText = utf8(b64urlEncode(await hybridSign(newSigner.edPrivate, newSigner.mldsaSecret, body)));
    await withRetry(() => dest.put(RUNLOG_SIG_PENDING_KEY, sigText), throttleRetry());
    const res = await withRetry(() => dest.putConditional(RUNLOG_KEY, body, { ifMatch: existing.etag }), throttleRetry());
    if (!res.ok) continue; // a concurrent writer moved the body: re-read and decide again
    const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
    const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, body));
    if (!stillOurs) continue;
    await withRetry(() => dest.put(RUNLOG_SIG_KEY, sigText), throttleRetry());
    return "re-signed";
  }
  return "pending";
}

/** What the attended re-sign shows an Owner about one destination's RUNLOG. Read only: it promotes nothing. */
export interface RunlogSignatureDiagnosis {
  present: boolean;
  sigPresent: boolean;
  pendingPresent: boolean;
  // Under the CURRENT signer: verified, or only the pending signature verifies (an interrupted write the next
  // RUNLOG write resumes), or the .sig is absent, or it does not verify.
  state: "verified" | "pending-verifies" | "sig-absent" | "sig-invalid" | "absent";
  verifiesUnderHeldOld: boolean; // the .sig or the pending signature verifies under a held re-key public key
  digest?: string; // SHA-384 of the RUNLOG bytes, hex: what an Owner confirms before a re-sign
  parses: boolean;
  entryCount?: number;
  maxIndex?: number;
  chainAnomaly?: string; // the closed anomaly kind, when the parsed chain has one
}

export async function diagnoseRunlogSignature(dest: Destination, current: HybridVerifier, heldOld: HybridVerifier | null): Promise<RunlogSignatureDiagnosis> {
  const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
  if (!existing) return { present: false, sigPresent: false, pendingPresent: false, state: "absent", verifiesUnderHeldOld: false, parses: false };
  const body = existing.body;
  const sigObj = await withRetry(() => dest.get(RUNLOG_SIG_KEY), throttleRetry());
  const pending = await withRetry(() => dest.get(RUNLOG_SIG_PENDING_KEY), throttleRetry());
  let state: RunlogSignatureDiagnosis["state"];
  if (await sigVerifies(sigObj, body, current)) state = "verified";
  else if (await sigVerifies(pending, body, current)) state = "pending-verifies";
  else state = sigObj ? "sig-invalid" : "sig-absent";
  const verifiesUnderHeldOld = heldOld !== null && ((await sigVerifies(sigObj, body, heldOld)) || (await sigVerifies(pending, body, heldOld)));
  const out: RunlogSignatureDiagnosis = { present: true, sigPresent: sigObj !== null, pendingPresent: pending !== null, state, verifiesUnderHeldOld, digest: hexEncode(await sha384(body)), parses: false };
  try {
    const entries = parseRunlog(body);
    out.parses = true;
    out.entryCount = entries.length;
    out.maxIndex = entries.reduce((m, e) => Math.max(m, e.index), 0);
    const anomaly = detectChainAnomaly(entries);
    if (anomaly) out.chainAnomaly = anomaly.kind;
  } catch {
    // site-fault-waiver: src/seal/runlog-handover.ts:diagnoseRunlogSignature:catch:1 -- these bucket bytes may not verify, so a parse failure is data, and parses false is what this view shows the Owner
    out.parses = false;
  }
  return out;
}

/**
 * resignRunlogAttended signs, under the current signer, the exact RUNLOG bytes an Owner confirmed by their
 * SHA-384. It is called only by the attended route, after step-up. If the stored bytes are not the ones the
 * Owner saw, nothing is signed. The write uses the RUNLOG writers' protocol.
 */
export async function resignRunlogAttended(dest: Destination, signer: Signer, confirmedDigest: string): Promise<"re-signed" | "changed-since-read" | "absent"> {
  const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
  if (!existing) return "absent";
  const body = existing.body;
  if (hexEncode(await sha384(body)) !== confirmedDigest) return "changed-since-read";
  const sigText = utf8(b64urlEncode(await hybridSign(signer.edPrivate, signer.mldsaSecret, body)));
  await withRetry(() => dest.put(RUNLOG_SIG_PENDING_KEY, sigText), throttleRetry());
  const res = await withRetry(() => dest.putConditional(RUNLOG_KEY, body, { ifMatch: existing.etag }), throttleRetry());
  if (!res.ok) return "changed-since-read";
  const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
  const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, body));
  if (!stillOurs) return "changed-since-read";
  await withRetry(() => dest.put(RUNLOG_SIG_KEY, sigText), throttleRetry());
  return "re-signed";
}

// relinkChain returns a copy of the entries with ONE downpipe's chain relinked into ascending-index order (the
// same relink appendRunlog applies on every append). Other downpipes' entries are copied unchanged.
export function relinkChain(entries: readonly RunlogEntry[], downpipeId: string): RunlogEntry[] {
  const out = entries.map((e) => ({ ...e }));
  let prev: string | null = null;
  for (const e of out.filter((x) => x.downpipeId === downpipeId).sort((a, b) => a.index - b.index)) {
    e.prevRunId = prev;
    prev = e.runId;
  }
  return out.sort((a, b) => a.index - b.index);
}

/** What the attended relink shows an Owner about one downpipe's chain in a destination RUNLOG. Read only. */
export interface ChainDiagnosis {
  present: boolean;
  verifies: boolean; // the stored .sig verifies the bytes under the current signer
  digest?: string;
  maxIndex?: number;
  chainEntries?: number; // how many entries this downpipe has in the RUNLOG
  anomaly?: { kind: string; reason: string; indexA?: number; indexB?: number };
  relinkClears: boolean; // relinking this one chain leaves it with no anomaly
}

export async function diagnoseChain(dest: Destination, current: HybridVerifier, downpipeId: string): Promise<ChainDiagnosis> {
  const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
  if (!existing) return { present: false, verifies: false, relinkClears: false };
  const sigObj = await withRetry(() => dest.get(RUNLOG_SIG_KEY), throttleRetry());
  const out: ChainDiagnosis = { present: true, verifies: await sigVerifies(sigObj, existing.body, current), digest: hexEncode(await sha384(existing.body)), relinkClears: false };
  let entries: RunlogEntry[];
  try {
    entries = parseRunlog(existing.body);
  } catch {
    // site-fault-waiver: src/seal/runlog-handover.ts:diagnoseChain:catch:1 -- these bucket bytes may not verify, so a parse failure is data, and the view refuses the relink to the Owner as not parsing
    return out;
  }
  out.maxIndex = entries.reduce((m, e) => Math.max(m, e.index), 0);
  const chain = entries.filter((e) => e.downpipeId === downpipeId);
  out.chainEntries = chain.length;
  const anomaly = detectChainAnomaly(chain);
  if (anomaly) {
    out.anomaly = { kind: anomaly.kind, reason: anomaly.reason, ...(anomaly.indexA !== undefined ? { indexA: anomaly.indexA } : {}), ...(anomaly.indexB !== undefined ? { indexB: anomaly.indexB } : {}) };
    out.relinkClears = detectChainAnomaly(relinkChain(entries, downpipeId).filter((e) => e.downpipeId === downpipeId)) === null;
  }
  return out;
}

/**
 * relinkRunlogAttended relinks ONE downpipe's chain in a destination RUNLOG, once, for the attended route after
 * step-up. It acts only on the exact bytes the Owner confirmed by their SHA-384, only when the stored .sig
 * verifies those bytes under the current signer (it never re-signs bytes that do not verify), only when that
 * chain has an anomaly, and only when the relink clears it. The write uses the RUNLOG writers' protocol.
 */
export async function relinkRunlogAttended(dest: Destination, signer: Signer, downpipeId: string, confirmedDigest: string): Promise<"relinked" | "changed-since-read" | "absent" | "not-verified" | "no-anomaly" | "not-cleared"> {
  const existing = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
  if (!existing) return "absent";
  const body = existing.body;
  if (hexEncode(await sha384(body)) !== confirmedDigest) return "changed-since-read";
  const sigObj = await withRetry(() => dest.get(RUNLOG_SIG_KEY), throttleRetry());
  if (!(await sigVerifies(sigObj, body, { ed: signer.edPublic, mldsa: signer.mldsaPublic }))) return "not-verified";
  let entries: RunlogEntry[];
  try {
    entries = parseRunlog(body);
  } catch (e) {
    // The signature verified, so the engine signed bytes it cannot parse.
    noteSiteFault("runlog.relink-parse", e);
    return "not-verified";
  }
  if (detectChainAnomaly(entries.filter((e) => e.downpipeId === downpipeId)) === null) return "no-anomaly";
  const relinked = relinkChain(entries, downpipeId);
  if (detectChainAnomaly(relinked.filter((e) => e.downpipeId === downpipeId)) !== null) return "not-cleared";
  const { runlog, sig } = await signRunlog(relinked, signer.edPrivate, signer.mldsaSecret);
  const sigText = utf8(b64urlEncode(sig));
  await withRetry(() => dest.put(RUNLOG_SIG_PENDING_KEY, sigText), throttleRetry());
  const res = await withRetry(() => dest.putConditional(RUNLOG_KEY, runlog, { ifMatch: existing.etag }), throttleRetry());
  if (!res.ok) return "changed-since-read";
  const after = await withRetry(() => dest.get(RUNLOG_KEY), throttleRetry());
  const stillOurs = !!after && (res.etag ? after.etag === res.etag : bytesEqual(after.body, runlog));
  if (!stillOurs) return "changed-since-read";
  await withRetry(() => dest.put(RUNLOG_SIG_KEY, sigText), throttleRetry());
  return "relinked";
}
