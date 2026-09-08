// key-vintages.ts -- the KEYLESS, MANIFEST-AUTHORITATIVE key-vintage inventory. It answers "which archive vintages does each key open, and which runs are
// stranded to a key that is NOT currently installed" without any private key: it walks each retained OK run,
// reads its SIGNATURE-VERIFIED root manifest back from the destination, and reads the recipient fingerprints
// (masterCapsule[].fingerprint) and the signer fingerprint straight off it.
//
// The signed root is AUTHORITATIVE for BOTH the safe and the stranded verdict (the correction the adversarial
// refuter landed): there is NO recorded per-run fingerprint index, and nothing is threaded onto /complete, so
// no stale or corrupt index can ever fabricate a false "safe" (which would be G-P0-098 reintroduced). The walk
// is bounded to the retained rings, the same cost envelope the periodic drill and the attended-verification
// capsule read already accept.
//
// CUSTODY-SAFETY (binding): only dpr1:/edmldsa1: fingerprints of PUBLIC keys, the closed role enum and run
// counts are ever read, returned or displayed -- never a private half, a seed, a capsule ciphertext or a byte
// length of a pasted value. The break-glass and operational PRIVATES never touch this path; the manifest read
// is the identical keyless read the Tier-0 attestation (format/reader.ts) and the attended-verification
// capsule read (router-attest.ts) already use.
import { recipientFingerprint } from "../crypto/capsule.ts";
import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { type ObjectStore, readRunCapsule } from "../format/reader.ts";
import { signerFingerprint } from "../format/writer.ts";
import { loadRecipientPublic, loadSigner, verifierFrom } from "../keys-env.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import { log } from "../log.ts";
import { classifyRestoreFailure } from "../restore-reasons.ts";
import type { RunHistoryEntry } from "../sched/types.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { doURL } from "../do-url.ts";
import { withRunDestFallback } from "./router-sources.ts";

// VINTAGE_RUN_SCAN_MAX bounds how many OK runs one inventory pass reads back from destinations (newest-first
// across the retained rings), so a very large fleet cannot fan out an unbounded number of manifest reads and
// trip the platform subrequest cap. When more OK runs exist than this, the pass reads the most recent
// VINTAGE_RUN_SCAN_MAX and reports truncated:true; the discard-guard then treats truncation as uncertainty,
// because it cannot assert that nothing older is sole-access-openable by the key being removed.
const VINTAGE_RUN_SCAN_MAX = 400;

// KeyVintageRollup is one distinct recipient key observed across the readable runs: its public fingerprint,
// its role, how many readable runs are wrapped to it, and whether it is a CURRENT key (in currentInstalled).
export interface KeyVintageRollup {
  fingerprint: string;
  role: string; // "break-glass" | "operational"
  runCount: number;
  isCurrent: boolean;
}

// StrandedVintage attributes stranded runs to the (prior) break-glass vintage that seals them, so the surface
// can say "N runs from vintage <short-fp>" one line per vintage.
export interface StrandedVintage {
  fingerprint: string;
  role: string;
  runCount: number;
}

// KeyVintageInventory is the whole read: the current keys (what the NEXT seal wraps to), the per-vintage
// rollup, the recipient-stranding tally, and the signer-continuity tally for the re-key surface.
export interface KeyVintageInventory {
  // current keys derived from env by the SAME loaders the seal uses, so "current" cannot drift from what the
  // next seal wraps to (correction 4: PUBLIC presence -- operational is present iff OPERATIONAL_PUBLIC is set,
  // never gated on OPERATIONAL_PRIVATE). null when the slot is unset or a pasted value does not parse.
  current: { breakGlass: string | null; operational: string | null; signer: string | null };
  okRunCount: number; // OK runs observed across the retained rings
  readableRunCount: number; // of those, how many manifests read back + verified under the current signer
  truncated: boolean; // more OK runs exist than one pass reads; older ones were not inspected this pass
  // historyReadOk is false when the run-history read itself failed (a non-2xx from the scheduler DO, or a
  // throw): the inventory could NOT enumerate the runs to inspect, so a zero count means "not read", NOT "no
  // archives at stake". The discard-guard treats this as uncertainty and refuses-unless-confirmed, so a
  // transient /history fault can never read as "nothing to strand" (the fail-open the refuter landed).
  historyReadOk: boolean;
  vintages: KeyVintageRollup[];
  // recipient stranding NOW: runCount is the per-run stranded tally (each stranded run counted once, over its
  // whole recipient set); byVintage attributes them to the prior break-glass vintage; unknownCount is OK runs
  // whose recipient set could NOT be authoritatively read (manifest unreadable, or signed by a prior signer),
  // never folded into a current vintage and never asserted stranded.
  stranded: { runCount: number; byVintage: StrandedVintage[]; unknownCount: number };
  // signer continuity (G-P0-099 surfacing), independent of recipient stranding: brokenRunCount is OK runs whose
  // root signature does NOT verify under the current signer (a prior signer, or a tampered root), currentRunCount
  // is OK runs that DO verify under the current signer (these are exactly the runs a re-key would stop verifying).
  signer: { current: string | null; brokenRunCount: number; currentRunCount: number };
  // currentBreakGlassRunCount is the readable runs wrapped to the CURRENT break-glass key -- the recipient-
  // stranding blast radius of a deliberate re-key (which replaces BREAK_GLASS_PUBLIC too), so the re-key
  // surface can show BOTH the recipient count and the signer count (correction 5).
  currentBreakGlassRunCount: number;
  // operationalSoleAccessRunCount is the discard-guard's crux: readable runs the CURRENT operational key alone
  // opens among the currently-installed keys (wrapped to operational but NOT to the current break-glass), so
  // removing the operational key strands them. Zero in the ordinary no-rotation estate.
  operationalSoleAccessRunCount: number;
}

// envRecipientFingerprint derives a recipient slot's dpr1: fingerprint from its env public exactly as the seal
// does (loadRecipientPublic + recipientFingerprint), so the inventory's "current" cannot drift from what the
// next seal wraps to. A malformed or absent value is honestly null ("not a current vintage"), never a throw.
export async function envRecipientFingerprint(b64: string | undefined): Promise<string | null> {
  if (typeof b64 !== "string" || b64.trim() === "") return null;
  try {
    const pub = loadRecipientPublic(b64);
    return await recipientFingerprint(pub.x25519, pub.mlkemEk);
  } catch {
    return null;
  }
}

// envSignerFingerprint derives the current signer's edmldsa1: fingerprint from SIGNER_PRIVATE, matching the
// value stamped into every root the current signer signs. Absent/malformed is null, never a throw.
async function envSignerFingerprint(b64: string | undefined): Promise<string | null> {
  if (typeof b64 !== "string" || b64.trim() === "") return null;
  try {
    return await signerFingerprint(verifierFrom(await loadSigner(b64)));
  } catch {
    return null;
  }
}

// RunManifest is the per-run keyless read outcome: readable (the signed root read back + verified under the
// current signer, so its recipient set + roles + signer are authoritative), signer-broken (the root is present
// but its signature does NOT verify under the current signer -- a prior signer or a tampered root, so its
// recipient set is NOT authoritative), or unknown (the manifest could not be read: destination unreachable or
// the object pruned). Recipient stranding is decided ONLY from a readable manifest; the other two are surfaced
// honestly and never asserted safe.
type RunManifest =
  | { kind: "readable"; recipientFps: string[]; roleByFp: Map<string, string> }
  | { kind: "signer-broken" }
  | { kind: "unknown" };

// readRunManifest reads one run's root manifest KEYLESSLY, with per-downpipe destination resolution + 3-2-1
// replica fallback (the same withRunDestFallback the restore/capsule paths use). readRunCapsule
// signature-verifies the root under the operator-pinned verifier before returning, so the recipient set it
// yields is manifest-authoritative. A SIGNATURE failure is terminal (every replica holds the same signed
// bytes, so it is not a replica-fallback reason) and reads as signer-broken; an AVAILABILITY failure falls
// through to the next copy before the run is finally reported unknown.
async function readRunManifest(env: Env, scheduler: DurableObjectStub, runId: string, verifier: HybridVerifier, wrapKey: Uint8Array | undefined): Promise<RunManifest> {
  const res = await withRunDestFallback(
    scheduler,
    runId,
    undefined,
    async (cfg: RuntimeDestConfig | null): Promise<{ ok: boolean; reason?: string; manifest: RunManifest }> => {
      try {
        const dest = await buildDestination(env, undefined, cfg);
        const store: ObjectStore = {
          get: async (k: string) => {
            const r = await dest.get(k);
            if (!r) throw new Error(`object ${k} is missing`);
            return r.body;
          },
        };
        const cap = await readRunCapsule(store, runId, verifier);
        const roleByFp = new Map<string, string>();
        for (const r of cap.recipients) roleByFp.set(r.fingerprint, r.role);
        return { ok: true, manifest: { kind: "readable", recipientFps: cap.masterCapsule.map((w) => w.fingerprint), roleByFp } };
      } catch (e) {
        const m = (e as Error).message;
        // A signer mismatch reads as "signature did not verify" (crypto/capsule.ts + reader.ts): the root is
        // present but signed by a different signer, which no replica can fix, so return an integrity reason
        // (withRunDestFallback treats it as terminal) and mark signer-broken. Everything else is an availability
        // reason that withRunDestFallback may retry on a replica before the run is finally reported unknown.
        if (/signature did not verify/.test(m)) return { ok: false, reason: "integrity check failed", manifest: { kind: "signer-broken" } };
        return { ok: false, reason: classifyRestoreFailure(e), manifest: { kind: "unknown" } };
      }
    },
    wrapKey,
  );
  return res.manifest;
}

// computeKeyVintages builds the whole inventory. It reads the current keys from env (the CURRENT-key facts,
// matching the support-pack semantics), gathers the OK runs across the retained rings (correction 3: ok-only),
// and reads each run's signed root manifest keylessly, tallying the per-vintage rollup, the recipient-stranding
// count and the signer-continuity count. It never throws for an individual run (a bad manifest is unknown, a
// prior-signer manifest is signer-broken); only a total failure to read history degrades the whole pass, which
// is reported honestly (okRunCount reflects what was seen).
export async function computeKeyVintages(env: Env, scheduler: DurableObjectStub): Promise<KeyVintageInventory> {
  const breakGlassFp = await envRecipientFingerprint(env.BREAK_GLASS_PUBLIC);
  const operationalFp = await envRecipientFingerprint(env.OPERATIONAL_PUBLIC);
  const signerFp = await envSignerFingerprint(env.SIGNER_PRIVATE);
  // currentInstalled (correction 4): PUBLIC presence only. Break-glass whenever BREAK_GLASS_PUBLIC parses,
  // operational whenever OPERATIONAL_PUBLIC parses. It never requires OPERATIONAL_PRIVATE: "the engine can
  // self-decrypt now" is a different question from "the owner holds a path to this key", and current must
  // match what the NEXT seal wraps to.
  const currentInstalled = new Set<string>();
  if (breakGlassFp !== null) currentInstalled.add(breakGlassFp);
  if (operationalFp !== null) currentInstalled.add(operationalFp);

  // Gather OK runs across all retained rings. Failed/abandoned rows keep their allocated runId but sealed no
  // archive (correction 3), so iterating them would inflate unknownCount and a partial seal could read stranded.
  // CRITICAL (fail-closed): a /history read that FAILS (a non-2xx from the DO, or a throw) must not be conflated
  // with "zero OK runs". fetch does not throw on a non-2xx, so the status is checked explicitly before parsing;
  // any failure sets historyReadOk=false, which the discard-guard treats as uncertainty (refuse-unless-confirmed).
  const okRunIds: string[] = [];
  let historyReadOk = true;
  try {
    const resp = await scheduler.fetch(doURL("/history"), { method: "GET" });
    if (!resp.ok) {
      historyReadOk = false;
      log("warn", `key-vintages: history read returned ${resp.status}; inventory reported as incomplete (fail-closed)`);
    } else {
      const hist = (await resp.json()) as { byDownpipe?: Record<string, RunHistoryEntry[]> };
      const byDownpipe = hist.byDownpipe ?? {};
      for (const ring of Object.values(byDownpipe)) {
        for (const e of ring) if (e.status === "ok" && typeof e.runId === "string" && e.runId !== "") okRunIds.push(e.runId);
      }
    }
  } catch (e) {
    historyReadOk = false;
    log("warn", `key-vintages: history read failed (${(e as Error).message.slice(0, 120)}); inventory reported as incomplete (fail-closed)`);
  }
  const okRunCount = okRunIds.length;
  const truncated = okRunCount > VINTAGE_RUN_SCAN_MAX;
  // Rings arrive newest-first, so the head is the most recent set of runs when truncating.
  const scan = truncated ? okRunIds.slice(0, VINTAGE_RUN_SCAN_MAX) : okRunIds;

  const verifier = env.SIGNER_PRIVATE ? verifierFrom(await loadSigner(env.SIGNER_PRIVATE)) : null;
  const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);

  const vintageRuns = new Map<string, { role: string; count: number }>();
  const strandedByBg = new Map<string, number>();
  let strandedRunCount = 0;
  let unknownCount = 0;
  let signerBrokenCount = 0;
  let readableRunCount = 0;
  let currentBreakGlassRunCount = 0;
  let operationalSoleAccessRunCount = 0;

  for (const runId of scan) {
    const manifest: RunManifest = verifier === null ? { kind: "unknown" } : await readRunManifest(env, scheduler, runId, verifier, wrapKey);
    if (manifest.kind === "signer-broken") {
      // A prior-signer (or tampered) root: its signature does not verify here, so its recipient set is NOT
      // authoritative -- it is unknown for recipient stranding AND counted as signer-continuity broken.
      signerBrokenCount++;
      unknownCount++;
      continue;
    }
    if (manifest.kind === "unknown") {
      unknownCount++;
      continue;
    }
    readableRunCount++;
    const fps = new Set(manifest.recipientFps);
    // Per-vintage run tally (roles paired from the recipients[] set on the signed root).
    for (const fp of fps) {
      const role = manifest.roleByFp.get(fp) ?? "unknown";
      const cur = vintageRuns.get(fp);
      if (cur) cur.count++;
      else vintageRuns.set(fp, { role, count: 1 });
    }
    // Recipient stranding NOW: the whole recipient set is disjoint from currentInstalled (computed once per
    // run, so a multi-recipient run is evaluated as a whole and never double-counted).
    const openableNow = [...fps].some((fp) => currentInstalled.has(fp));
    if (!openableNow) {
      strandedRunCount++;
      const bgWrap = [...manifest.roleByFp.entries()].find(([, role]) => role === "break-glass")?.[0] ?? "unknown";
      strandedByBg.set(bgWrap, (strandedByBg.get(bgWrap) ?? 0) + 1);
    }
    if (breakGlassFp !== null && fps.has(breakGlassFp)) currentBreakGlassRunCount++;
    // Operational SOLE access: wrapped to the current operational key but NOT to the current break-glass key,
    // so among the currently-installed keys ONLY operational opens it. Removing operational strands it.
    if (operationalFp !== null && fps.has(operationalFp) && (breakGlassFp === null || !fps.has(breakGlassFp))) {
      operationalSoleAccessRunCount++;
    }
  }

  const vintages: KeyVintageRollup[] = [...vintageRuns.entries()].map(([fingerprint, v]) => ({ fingerprint, role: v.role, runCount: v.count, isCurrent: currentInstalled.has(fingerprint) }));
  const byVintage: StrandedVintage[] = [...strandedByBg.entries()].map(([fingerprint, runCount]) => ({ fingerprint, role: "break-glass", runCount }));

  return {
    current: { breakGlass: breakGlassFp, operational: operationalFp, signer: signerFp },
    okRunCount,
    readableRunCount,
    truncated,
    historyReadOk,
    vintages,
    stranded: { runCount: strandedRunCount, byVintage, unknownCount },
    signer: { current: signerFp, brokenRunCount: signerBrokenCount, currentRunCount: readableRunCount },
    currentBreakGlassRunCount,
    operationalSoleAccessRunCount,
  };
}
